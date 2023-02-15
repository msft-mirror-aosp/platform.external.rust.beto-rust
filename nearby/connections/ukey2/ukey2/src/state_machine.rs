#![allow(missing_docs)]
// Copyright 2023 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::proto_adapter::{IntoAdapter, MessageType, ToWrappedMessage as _};
use crate::ukey2_handshake::ClientFinishedError;
use crate::{
    ukey2_handshake::{
        ClientInit, ClientInitError, Ukey2Client, Ukey2ClientStage1, Ukey2Server,
        Ukey2ServerStage1, Ukey2ServerStage2,
    },
    ErrorHandler, Severity,
};
use crypto_provider::CryptoProvider;
use std::fmt::Debug;
use ukey2_proto::protobuf::{Message, ProtobufEnum};
use ukey2_proto::ukey2_all_proto::ukey;

/// An alert type and message to be sent to the other party.
#[derive(Debug, PartialEq, Eq)]
pub struct SendAlert {
    alert_type: ukey::Ukey2Alert_AlertType,
    msg: Option<String>,
}

impl SendAlert {
    pub(crate) fn from(alert_type: ukey::Ukey2Alert_AlertType, msg: Option<String>) -> Self {
        Self { alert_type, msg }
    }

    pub fn into_wrapped_alert_msg(self) -> Vec<u8> {
        let mut alert_message = ukey::Ukey2Alert::default();
        alert_message.set_field_type(self.alert_type);
        if let Some(msg) = self.msg {
            alert_message.set_error_message(msg)
        }
        alert_message.to_wrapped_msg().write_to_bytes().unwrap()
    }
}

pub trait StateMachine {
    /// The type produced by each successful state transition
    type Success;

    /// Advance to the next state in the relevant half (client/server) of the protocol.
    fn advance_state<R: rand::Rng + rand::CryptoRng>(
        self,
        rng: &mut R,
        message_bytes: &[u8],
    ) -> Result<Self::Success, SendAlert>;
}

impl<C: CryptoProvider, E: ErrorHandler> StateMachine for Ukey2ClientStage1<C, E> {
    type Success = Ukey2Client;

    fn advance_state<R: rand::Rng + rand::CryptoRng>(
        self,
        _rng: &mut R,
        message_bytes: &[u8],
    ) -> Result<Self::Success, SendAlert> {
        let (message_data, message_type) =
            decode_wrapper_msg_and_type(message_bytes, &self.error_logger)?;

        match message_type {
            // Client should not be receiving ClientInit/ClientFinish
            MessageType::ClientInit | MessageType::ClientFinish => Err(SendAlert::from(
                ukey::Ukey2Alert_AlertType::INCORRECT_MESSAGE,
                Some("wrong message".to_string()),
            )),
            MessageType::ServerInit => {
                let message = decode_msg_contents::<_, ukey::Ukey2ServerInit, _>(
                    message_data,
                    &self.error_logger,
                )?;
                self.handle_server_init(message, message_bytes.to_vec())
                    .map_err(|_| {
                        SendAlert::from(
                            ukey::Ukey2Alert_AlertType::BAD_MESSAGE_DATA,
                            Some("bad message_data".to_string()),
                        )
                    })
            }
        }
    }
}

impl<C: CryptoProvider, E: ErrorHandler> StateMachine for Ukey2ServerStage1<C, E> {
    type Success = Ukey2ServerStage2<C, E>;

    fn advance_state<R: rand::Rng + rand::CryptoRng>(
        self,
        rng: &mut R,
        message_bytes: &[u8],
    ) -> Result<Self::Success, SendAlert> {
        let (message_data, message_type) =
            decode_wrapper_msg_and_type(message_bytes, &self.error_logger)?;
        match message_type {
            MessageType::ClientInit => {
                let message: ClientInit = decode_msg_contents::<_, ukey::Ukey2ClientInit, _>(
                    message_data,
                    &self.error_logger,
                )?;
                self.handle_client_init(rng, message, message_bytes.to_vec())
                    .map_err(|e| {
                        SendAlert::from(
                            match e {
                                ClientInitError::BadVersion => {
                                    ukey::Ukey2Alert_AlertType::BAD_VERSION
                                }
                                ClientInitError::BadHandshakeCipher => {
                                    ukey::Ukey2Alert_AlertType::BAD_HANDSHAKE_CIPHER
                                }
                                ClientInitError::BadNextProtocol => {
                                    ukey::Ukey2Alert_AlertType::BAD_NEXT_PROTOCOL
                                }
                            },
                            None,
                        )
                    })
            }
            MessageType::ClientFinish | MessageType::ServerInit => Err(SendAlert::from(
                ukey::Ukey2Alert_AlertType::INCORRECT_MESSAGE,
                Some("wrong message".to_string()),
            )),
        }
    }
}

impl<C: CryptoProvider, E: ErrorHandler> StateMachine for Ukey2ServerStage2<C, E> {
    type Success = Ukey2Server;

    fn advance_state<R: rand::Rng + rand::CryptoRng>(
        self,
        _rng: &mut R,
        message_bytes: &[u8],
    ) -> Result<Self::Success, SendAlert> {
        let (message_data, message_type) =
            decode_wrapper_msg_and_type(message_bytes, &self.error_logger)?;
        match message_type {
            MessageType::ClientFinish => {
                let message = decode_msg_contents::<_, ukey::Ukey2ClientFinished, _>(
                    message_data,
                    &self.error_logger,
                )?;
                self.handle_client_finished_msg(message, message_bytes)
                    .map_err(|e| match e {
                        ClientFinishedError::BadEd25519Key => SendAlert::from(
                            ukey::Ukey2Alert_AlertType::BAD_PUBLIC_KEY,
                            "Bad ED25519 Key".to_string().into(),
                        ),
                        ClientFinishedError::BadP256Key => SendAlert::from(
                            ukey::Ukey2Alert_AlertType::BAD_PUBLIC_KEY,
                            "Bad P256 Key".to_string().into(),
                        ),
                        ClientFinishedError::UnknownCommitment => SendAlert::from(
                            ukey::Ukey2Alert_AlertType::BAD_MESSAGE_DATA,
                            "Unknown commitment".to_string().into(),
                        ),
                        ClientFinishedError::BadKeyExchange => SendAlert::from(
                            ukey::Ukey2Alert_AlertType::INTERNAL_ERROR,
                            "Key exchange error".to_string().into(),
                        ),
                    })
            }
            MessageType::ClientInit | MessageType::ServerInit => Err(SendAlert::from(
                ukey::Ukey2Alert_AlertType::INCORRECT_MESSAGE,
                "wrong message".to_string().into(),
            )),
        }
    }
}

/// Extract the message field and message type from a Ukey2Message
fn decode_wrapper_msg_and_type<E: ErrorHandler>(
    bytes: &[u8],
    logger: &E,
) -> Result<(Vec<u8>, MessageType), SendAlert> {
    ukey::Ukey2Message::parse_from_bytes(bytes)
        .map_err(|_| {
            logger.log_err(
                Severity::Error,
                "Unable to unmarshal into Ukey2Message".to_string(),
            );

            SendAlert::from(
                ukey::Ukey2Alert_AlertType::BAD_MESSAGE,
                Some("Bad message data".to_string()),
            )
        })
        .and_then(|message| {
            let message_data = message.get_message_data();
            if message_data.is_empty() {
                return Err(SendAlert::from(
                    ukey::Ukey2Alert_AlertType::BAD_MESSAGE_DATA,
                    None,
                ));
            }
            let message_type = message.get_message_type();
            if message_type == ukey::Ukey2Message_Type::UNKNOWN_DO_NOT_USE {
                return Err(SendAlert::from(
                    ukey::Ukey2Alert_AlertType::BAD_MESSAGE_TYPE,
                    None,
                ));
            }
            message_type
                .value()
                .into_adapter()
                .map_err(|e| {
                    logger.log_err(Severity::Error, "Unknown UKEY2 Message Type".to_string());
                    SendAlert::from(e, Some("bad message type".to_string()))
                })
                .map(|message_type| (message_data.to_vec(), message_type))
        })
}

/// Extract a specific message type from message data in a Ukey2Messaage
///
/// See [decode_wrapper_msg_and_type] for getting the message data.
fn decode_msg_contents<A, M: Message + Default + IntoAdapter<A>, E: ErrorHandler>(
    message_data: Vec<u8>,
    logger: &E,
) -> Result<A, SendAlert> {
    M::parse_from_bytes(message_data.as_slice())
        .map_err(|_| {
            logger.log_err(
                Severity::Error,
                "Unable to unmarshal message, check frame of the message you were trying to send"
                    .to_string(),
            );
            SendAlert::from(
                ukey::Ukey2Alert_AlertType::BAD_MESSAGE_DATA,
                Some("frame error".to_string()),
            )
        })?
        .into_adapter()
        .map_err(|t| SendAlert::from(t, Some("failed to translate proto".to_string())))
}
