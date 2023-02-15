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

use crypto_provider::elliptic_curve::EcdhProvider;
use crypto_provider::p256::{P256EcdhProvider, P256PublicKey, P256};
use crypto_provider::CryptoProvider;
use derive_getters::Getters;
use ukey2_proto::protobuf::ProtobufEnum;
use ukey2_proto::ukey2_all_proto::{securemessage, ukey};

/// For generated proto types for UKEY2 messages
trait WithMessageType: ukey2_proto::protobuf::Message {
    fn msg_type() -> ukey::Ukey2Message_Type;
}

pub(crate) trait ToWrappedMessage {
    /// Encode self and wrap in a `Ukey2Message`
    fn to_wrapped_msg(self) -> ukey::Ukey2Message;
}

impl<M: WithMessageType> ToWrappedMessage for M {
    fn to_wrapped_msg(self) -> ukey::Ukey2Message {
        let mut message = ukey::Ukey2Message::default();
        message.set_message_type(Self::msg_type());
        message.set_message_data(self.write_to_bytes().unwrap());
        message
    }
}

impl WithMessageType for ukey::Ukey2Alert {
    fn msg_type() -> ukey::Ukey2Message_Type {
        ukey::Ukey2Message_Type::ALERT
    }
}

impl WithMessageType for ukey::Ukey2ServerInit {
    fn msg_type() -> ukey::Ukey2Message_Type {
        ukey::Ukey2Message_Type::SERVER_INIT
    }
}

impl WithMessageType for ukey::Ukey2ClientFinished {
    fn msg_type() -> ukey::Ukey2Message_Type {
        ukey::Ukey2Message_Type::CLIENT_FINISH
    }
}

impl WithMessageType for ukey::Ukey2ClientInit {
    fn msg_type() -> ukey::Ukey2Message_Type {
        ukey::Ukey2Message_Type::CLIENT_INIT
    }
}

/// Convert a generated proto type into our custom adapter type.
pub(crate) trait IntoAdapter<A> {
    /// Convert `self` into the adapter type.
    fn into_adapter(self) -> Result<A, ukey::Ukey2Alert_AlertType>;
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum MessageType {
    ClientInit,
    ServerInit,
    ClientFinish,
}

#[derive(Getters)]
pub(crate) struct ClientInit {
    version: i32,
    random: [u8; 32],
    commitments: Vec<CipherCommitment>,
    next_protocol: String,
}

#[allow(dead_code)]
#[derive(Getters)]
pub(crate) struct ServerInit {
    version: i32,
    random: [u8; 32],
    handshake_cipher: HandshakeCipher,
    #[getter(skip)]
    pub(crate) public_key: Vec<u8>,
}

pub(crate) struct ClientFinished {
    pub(crate) public_key: Vec<u8>,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum HandshakeCipher {
    P256Sha512,
    Curve25519Sha512,
}

impl HandshakeCipher {
    pub(crate) fn as_proto(&self) -> ukey::Ukey2HandshakeCipher {
        match self {
            HandshakeCipher::P256Sha512 => ukey::Ukey2HandshakeCipher::P256_SHA512,
            HandshakeCipher::Curve25519Sha512 => ukey::Ukey2HandshakeCipher::CURVE25519_SHA512,
        }
    }
}

#[derive(Clone, Getters)]
pub(crate) struct CipherCommitment {
    cipher: HandshakeCipher,
    commitment: Vec<u8>,
}

pub(crate) enum PublicKeyType {
    Ec256,
    RSA2048,
    Dh2048Modp,
}

pub(crate) enum GenericPublicKey<C: CryptoProvider> {
    Ec256(<C::P256 as EcdhProvider<P256>>::PublicKey),
    // Other public key types are not supported
}

impl IntoAdapter<MessageType> for i32 {
    fn into_adapter(self) -> Result<MessageType, ukey::Ukey2Alert_AlertType> {
        const CLIENT_INIT: i32 = ukey::Ukey2Message_Type::CLIENT_INIT as i32;
        const SERVER_INIT: i32 = ukey::Ukey2Message_Type::SERVER_INIT as i32;
        const CLIENT_FINISH: i32 = ukey::Ukey2Message_Type::CLIENT_FINISH as i32;
        match self {
            CLIENT_INIT => Some(MessageType::ClientInit),
            SERVER_INIT => Some(MessageType::ServerInit),
            CLIENT_FINISH => Some(MessageType::ClientFinish),
            _ => None,
        }
        .ok_or(ukey::Ukey2Alert_AlertType::BAD_MESSAGE_TYPE)
    }
}

impl IntoAdapter<HandshakeCipher> for i32 {
    fn into_adapter(self) -> Result<HandshakeCipher, ukey::Ukey2Alert_AlertType> {
        const P256_CODE: i32 = ukey::Ukey2HandshakeCipher::P256_SHA512 as i32;
        const CURVE25519_CODE: i32 = ukey::Ukey2HandshakeCipher::CURVE25519_SHA512 as i32;
        match self {
            P256_CODE => Ok(HandshakeCipher::P256Sha512),
            CURVE25519_CODE => Ok(HandshakeCipher::Curve25519Sha512),
            _ => Err(ukey::Ukey2Alert_AlertType::BAD_HANDSHAKE_CIPHER),
        }
    }
}

impl IntoAdapter<CipherCommitment> for ukey::Ukey2ClientInit_CipherCommitment {
    fn into_adapter(self) -> Result<CipherCommitment, ukey::Ukey2Alert_AlertType> {
        let handshake_cipher: HandshakeCipher =
            self.get_handshake_cipher().value().into_adapter()?;
        // no bad commitment so this is best-effort
        let commitment = self.get_commitment().to_vec();
        if commitment.is_empty() {
            return Err(ukey::Ukey2Alert_AlertType::BAD_HANDSHAKE_CIPHER);
        }
        Ok(CipherCommitment {
            commitment,
            cipher: handshake_cipher,
        })
    }
}

impl IntoAdapter<ClientInit> for ukey::Ukey2ClientInit {
    fn into_adapter(self) -> Result<ClientInit, ukey::Ukey2Alert_AlertType> {
        let random: [u8; 32] = self
            .get_random()
            .try_into()
            .map_err(|_| ukey::Ukey2Alert_AlertType::BAD_RANDOM)?;
        if !self.has_version() {
            return Err(ukey::Ukey2Alert_AlertType::BAD_VERSION);
        }
        let version: i32 = self.get_version();
        let next_protocol = String::from(self.get_next_protocol());
        if next_protocol.is_empty() {
            return Err(ukey::Ukey2Alert_AlertType::BAD_NEXT_PROTOCOL);
        }
        Ok(ClientInit {
            random,
            next_protocol,
            version,
            commitments: self
                .cipher_commitments
                .into_iter()
                .map(|c| c.into_adapter())
                .collect::<Result<Vec<_>, _>>()?,
        })
    }
}

impl IntoAdapter<ServerInit> for ukey::Ukey2ServerInit {
    fn into_adapter(self) -> Result<ServerInit, ukey::Ukey2Alert_AlertType> {
        if !self.has_version() {
            return Err(ukey::Ukey2Alert_AlertType::BAD_VERSION);
        }
        let version: i32 = self.get_version();
        let random: [u8; 32] = self
            .get_random()
            .try_into()
            .map_err(|_| ukey::Ukey2Alert_AlertType::BAD_RANDOM)?;
        let handshake_cipher = self.get_handshake_cipher().value().into_adapter()?;
        // We will be handling bad pubkeys in the layers above
        let public_key: Vec<u8> = self.get_public_key().to_vec();
        if public_key.is_empty() {
            return Err(ukey::Ukey2Alert_AlertType::BAD_PUBLIC_KEY);
        }
        Ok(ServerInit {
            handshake_cipher,
            version,
            public_key,
            random,
        })
    }
}

impl IntoAdapter<ClientFinished> for ukey::Ukey2ClientFinished {
    fn into_adapter(self) -> Result<ClientFinished, ukey::Ukey2Alert_AlertType> {
        let public_key: Vec<u8> = self.get_public_key().to_vec();
        if public_key.is_empty() {
            return Err(ukey::Ukey2Alert_AlertType::BAD_PUBLIC_KEY);
        }
        Ok(ClientFinished { public_key })
    }
}

impl<C: CryptoProvider> IntoAdapter<GenericPublicKey<C>> for securemessage::GenericPublicKey {
    fn into_adapter(self) -> Result<GenericPublicKey<C>, ukey::Ukey2Alert_AlertType> {
        const DH2048_MODP: i32 = securemessage::PublicKeyType::DH2048_MODP as i32;
        const EC_P256: i32 = securemessage::PublicKeyType::EC_P256 as i32;
        const RSA_2048: i32 = securemessage::PublicKeyType::RSA2048 as i32;
        let key_type = match self.get_field_type().value() {
            DH2048_MODP => Some(PublicKeyType::Dh2048Modp),
            EC_P256 => Some(PublicKeyType::Ec256),
            RSA_2048 => Some(PublicKeyType::RSA2048),
            _ => None,
        }
        .ok_or(ukey::Ukey2Alert_AlertType::BAD_PUBLIC_KEY)?;
        match key_type {
            PublicKeyType::Ec256 => {
                let key = self.ec_p256_public_key.unwrap();
                // TODO: condense
                let key_x = num_bigint::BigInt::from_bytes_be(num_bigint::Sign::Plus, key.get_x())
                    .to_biguint()
                    .unwrap();
                let key_y = num_bigint::BigInt::from_bytes_be(num_bigint::Sign::Plus, key.get_y())
                    .to_biguint()
                    .unwrap();
                let key_x_bytes: [u8; 32] = key_x
                    .to_bytes_be()
                    .as_slice()
                    .try_into()
                    .map_err(|_| ukey::Ukey2Alert_AlertType::BAD_PUBLIC_KEY)?;
                let key_y_bytes: [u8; 32] = key_y
                    .to_bytes_be()
                    .as_slice()
                    .try_into()
                    .map_err(|_| ukey::Ukey2Alert_AlertType::BAD_PUBLIC_KEY)?;
                <C::P256 as P256EcdhProvider>::PublicKey::from_affine_coordinates(
                    &key_x_bytes,
                    &key_y_bytes,
                )
                .map(GenericPublicKey::Ec256)
                .map_err(|_| ukey::Ukey2Alert_AlertType::BAD_PUBLIC_KEY)
            }
            PublicKeyType::RSA2048 => {
                // We don't support RSA keys
                Err(ukey::Ukey2Alert_AlertType::BAD_PUBLIC_KEY)
            }
            PublicKeyType::Dh2048Modp => {
                // We don't support DH2048 keys, only ECDH.
                Err(ukey::Ukey2Alert_AlertType::BAD_PUBLIC_KEY)
            }
        }
    }
}