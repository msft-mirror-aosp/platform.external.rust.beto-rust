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

use crate::d2d_connection_context_v1::D2DConnectionContextV1;
use crypto_provider::CryptoProvider;
use rand::{rngs::StdRng, SeedableRng as _};
use std::{collections::HashSet, mem};
use ukey2_rs::{
    CompletedHandshake, ErrorHandler, HandshakeImplementation, StateMachine, Ukey2Client,
    Ukey2ClientStage1, Ukey2Server, Ukey2ServerStage1, Ukey2ServerStage2,
};

#[derive(Debug)]
pub enum HandshakeError {
    HandshakeNotComplete,
}

#[derive(Debug)]
pub enum HandleMessageError {
    /// The supplied message was not applicable for the current state
    InvalidState,
    /// Handling the message produced an error that should be sent to the other party
    ErrorMessage(Vec<u8>),
    /// Bad message
    BadMessage,
}

// TODO docs
pub trait D2DHandshakeContext<R = rand::rngs::StdRng>: Send
where
    R: rand::RngCore + rand::CryptoRng + rand::SeedableRng + Send,
{
    fn is_handshake_complete(&self) -> bool;

    fn get_next_handshake_message(&self) -> Option<Vec<u8>>;

    fn can_send_payload_in_handshake_message(&self) -> bool;

    fn handle_handshake_message(&mut self, message: &[u8]) -> Result<(), HandleMessageError>;

    fn to_connection_context(&mut self) -> Result<D2DConnectionContextV1<R>, HandshakeError>;

    fn to_completed_handshake(&self) -> Result<&CompletedHandshake, HandshakeError>;
}

enum InitiatorState<C: CryptoProvider, E: ErrorHandler> {
    Stage1(Ukey2ClientStage1<C, E>),
    Complete(Ukey2Client),
    /// If the initiator enters into an invalid state, e.g. by receiving invalid input.
    /// Also a momentary placeholder while swapping out states.
    Invalid,
}

pub struct InitiatorD2DHandshakeContext<C: CryptoProvider, E: ErrorHandler, R = rand::rngs::StdRng>
where
    R: rand::RngCore + rand::CryptoRng + rand::SeedableRng + Send,
{
    state: InitiatorState<C, E>,
    rng: R,
}

impl<C: CryptoProvider, E: ErrorHandler> InitiatorD2DHandshakeContext<C, E, rand::rngs::StdRng> {
    pub fn new(handshake_impl: HandshakeImplementation, error_logger: E) -> Self {
        Self::new_impl(
            handshake_impl,
            error_logger,
            rand::rngs::StdRng::from_entropy(),
        )
    }
}

impl<C: CryptoProvider, E: ErrorHandler, R> InitiatorD2DHandshakeContext<C, E, R>
where
    R: rand::RngCore + rand::CryptoRng + rand::SeedableRng + Send,
{
    #[doc(hidden)]
    pub fn new_impl(handshake_impl: HandshakeImplementation, error_logger: E, mut rng: R) -> Self {
        let client = Ukey2ClientStage1::from(
            &mut rng,
            D2DConnectionContextV1::<StdRng>::NEXT_PROTOCOL_IDENTIFIER.to_owned(),
            handshake_impl,
            error_logger,
        );
        Self {
            state: InitiatorState::Stage1(client),
            rng,
        }
    }
}

impl<C: CryptoProvider, E: ErrorHandler, R> D2DHandshakeContext<R>
    for InitiatorD2DHandshakeContext<C, E, R>
where
    R: rand::RngCore + rand::CryptoRng + rand::SeedableRng + Send,
{
    fn is_handshake_complete(&self) -> bool {
        match self.state {
            InitiatorState::Stage1(_) => false,
            InitiatorState::Complete(_) => true,
            InitiatorState::Invalid => false,
        }
    }

    fn get_next_handshake_message(&self) -> Option<Vec<u8>> {
        let next_msg = match &self.state {
            InitiatorState::Stage1(c) => Some(c.client_init_msg().to_vec()),
            InitiatorState::Complete(c) => Some(c.client_finished_msg().to_vec()),
            InitiatorState::Invalid => None,
        }?;
        Some(next_msg)
    }

    fn can_send_payload_in_handshake_message(&self) -> bool {
        false
    }

    fn handle_handshake_message(&mut self, message: &[u8]) -> Result<(), HandleMessageError> {
        match mem::replace(&mut self.state, InitiatorState::Invalid) {
            InitiatorState::Stage1(c) => {
                let client = c
                    .advance_state(&mut self.rng, message)
                    .map_err(|a| HandleMessageError::ErrorMessage(a.into_wrapped_alert_msg()))?;
                self.state = InitiatorState::Complete(client);
                Ok(())
            }
            InitiatorState::Complete(_) | InitiatorState::Invalid => {
                // already in invalid state, so leave it as is
                Err(HandleMessageError::InvalidState)
            }
        }
    }

    fn to_completed_handshake(&self) -> Result<&CompletedHandshake, HandshakeError> {
        match &self.state {
            InitiatorState::Stage1(_) | InitiatorState::Invalid => {
                Err(HandshakeError::HandshakeNotComplete)
            }
            InitiatorState::Complete(c) => Ok(c.completed_handshake()),
        }
    }

    fn to_connection_context(&mut self) -> Result<D2DConnectionContextV1<R>, HandshakeError> {
        // Since self.rng is expected to be a seeded PRNG, not an OsRng directly, from_rng
        // should never fail. https://rust-random.github.io/book/guide-err.html
        let rng = R::from_rng(&mut self.rng).unwrap();
        self.to_completed_handshake()
            .and_then(|h| match h.next_protocol.as_ref() {
                D2DConnectionContextV1::<R>::NEXT_PROTOCOL_IDENTIFIER => Ok(
                    D2DConnectionContextV1::from_initiator_handshake::<C>(h, rng),
                ),
                _ => Err(HandshakeError::HandshakeNotComplete),
            })
    }
}

enum ServerState<C: CryptoProvider, E: ErrorHandler> {
    Stage1(Ukey2ServerStage1<C, E>),
    Stage2(Ukey2ServerStage2<C, E>),
    Complete(Ukey2Server),
    /// If the initiator enters into an invalid state, e.g. by receiving invalid input.
    /// Also a momentary placeholder while swapping out states.
    Invalid,
}

pub struct ServerD2DHandshakeContext<C: CryptoProvider, E: ErrorHandler, R = rand::rngs::StdRng>
where
    R: rand::Rng + rand::SeedableRng + rand::CryptoRng + Send,
{
    state: ServerState<C, E>,
    rng: R,
}

impl<C: CryptoProvider, E: ErrorHandler> ServerD2DHandshakeContext<C, E, rand::rngs::StdRng> {
    pub fn new(handshake_impl: HandshakeImplementation, error_logger: E) -> Self {
        Self::new_impl(
            handshake_impl,
            error_logger,
            rand::rngs::StdRng::from_entropy(),
        )
    }
}

impl<C: CryptoProvider, E: ErrorHandler, R> ServerD2DHandshakeContext<C, E, R>
where
    R: rand::Rng + rand::SeedableRng + rand::CryptoRng + Send,
{
    #[doc(hidden)]
    pub fn new_impl(handshake_impl: HandshakeImplementation, error_logger: E, rng: R) -> Self {
        Self {
            state: ServerState::Stage1(Ukey2ServerStage1::from(
                HashSet::from([
                    D2DConnectionContextV1::<rand::rngs::StdRng>::NEXT_PROTOCOL_IDENTIFIER
                        .to_owned(),
                ]),
                handshake_impl,
                error_logger,
            )),
            rng,
        }
    }
}

impl<C, E, R> D2DHandshakeContext<R> for ServerD2DHandshakeContext<C, E, R>
where
    C: CryptoProvider,
    E: ErrorHandler,
    R: rand::Rng + rand::SeedableRng + rand::CryptoRng + Send,
{
    fn is_handshake_complete(&self) -> bool {
        match &self.state {
            ServerState::Complete(_) => true,
            ServerState::Stage1(_) | ServerState::Stage2(_) | ServerState::Invalid => false,
        }
    }

    fn get_next_handshake_message(&self) -> Option<Vec<u8>> {
        let next_msg = match &self.state {
            ServerState::Stage1(_) => None,
            ServerState::Stage2(s) => Some(s.server_init_msg().to_vec()),
            ServerState::Complete(_) => None,
            ServerState::Invalid => None,
        }?;
        Some(next_msg)
    }

    fn can_send_payload_in_handshake_message(&self) -> bool {
        match &self.state {
            ServerState::Stage1(_) => false,
            ServerState::Stage2(_) => true,
            ServerState::Complete(_) => true,
            ServerState::Invalid => false,
        }
    }

    fn handle_handshake_message(&mut self, message: &[u8]) -> Result<(), HandleMessageError> {
        match mem::replace(&mut self.state, ServerState::Invalid) {
            ServerState::Stage1(s) => {
                let server2 = s
                    .advance_state(&mut self.rng, message)
                    .map_err(|a| HandleMessageError::ErrorMessage(a.into_wrapped_alert_msg()))?;
                self.state = ServerState::Stage2(server2);
                Ok(())
            }
            ServerState::Stage2(s) => {
                let server = s
                    .advance_state(&mut self.rng, message)
                    .map_err(|a| HandleMessageError::ErrorMessage(a.into_wrapped_alert_msg()))?;
                self.state = ServerState::Complete(server);
                Ok(())
            }
            ServerState::Complete(_) | ServerState::Invalid => {
                Err(HandleMessageError::InvalidState)
            }
        }
    }

    fn to_completed_handshake(&self) -> Result<&CompletedHandshake, HandshakeError> {
        match &self.state {
            ServerState::Stage1(_) | ServerState::Stage2(_) | ServerState::Invalid => {
                Err(HandshakeError::HandshakeNotComplete)
            }
            ServerState::Complete(s) => Ok(s.completed_handshake()),
        }
    }

    fn to_connection_context(&mut self) -> Result<D2DConnectionContextV1<R>, HandshakeError> {
        // Since self.rng is expected to be a seeded PRNG, not an OsRng directly, from_rng
        // should never fail. https://rust-random.github.io/book/guide-err.html
        let rng = R::from_rng(&mut self.rng).unwrap();
        self.to_completed_handshake()
            .map(|h| match h.next_protocol.as_ref() {
                D2DConnectionContextV1::<R>::NEXT_PROTOCOL_IDENTIFIER => {
                    D2DConnectionContextV1::from_responder_handshake::<C>(h, rng)
                }
                _ => {
                    // This should never happen because ukey2_handshake should set next_protocol to
                    // one of the values we passed in Ukey2ServerStage1::from, which doesn't contain
                    // any other value.
                    panic!("Unknown next protocol: {}", h.next_protocol);
                }
            })
    }
}
