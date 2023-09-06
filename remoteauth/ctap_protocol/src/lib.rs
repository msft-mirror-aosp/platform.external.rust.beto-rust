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

//! # CTAP Protocol
//!
//! This crate represents CTAP messages and turns them into a binary representation to be sent to a
//! remote device.

use anyhow::anyhow;

/// The Rust representation of CTAP messages.
#[derive(Debug, PartialEq)]
pub enum CtapMessage {
    AuthenticatorReset,
}

impl CtapMessage {
    /// Converts the given CTAP message into its binary representation.
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            CtapMessage::AuthenticatorReset => vec![0x07],
        }
    }

    /// Convert a binary message to its Rust representation.
    pub fn from_bytes(bytes: Vec<u8>) -> anyhow::Result<CtapMessage> {
        if bytes.len() == 0 {
            Err(anyhow!("Binary message was empty."))
        } else {
            match bytes[0] {
                0x07 => Ok(CtapMessage::AuthenticatorReset),
                _ => Err(anyhow!("Unknown message type.")),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn translate_message_to_bytes() {
        let message = CtapMessage::AuthenticatorReset;
        let bytes = message.to_bytes();

        assert_eq!(bytes, vec![0x07]);
    }

    #[test]
    fn translate_bytes_to_message() {
        let bytes = vec![0x07];
        let message = CtapMessage::from_bytes(bytes);

        assert_eq!(message.is_ok(), true);
        assert_eq!(message.unwrap(), CtapMessage::AuthenticatorReset);
    }

    #[test]
    fn translate_empty_bytes() {
        let bytes = vec![];
        let message = CtapMessage::from_bytes(bytes);

        assert_eq!(message.is_err(), true);
        assert_eq!(
            message.unwrap_err().to_string(),
            "Binary message was empty."
        );
    }

    #[test]
    fn translate_unknown_message() {
        let bytes = vec![0x01];
        let message = CtapMessage::from_bytes(bytes);

        assert_eq!(message.is_err(), true);
        assert_eq!(message.unwrap_err().to_string(), "Unknown message type.");
    }
}
