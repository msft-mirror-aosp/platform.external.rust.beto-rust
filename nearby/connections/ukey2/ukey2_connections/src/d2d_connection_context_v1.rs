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

use std::fmt::Formatter;

use bytes::BufMut;
use rand::SeedableRng as _;

use crypto_provider::{hkdf::Hkdf, hmac::Hmac, sha2::Sha256, CryptoProvider};
use ukey2_proto::protobuf::Message as _;
use ukey2_proto::ukey2_all_proto::{
    device_to_device_messages::DeviceToDeviceMessage,
    securegcm::{GcmMetadata, Type},
    securemessage::{EncScheme, Header, HeaderAndBody, SecureMessage, SigScheme},
};
use ukey2_rs::CompletedHandshake;

use crate::{crypto_utils, java_utils};

const PROTOCOL_VERSION: u8 = 1;
/// Number of bytes in the key
pub(crate) const AES_256_KEY_SIZE: usize = 32;
/// SHA-256 of "SecureMessage"
const ENCRYPTION_SALT: [u8; 32] = [
    0xbf, 0x9d, 0x2a, 0x53, 0xc6, 0x36, 0x16, 0xd7, 0x5d, 0xb0, 0xa7, 0x16, 0x5b, 0x91, 0xc1, 0xef,
    0x73, 0xe5, 0x37, 0xf2, 0x42, 0x74, 0x05, 0xfa, 0x23, 0x61, 0x0a, 0x4b, 0xe6, 0x57, 0x64, 0x2e,
];

/// Salt for Sha256 for getSessionUnique()
/// SHA-256 of "D2D"
const SESSION_UNIQUE_SALT: [u8; 32] = [
    0x82, 0xAA, 0x55, 0xA0, 0xD3, 0x97, 0xF8, 0x83, 0x46, 0xCA, 0x1C, 0xEE, 0x8D, 0x39, 0x09, 0xB9,
    0x5F, 0x13, 0xFA, 0x7D, 0xEB, 0x1D, 0x4A, 0xB3, 0x83, 0x76, 0xB8, 0x25, 0x6D, 0xA8, 0x55, 0x10,
];

pub(crate) type AesCbcIv = [u8; 16];
pub type Aes256Key = [u8; 32];

const HKDF_INFO_KEY_INITIATOR: &[u8; 6] = b"client";
const HKDF_INFO_KEY_RESPONDER: &[u8; 6] = b"server";
const HKDF_SALT_ENCRYPT_KEY: &[u8] = b"D2D";

// Static utilities for dealing with AES keys
/// Returns `None` if the requested size > 255 * 512 bytes.
fn encryption_key<const N: usize, C: CryptoProvider>(
    next_protocol_key: &[u8],
    purpose: &[u8],
) -> Option<[u8; N]> {
    let mut buf = [0u8; N];
    let result = &C::Sha256::sha256(HKDF_SALT_ENCRYPT_KEY);
    let hkdf = C::HkdfSha256::new(Some(result), next_protocol_key);
    hkdf.expand(purpose, &mut buf).ok().map(|_| buf)
}

struct RustDeviceToDeviceMessage {
    sequence_num: i32,
    message: Vec<u8>,
}

// Static utility functions for dealing with DeviceToDeviceMessage.
fn create_device_to_device_message(msg: RustDeviceToDeviceMessage) -> Vec<u8> {
    let d2d_message = {
        let mut proto_msg = DeviceToDeviceMessage::default();
        proto_msg.set_message(msg.message);
        proto_msg.set_sequence_number(msg.sequence_num);
        proto_msg
    };
    d2d_message.write_to_bytes().unwrap()
}

fn unwrap_device_to_device_message(
    message: &[u8],
) -> Result<RustDeviceToDeviceMessage, DeserializeError> {
    let result =
        DeviceToDeviceMessage::parse_from_bytes(message).map_err(|_| DeserializeError::BadData)?;
    let msg = result.get_message().to_vec();
    let seq_num = result.get_sequence_number();
    Ok(RustDeviceToDeviceMessage {
        sequence_num: seq_num,
        message: msg,
    })
}

fn derive_aes256_key<C: CryptoProvider>(initial_key: &[u8], purpose: &[u8]) -> Aes256Key {
    let mut buf = [0u8; AES_256_KEY_SIZE];
    let hkdf = C::HkdfSha256::new(Some(&ENCRYPTION_SALT), initial_key);
    hkdf.expand(purpose, &mut buf).unwrap();
    buf
}

#[derive(Debug)]
pub struct D2DConnectionContextV1<R = rand::rngs::StdRng>
where
    R: rand::Rng + rand::SeedableRng + rand::CryptoRng,
{
    decode_sequence_num: i32,
    encode_sequence_num: i32,
    encode_key: Aes256Key,
    decode_key: Aes256Key,
    rng: R,
}

#[derive(Debug)]
pub enum DecodeError {
    BadData,
    BadSequenceNumber,
}

#[derive(Debug, PartialEq, Eq)]
pub enum DeserializeError {
    BadData,
    // For proto struct
    BadDataLength,
    BadProtocolVersion,
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            DecodeError::BadData => write!(f, "DecodeError: BadData"),
            DecodeError::BadSequenceNumber => write!(f, "DecodeError: Bad sequence number"),
        }
    }
}

impl D2DConnectionContextV1<rand::rngs::StdRng> {
    pub fn from_saved_session(session: &[u8]) -> Result<Self, DeserializeError> {
        Self::from_saved_session_with_rng(session, rand::rngs::StdRng::from_entropy())
    }
}

impl<R> D2DConnectionContextV1<R>
where
    R: rand::Rng + rand::SeedableRng + rand::CryptoRng,
{
    pub(crate) const NEXT_PROTOCOL_IDENTIFIER: &'static str = "AES_256_CBC-HMAC_SHA256";

    pub fn new(
        decode_sequence_num: i32,
        encode_sequence_num: i32,
        encode_key: Aes256Key,
        decode_key: Aes256Key,
        rng: R,
    ) -> Self {
        D2DConnectionContextV1 {
            decode_sequence_num,
            encode_sequence_num,
            encode_key,
            decode_key,
            rng,
        }
    }

    pub(crate) fn from_initiator_handshake<C: CryptoProvider>(
        handshake: &CompletedHandshake,
        rng: R,
    ) -> Self {
        let next_protocol_secret = handshake
            .next_protocol_secret::<C>()
            .derive_array::<AES_256_KEY_SIZE>()
            .unwrap();
        D2DConnectionContextV1::new(
            0,
            0,
            encryption_key::<32, C>(&next_protocol_secret, HKDF_INFO_KEY_INITIATOR).unwrap(),
            encryption_key::<32, C>(&next_protocol_secret, HKDF_INFO_KEY_RESPONDER).unwrap(),
            rng,
        )
    }

    pub(crate) fn from_responder_handshake<C: CryptoProvider>(
        handshake: &CompletedHandshake,
        rng: R,
    ) -> Self {
        let next_protocol_secret = handshake
            .next_protocol_secret::<C>()
            .derive_array::<AES_256_KEY_SIZE>()
            .unwrap();
        D2DConnectionContextV1::new(
            0,
            0,
            encryption_key::<32, C>(&next_protocol_secret, HKDF_INFO_KEY_RESPONDER).unwrap(),
            encryption_key::<32, C>(&next_protocol_secret, HKDF_INFO_KEY_INITIATOR).unwrap(),
            rng,
        )
    }

    pub fn save_session(&self) -> Vec<u8> {
        let mut ret: Vec<u8> = vec![];
        ret.push(PROTOCOL_VERSION);
        ret.put_i32(self.encode_sequence_num);
        ret.put_i32(self.decode_sequence_num);
        ret.extend_from_slice(self.encode_key.as_slice());
        ret.extend_from_slice(self.decode_key.as_slice());
        ret
    }

    pub(crate) fn from_saved_session_with_rng(
        session: &[u8],
        rng: R,
    ) -> Result<Self, DeserializeError> {
        // TODO parse with nom to ensure safety
        if session.len() != 73 {
            return Err(DeserializeError::BadDataLength);
        }
        let protocol_version = session[0];
        if protocol_version != PROTOCOL_VERSION {
            return Err(DeserializeError::BadProtocolVersion);
        }
        let encode_sequence_num = i32::from_be_bytes(session[1..5].try_into().unwrap());
        let decode_sequence_num = i32::from_be_bytes(session[5..9].try_into().unwrap());
        let encode_key = session[9..41]
            .try_into()
            .expect("Selecting exactly 32 bytes");
        let decode_key = session[41..73]
            .try_into()
            .expect("Selecting exactly 32 bytes");
        Ok(Self {
            encode_sequence_num,
            decode_sequence_num,
            encode_key,
            decode_key,
            rng,
        })
    }

    pub fn encode_message_to_peer<C: CryptoProvider, A: AsRef<[u8]>>(
        &mut self,
        payload: &[u8],
        associated_data: Option<A>,
    ) -> Vec<u8> {
        self.increment_encode_sequence_number();
        let message = create_device_to_device_message(RustDeviceToDeviceMessage {
            message: payload.to_vec(),
            sequence_num: self.get_sequence_number_for_encoding(),
        });
        let encrypt_key = derive_aes256_key::<C>(&self.encode_key, b"ENC:2");
        let (ciphertext, iv) = crypto_utils::encrypt::<_, C::AesCbcPkcs7Padded>(
            &encrypt_key,
            message.as_slice(),
            &mut self.rng,
        );
        let mut metadata: GcmMetadata = GcmMetadata::default();
        metadata.set_field_type(Type::DEVICE_TO_DEVICE_MESSAGE);
        // As specified in
        // google3/third_party/ukey2/src/main/java/com/google/security/cryptauth/lib/securegcm/SecureGcmConstants.java
        metadata.set_version(1);
        let mut header: Header = Header::default();
        header.set_signature_scheme(SigScheme::HMAC_SHA256);
        header.set_encryption_scheme(EncScheme::AES_256_CBC);
        header.set_iv(iv.to_vec());
        header.set_public_metadata(metadata.write_to_bytes().unwrap());
        if let Some(assoc_data) = associated_data.as_ref() {
            header.set_associated_data_length(assoc_data.as_ref().len() as u32)
        }
        let mut header_and_body = HeaderAndBody::default();
        header_and_body.set_header(header);
        header_and_body.set_body(ciphertext);
        let header_and_body_bytes = header_and_body.write_to_bytes().unwrap();

        // add sha256 MAC
        let sign_key = derive_aes256_key::<C>(&self.encode_key, b"SIG:1");
        let mut hmac = C::HmacSha256::new_from_slice(&sign_key).unwrap();
        hmac.update(header_and_body_bytes.as_slice());
        if let Some(associated_data_vec) = associated_data.as_ref() {
            hmac.update(associated_data_vec.as_ref())
        }
        let result_mac = hmac.finalize().to_vec();

        let mut secure_message = SecureMessage::default();
        secure_message.set_header_and_body(header_and_body_bytes);
        secure_message.set_signature(result_mac);
        secure_message.write_to_bytes().unwrap()
    }

    pub fn decode_message_from_peer<C: CryptoProvider, A: AsRef<[u8]>>(
        &mut self,
        payload: &[u8],
        associated_data: Option<A>,
    ) -> Result<Vec<u8>, DecodeError> {
        // first confirm that the payload MAC matches the header_and_body
        let message = SecureMessage::parse_from_bytes(payload).map_err(|_| DecodeError::BadData)?;
        let payload_mac: [u8; 32] = message
            .get_signature()
            .try_into()
            .map_err(|_| DecodeError::BadData)?;
        let payload = message.get_header_and_body();
        let verify_key = derive_aes256_key::<C>(&self.decode_key, b"SIG:1");
        let mut hmac = C::HmacSha256::new_from_slice(&verify_key).unwrap();
        hmac.update(payload);
        if let Some(associated_data) = associated_data.as_ref() {
            hmac.update(associated_data.as_ref())
        }
        hmac.verify(payload_mac).map_err(|_| DecodeError::BadData)?;
        let payload = HeaderAndBody::parse_from_bytes(payload).map_err(|_| DecodeError::BadData)?;
        let associated_data_len = payload.header.as_ref().and_then(|header| {
            if header.has_associated_data_length() {
                Some(header.get_associated_data_length())
            } else {
                None
            }
        });
        if associated_data_len != associated_data.map(|ad| ad.as_ref().len() as u32) {
            return Err(DecodeError::BadData);
        }
        let iv: AesCbcIv = payload
            .get_header()
            .get_iv()
            .try_into()
            .map_err(|_| DecodeError::BadData)?;
        let decode_key = derive_aes256_key::<C>(&self.decode_key, b"ENC:2");
        let decrypted =
            crypto_utils::decrypt::<C::AesCbcPkcs7Padded>(&decode_key, payload.get_body(), &iv)
                .map_err(|_| DecodeError::BadData)?;
        let d2d_message = unwrap_device_to_device_message(decrypted.as_slice())
            .map_err(|_| DecodeError::BadData)?;
        if d2d_message.sequence_num != self.get_sequence_number_for_decoding() + 1 {
            return Err(DecodeError::BadSequenceNumber);
        }
        self.increment_decode_sequence_number();
        Ok(d2d_message.message)
    }

    fn increment_encode_sequence_number(&mut self) {
        self.encode_sequence_num += 1;
    }

    fn increment_decode_sequence_number(&mut self) {
        self.decode_sequence_num += 1;
    }

    pub fn get_sequence_number_for_encoding(&self) -> i32 {
        self.encode_sequence_num
    }

    pub fn get_sequence_number_for_decoding(&self) -> i32 {
        self.decode_sequence_num
    }

    pub fn get_session_unique<C: CryptoProvider>(&self) -> Vec<u8> {
        let encode_key_hash = java_utils::hash_code(self.encode_key.as_slice());
        let decode_key_hash = java_utils::hash_code(self.decode_key.as_slice());
        let first_key_bytes = if encode_key_hash < decode_key_hash {
            self.encode_key.as_slice()
        } else {
            self.decode_key.as_slice()
        };
        let second_key_bytes = if first_key_bytes == self.encode_key.as_slice() {
            self.decode_key.as_slice()
        } else {
            self.encode_key.as_slice()
        };
        C::Sha256::sha256(&[&SESSION_UNIQUE_SALT, first_key_bytes, second_key_bytes].concat())
            .to_vec()
    }
}
