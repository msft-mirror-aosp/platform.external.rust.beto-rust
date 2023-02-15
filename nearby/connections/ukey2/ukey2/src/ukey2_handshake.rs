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

pub(crate) use crate::proto_adapter::{
    CipherCommitment, ClientFinished, ClientInit, GenericPublicKey, HandshakeCipher,
    IntoAdapter as _, ServerInit, ToWrappedMessage as _,
};
use crate::ErrorHandler;
use crypto_provider::elliptic_curve::EphemeralSecret;
use crypto_provider::p256::{P256EcdhProvider, P256PublicKey, P256};
use crypto_provider::x25519::X25519;
use crypto_provider::CryptoProvider;
use crypto_provider::{
    elliptic_curve::{EcdhProvider, PublicKey},
    hkdf::Hkdf,
    sha2::{Sha256, Sha512},
};
use std::{
    collections::hash_set,
    fmt::{self, Formatter},
    marker::PhantomData,
};
use ukey2_proto::protobuf::Message;
use ukey2_proto::ukey2_all_proto::{securemessage, ukey};

pub trait WireCompatibilityLayer {
    fn encode_public_key<C: CryptoProvider>(
        &self,
        key: Vec<u8>,
        cipher: HandshakeCipher,
    ) -> Option<Vec<u8>>;
    fn decode_public_key<C: CryptoProvider>(
        &self,
        key: Vec<u8>,
        cipher: HandshakeCipher,
    ) -> Option<Vec<u8>>;
}

#[derive(Clone)]
pub enum HandshakeImplementation {
    Spec,
    Weird,
}

impl WireCompatibilityLayer for HandshakeImplementation {
    fn encode_public_key<C: CryptoProvider>(
        &self,
        key: Vec<u8>,
        cipher: HandshakeCipher,
    ) -> Option<Vec<u8>> {
        match self {
            HandshakeImplementation::Spec => Some(key),
            HandshakeImplementation::Weird => match cipher {
                HandshakeCipher::P256Sha512 => {
                    let p256_key =
                        <C::P256 as P256EcdhProvider>::PublicKey::from_bytes(key.as_slice())
                            .unwrap();
                    let (x, y) = p256_key.to_affine_coordinates().unwrap();
                    let bigboi_x = num_bigint::BigInt::from_biguint(
                        num_bigint::Sign::Plus,
                        num_bigint::BigUint::from_bytes_be(x.to_vec().as_slice()),
                    );
                    let bigboi_y = num_bigint::BigInt::from_biguint(
                        num_bigint::Sign::Plus,
                        num_bigint::BigUint::from_bytes_be(y.to_vec().as_slice()),
                    );
                    let mut proto_key = securemessage::EcP256PublicKey::default();
                    proto_key.set_x(bigboi_x.to_signed_bytes_be());
                    proto_key.set_y(bigboi_y.to_signed_bytes_be());
                    let mut key = securemessage::GenericPublicKey::default();
                    key.set_field_type(securemessage::PublicKeyType::EC_P256);
                    key.set_ec_p256_public_key(proto_key);
                    key.write_to_bytes().ok()
                }
                HandshakeCipher::Curve25519Sha512 => None,
            },
        }
    }

    fn decode_public_key<C: CryptoProvider>(
        &self,
        key: Vec<u8>,
        cipher: HandshakeCipher,
    ) -> Option<Vec<u8>> {
        match self {
            HandshakeImplementation::Spec => Some(key),
            HandshakeImplementation::Weird => {
                // key will be wrapped in a genericpublickey
                let public_key: GenericPublicKey<C> =
                    securemessage::GenericPublicKey::parse_from_bytes(key.as_slice())
                        .ok()?
                        .into_adapter()
                        .ok()?;
                match public_key {
                    GenericPublicKey::Ec256(key) => {
                        debug_assert_eq!(cipher, HandshakeCipher::P256Sha512);
                        Some(key.to_bytes())
                    }
                }
            }
        }
    }
}

pub struct Ukey2ServerStage1<C: CryptoProvider, E: ErrorHandler> {
    pub(crate) next_protocols: hash_set::HashSet<String>,
    pub(crate) handshake_impl: HandshakeImplementation,
    pub(crate) error_logger: E,
    _marker: PhantomData<C>,
}

impl<C: CryptoProvider, E: ErrorHandler> fmt::Debug for Ukey2ServerStage1<C, E> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "Ukey2ServerS1")
    }
}

impl<C: CryptoProvider, E: ErrorHandler> Ukey2ServerStage1<C, E> {
    pub fn from(
        next_protocols: hash_set::HashSet<String>,
        handshake_impl: HandshakeImplementation,
        error_logger: E,
    ) -> Self {
        Self {
            next_protocols,
            handshake_impl,
            error_logger,
            _marker: PhantomData,
        }
    }

    pub(crate) fn handle_client_init<R: rand::Rng + rand::CryptoRng>(
        self,
        rng: &mut R,
        client_init: ClientInit,
        client_init_msg_bytes: Vec<u8>,
    ) -> Result<Ukey2ServerStage2<C, E>, ClientInitError> {
        if client_init.version() != &1 {
            return Err(ClientInitError::BadVersion);
        }

        let next_protocol = client_init.next_protocol();
        if !self.next_protocols.contains(next_protocol) {
            return Err(ClientInitError::BadNextProtocol);
        }

        // nothing to check here about client_init.random -- already been validated as 32 bytes

        // all cipher types are supported, so no BAD_HANDSHAKE_CIPHER case
        let commitment = client_init
            .commitments()
            .iter()
            // we want to get the first matching cipher, but max_by_key returns the last max,
            // so iterate in reverse direction
            .rev()
            // proto enum uses the priority as the numeric value
            .max_by_key(|c| c.cipher().as_proto() as i32)
            .ok_or(ClientInitError::BadHandshakeCipher)?;
        match *commitment.cipher() {
            // pick in priority order
            HandshakeCipher::Curve25519Sha512 => Ok(Ukey2ServerStage2::from(
                client_init_msg_bytes,
                commitment.clone(),
                client_init.random(),
                ServerKeyPair::Curve25519(
                    <C::X25519 as EcdhProvider<X25519>>::EphemeralSecret::generate_random(rng),
                ),
                self.handshake_impl,
                self.error_logger,
                next_protocol.to_string(),
            )),
            HandshakeCipher::P256Sha512 => Ok(Ukey2ServerStage2::from(
                client_init_msg_bytes,
                commitment.clone(),
                client_init.random(),
                ServerKeyPair::P256(
                    <C::P256 as EcdhProvider<P256>>::EphemeralSecret::generate_random(rng),
                ),
                self.handshake_impl,
                self.error_logger,
                next_protocol.to_string(),
            )),
        }
    }
}

enum ServerKeyPair<C: CryptoProvider> {
    Curve25519(<C::X25519 as EcdhProvider<X25519>>::EphemeralSecret),
    P256(<C::P256 as EcdhProvider<P256>>::EphemeralSecret),
}

pub struct Ukey2ServerStage2<C: CryptoProvider, E: ErrorHandler> {
    client_init_msg: Vec<u8>,
    server_init_msg: Vec<u8>,
    commitment: CipherCommitment,
    key_pair: ServerKeyPair<C>,
    pub(crate) handshake_impl: HandshakeImplementation,
    pub(crate) error_logger: E,
    next_protocol: String,
    _marker: PhantomData<C>,
}

impl<C: CryptoProvider, E: ErrorHandler> fmt::Debug for Ukey2ServerStage2<C, E> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "Ukey2ServerS2")
    }
}

const HKDF_SALT_AUTH: &[u8] = b"UKEY2 v1 auth";
const HKDF_SALT_NEXT: &[u8] = b"UKEY2 v1 next";

impl<C: CryptoProvider, E: ErrorHandler> Ukey2ServerStage2<C, E> {
    fn from(
        client_init_msg: Vec<u8>,
        commitment: CipherCommitment,
        random: &[u8; 32],
        key_pair: ServerKeyPair<C>,
        handshake_impl: HandshakeImplementation,
        error_logger: E,
        next_protocol: String,
    ) -> Self {
        let mut server_init = ukey::Ukey2ServerInit::default();
        server_init.set_version(1);
        server_init.set_random(random.to_vec());
        server_init.set_handshake_cipher(commitment.cipher().as_proto());
        server_init.set_public_key(match &key_pair {
            ServerKeyPair::Curve25519(es) => es.public_key_bytes(),
            ServerKeyPair::P256(es) => handshake_impl
                .encode_public_key::<C>(es.public_key_bytes(), HandshakeCipher::P256Sha512)
                .unwrap(),
        });

        Self {
            client_init_msg,
            server_init_msg: server_init.to_wrapped_msg().write_to_bytes().unwrap(),
            commitment,
            key_pair,
            handshake_impl,
            error_logger,
            next_protocol,
            _marker: PhantomData,
        }
    }

    pub fn server_init_msg(&self) -> &[u8] {
        &self.server_init_msg
    }

    pub(crate) fn handle_client_finished_msg(
        self,
        msg: ClientFinished,
        client_finished_msg_bytes: &[u8],
    ) -> Result<Ukey2Server, ClientFinishedError> {
        let hash_bytes = C::Sha512::sha512(client_finished_msg_bytes);
        // must be constant time to avoid timing attack on hash equality
        if C::constant_time_eq(hash_bytes.as_slice(), self.commitment.commitment()) {
            // handshake is complete
            // independently derive shared DH key
            let shared_secret_bytes = match self.key_pair {
                ServerKeyPair::Curve25519(es) => {
                    let buf = msg.public_key.into_iter().collect::<Vec<u8>>();
                    let public_key: [u8; 32] = (&buf[..])
                        .try_into()
                        .map_err(|_| ClientFinishedError::BadEd25519Key)?;
                    es.diffie_hellman(
                        &<C::X25519 as EcdhProvider<X25519>>::PublicKey::from_bytes(&public_key)
                            .map_err(|_| ClientFinishedError::BadEd25519Key)?,
                    )
                    .map_err(|_| ClientFinishedError::BadKeyExchange)?
                    .into()
                }
                ServerKeyPair::P256(es) => {
                    let other_public_key =
                        &<C::P256 as P256EcdhProvider>::PublicKey::from_sec1_bytes(
                            self.handshake_impl
                                .decode_public_key::<C>(msg.public_key, HandshakeCipher::P256Sha512)
                                .ok_or(ClientFinishedError::BadP256Key)?
                                .as_slice(),
                        )
                        .map_err(|_| ClientFinishedError::BadP256Key)?;
                    es.diffie_hellman(other_public_key)
                        .map_err(|_| ClientFinishedError::BadKeyExchange)?
                        .into()
                }
            };
            let shared_secret_sha256 = C::Sha256::sha256(&shared_secret_bytes).to_vec();
            Ok(Ukey2Server {
                completed_handshake: CompletedHandshake::new(
                    self.client_init_msg,
                    self.server_init_msg,
                    shared_secret_sha256,
                    self.next_protocol,
                ),
            })
        } else {
            Err(ClientFinishedError::UnknownCommitment)
        }
    }
}

pub struct Ukey2Server {
    completed_handshake: CompletedHandshake,
}

impl fmt::Debug for Ukey2Server {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "Ukey2Server")
    }
}

impl Ukey2Server {
    pub fn completed_handshake(&self) -> &CompletedHandshake {
        &self.completed_handshake
    }
}

pub struct Ukey2ClientStage1<C: CryptoProvider, E: ErrorHandler> {
    curve25519_secret: <C::X25519 as EcdhProvider<X25519>>::EphemeralSecret,
    p256_secret: <C::P256 as EcdhProvider<P256>>::EphemeralSecret,
    curve25519_client_finished_bytes: Vec<u8>,
    p256_client_finished_bytes: Vec<u8>,
    client_init_bytes: Vec<u8>,
    commitment_ciphers: Vec<HandshakeCipher>,
    handshake_impl: HandshakeImplementation,
    pub(crate) error_logger: E,
    next_protocol: String,
    _marker: PhantomData<C>,
}

impl<C: CryptoProvider, E: ErrorHandler> fmt::Debug for Ukey2ClientStage1<C, E> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "Ukey2Client1")
    }
}

impl<C: CryptoProvider, E: ErrorHandler> Ukey2ClientStage1<C, E> {
    pub fn from<R: rand::Rng + rand::SeedableRng + rand::CryptoRng>(
        rng: &mut R,
        next_protocol: String,
        handshake_impl: HandshakeImplementation,
        error_logger: E,
    ) -> Self {
        let random = rng.gen::<[u8; 32]>().to_vec();
        // Curve25519 ClientFinished Message
        let curve25519_secret =
            <C::X25519 as EcdhProvider<X25519>>::EphemeralSecret::generate_random(&mut *rng);
        let curve25519_client_finished_bytes = {
            let mut client_finished = ukey::Ukey2ClientFinished::default();
            client_finished.set_public_key(curve25519_secret.public_key_bytes());
            client_finished.to_wrapped_msg().write_to_bytes().unwrap()
        };
        let curve25519_client_finished_hash =
            C::Sha512::sha512(&curve25519_client_finished_bytes).to_vec();

        // P256 ClientFinished Message
        let p256_secret =
            <C::P256 as EcdhProvider<P256>>::EphemeralSecret::generate_random(&mut *rng);
        let p256_client_finished_bytes = {
            let mut client_finished = ukey::Ukey2ClientFinished::default();
            client_finished.set_public_key(
                handshake_impl
                    .encode_public_key::<C>(
                        p256_secret.public_key_bytes(),
                        HandshakeCipher::P256Sha512,
                    )
                    .unwrap(),
            );
            client_finished.to_wrapped_msg().write_to_bytes().unwrap()
        };
        let p256_client_finished_hash = C::Sha512::sha512(&p256_client_finished_bytes).to_vec();

        // ClientInit Message
        let client_init_bytes = {
            let mut curve25519_commitment = ukey::Ukey2ClientInit_CipherCommitment::default();
            curve25519_commitment
                .set_handshake_cipher(HandshakeCipher::Curve25519Sha512.as_proto());
            curve25519_commitment.set_commitment(curve25519_client_finished_hash);

            let mut p256_commitment = ukey::Ukey2ClientInit_CipherCommitment::default();
            p256_commitment.set_handshake_cipher(HandshakeCipher::P256Sha512.as_proto());
            p256_commitment.set_commitment(p256_client_finished_hash);

            let mut client_init = ukey::Ukey2ClientInit::default();
            client_init.set_version(1);
            client_init.set_random(random);
            client_init.set_cipher_commitments(vec![curve25519_commitment, p256_commitment].into());
            client_init.set_next_protocol(next_protocol.to_string());
            client_init.to_wrapped_msg().write_to_bytes().unwrap()
        };

        Self {
            curve25519_secret,
            p256_secret,
            curve25519_client_finished_bytes,
            p256_client_finished_bytes,
            client_init_bytes,
            commitment_ciphers: vec![
                HandshakeCipher::Curve25519Sha512,
                HandshakeCipher::P256Sha512,
            ],
            handshake_impl,
            error_logger,
            next_protocol,
            _marker: PhantomData,
        }
    }

    pub fn client_init_msg(&self) -> &[u8] {
        &self.client_init_bytes
    }

    pub(crate) fn handle_server_init(
        self,
        server_init: ServerInit,
        server_init_bytes: Vec<u8>,
    ) -> Result<Ukey2Client, ServerInitError> {
        if server_init.version() != &1 {
            return Err(ServerInitError::BadVersion);
        }

        // loop over all commitments every time for a semblance of constant time-ness
        // TODO better constant time way of doing this?
        let server_cipher = self
            .commitment_ciphers
            .iter()
            .fold(None, |accum, c| {
                if server_init.handshake_cipher() == c {
                    match accum {
                        None => Some(c),
                        Some(_) => accum,
                    }
                } else {
                    accum
                }
            })
            .ok_or(ServerInitError::BadHandshakeCipher)?;
        let (server_shared_secret, client_finished_bytes) = match server_cipher {
            HandshakeCipher::P256Sha512 => {
                let other_public_key = &<C::P256 as P256EcdhProvider>::PublicKey::from_sec1_bytes(
                    self.handshake_impl
                        .decode_public_key::<C>(
                            server_init.public_key.to_vec(),
                            HandshakeCipher::P256Sha512,
                        )
                        .ok_or(ServerInitError::BadPublicKey)?
                        .as_slice(),
                )
                .map_err(|_| ServerInitError::BadPublicKey)?;
                let shared_secret = self
                    .p256_secret
                    .diffie_hellman(other_public_key)
                    .map_err(|_| ServerInitError::BadKeyExchange)?;
                let shared_secret_bytes: [u8; 32] = shared_secret.into();
                (shared_secret_bytes, self.p256_client_finished_bytes)
            }
            HandshakeCipher::Curve25519Sha512 => {
                let pub_key: [u8; 32] = server_init
                    .public_key
                    .try_into()
                    .map_err(|_| ServerInitError::BadPublicKey)?;
                (
                    self.curve25519_secret
                        .diffie_hellman(
                            &<C::X25519 as EcdhProvider<X25519>>::PublicKey::from_bytes(&pub_key)
                                .map_err(|_| ServerInitError::BadPublicKey)?,
                        )
                        .map_err(|_| ServerInitError::BadKeyExchange)?
                        .into(),
                    self.curve25519_client_finished_bytes,
                )
            }
        };
        let shared_secret_bytes = C::Sha256::sha256(&server_shared_secret).to_vec();
        Ok(Ukey2Client {
            client_finished_bytes,
            completed_handshake: CompletedHandshake::new(
                self.client_init_bytes,
                server_init_bytes.to_vec(),
                shared_secret_bytes,
                self.next_protocol,
            ),
        })
    }
}

#[derive(Debug)]
#[allow(clippy::enum_variant_names)]
pub(crate) enum ServerInitError {
    BadVersion,
    BadHandshakeCipher,
    BadPublicKey,
    /// The diffie-hellman key exchange failed to generate a shared secret
    BadKeyExchange,
}

#[derive(Clone)]
pub struct Ukey2Client {
    completed_handshake: CompletedHandshake,
    client_finished_bytes: Vec<u8>,
}

impl fmt::Debug for Ukey2Client {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "Ukey2Client")
    }
}

impl Ukey2Client {
    pub fn client_finished_msg(&self) -> &[u8] {
        &self.client_finished_bytes
    }

    pub fn completed_handshake(&self) -> &CompletedHandshake {
        &self.completed_handshake
    }
}

#[allow(clippy::enum_variant_names)]
pub enum ClientInitError {
    BadVersion,
    BadHandshakeCipher,
    BadNextProtocol,
}

pub enum ClientFinishedError {
    BadEd25519Key,
    BadP256Key,
    UnknownCommitment,
    /// The diffie-hellman key exchange failed to generate a shared secret
    BadKeyExchange,
}

/// The result of completing the UKEY2 handshake.
#[derive(Clone)]
pub struct CompletedHandshake {
    client_init_bytes: Vec<u8>,
    server_init_bytes: Vec<u8>,
    shared_secret: Vec<u8>,
    pub next_protocol: String,
}

impl CompletedHandshake {
    fn new(
        client_init_bytes: Vec<u8>,
        server_init_bytes: Vec<u8>,
        shared_secret: Vec<u8>,
        next_protocol: String,
    ) -> Self {
        Self {
            client_init_bytes,
            server_init_bytes,
            shared_secret,
            next_protocol,
        }
    }

    /// Returns an HKDF for the UKEY2 `AUTH_STRING`.
    pub fn auth_string<C: CryptoProvider>(&self) -> HandshakeHkdf<C> {
        HandshakeHkdf::new(
            &self.client_init_bytes,
            &self.server_init_bytes,
            C::HkdfSha256::new(Some(HKDF_SALT_AUTH), &self.shared_secret),
        )
    }

    /// Returns an HKDF for the UKEY2 `NEXT_SECRET`.
    pub fn next_protocol_secret<C: CryptoProvider>(&self) -> HandshakeHkdf<C> {
        HandshakeHkdf::new(
            &self.client_init_bytes,
            &self.server_init_bytes,
            C::HkdfSha256::new(Some(HKDF_SALT_NEXT), &self.shared_secret),
        )
    }
}

/// A UKEY2 handshake secret that can derive output at the caller's preferred length.
pub struct HandshakeHkdf<'a, C: CryptoProvider> {
    client_init_bytes: &'a [u8],
    server_init_bytes: &'a [u8],
    hkdf: C::HkdfSha256,
}

impl<'a, C: CryptoProvider> HandshakeHkdf<'a, C> {
    /// Returns `None` if the requested size > 255 * 512 bytes.
    pub fn derive_array<const N: usize>(&self) -> Option<[u8; N]> {
        let mut buf = [0; N];
        self.derive_slice(&mut buf).map(|_| buf)
    }

    /// Returns `None` if the requested `length` > 255 * 512 bytes.
    pub fn derive_vec(&self, length: usize) -> Option<Vec<u8>> {
        let mut buf = vec![0; length];
        self.derive_slice(&mut buf).map(|_| buf)
    }

    /// Returns `None` if the provided `buf` has size > 255 * 512 bytes.
    pub fn derive_slice(&self, buf: &mut [u8]) -> Option<()> {
        self.hkdf
            .expand_multi_info(&[self.client_init_bytes, self.server_init_bytes], buf)
            .ok()
    }

    fn new(client_init_bytes: &'a [u8], server_init_bytes: &'a [u8], hkdf: C::HkdfSha256) -> Self {
        Self {
            client_init_bytes,
            server_init_bytes,
            hkdf,
        }
    }
}
