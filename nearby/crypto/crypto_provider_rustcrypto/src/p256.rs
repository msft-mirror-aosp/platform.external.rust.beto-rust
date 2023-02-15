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

extern crate alloc;

use ::p256::elliptic_curve::generic_array::GenericArray;
use ::p256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use alloc::vec::Vec;
use crypto_provider::elliptic_curve::{EcdhProvider, EphemeralSecret};
use crypto_provider::p256::P256;
use p256::elliptic_curve;

/// Implementation of NIST-P256 using RustCrypto crates.
pub enum P256Ecdh {}
impl EcdhProvider<P256> for P256Ecdh {
    type PublicKey = P256PublicKey;
    type EphemeralSecret = P256EphemeralSecret;
    type SharedSecret = [u8; 32];
}

/// A NIST-P256 public key.
#[derive(Debug, PartialEq, Eq)]
pub struct P256PublicKey(p256::PublicKey);
impl crypto_provider::p256::P256PublicKey for P256PublicKey {
    type Error = elliptic_curve::Error;

    fn from_sec1_bytes(bytes: &[u8]) -> Result<Self, Self::Error> {
        p256::PublicKey::from_sec1_bytes(bytes).map(Self)
    }

    fn to_sec1_bytes(&self) -> Vec<u8> {
        self.0.to_encoded_point(true).as_bytes().to_vec()
    }

    #[allow(clippy::expect_used)]
    fn to_affine_coordinates(&self) -> Result<([u8; 32], [u8; 32]), Self::Error> {
        let p256_key = self.0.to_encoded_point(false);
        let x: &[u8; 32] = p256_key
            .x()
            .expect("Generated key should not be on identity point")
            .as_ref();
        let y: &[u8; 32] = p256_key
            .y()
            .expect("Generated key should not be on identity point")
            .as_ref();
        Ok((*x, *y))
    }
    fn from_affine_coordinates(x: &[u8; 32], y: &[u8; 32]) -> Result<Self, Self::Error> {
        let key_option: Option<p256::PublicKey> =
            p256::PublicKey::from_encoded_point(&p256::EncodedPoint::from_affine_coordinates(
                &GenericArray::clone_from_slice(x),
                &GenericArray::clone_from_slice(y),
                false,
            ))
            .into();
        key_option.map(Self).ok_or(elliptic_curve::Error)
    }
}

/// Ephemeral secrect for use in a P256 Diffie-Hellman
pub struct P256EphemeralSecret(::p256::ecdh::EphemeralSecret);

impl EphemeralSecret<P256> for P256EphemeralSecret {
    type Impl = P256Ecdh;
    type Error = sec1::Error;

    fn generate_random<R: rand::Rng + rand::CryptoRng>(rng: &mut R) -> Self {
        Self(::p256::ecdh::EphemeralSecret::random(rng))
    }

    fn public_key_bytes(&self) -> Vec<u8> {
        self.0
            .public_key()
            .to_encoded_point(false)
            .as_bytes()
            .into()
    }

    fn diffie_hellman(
        self,
        other_pub: &P256PublicKey,
    ) -> Result<<Self::Impl as EcdhProvider<P256>>::SharedSecret, Self::Error> {
        let shared_secret = p256::ecdh::EphemeralSecret::diffie_hellman(&self.0, &other_pub.0);
        let bytes: <Self::Impl as EcdhProvider<P256>>::SharedSecret =
            (*shared_secret.raw_secret_bytes()).into();
        Ok(bytes)
    }
}

#[cfg(test)]
impl crypto_provider::elliptic_curve::EphemeralSecretForTesting<P256> for P256EphemeralSecret {
    fn from_private_components(
        private_bytes: &[u8; 32],
        _public_key: &P256PublicKey,
    ) -> Result<Self, Self::Error> {
        Ok(Self::generate_random(&mut crate::testing::MockCryptoRng {
            values: private_bytes.iter(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::P256Ecdh;
    use core::marker::PhantomData;
    use crypto_provider::p256::testing::*;

    #[apply(p256_test_cases)]
    fn p256_tests(testcase: CryptoProviderTestCase<P256Ecdh>) {
        testcase(PhantomData::<P256Ecdh>)
    }
}
