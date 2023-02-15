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

use crypto_provider::ed25519::{
    InvalidBytes, InvalidSignature, Signature as _, SignatureError, KEY_LENGTH, KEY_PAIR_LENGTH,
    SIGNATURE_LENGTH,
};
use ed25519_dalek::Signer;

pub struct Ed25519;
impl crypto_provider::ed25519::Ed25519Provider for Ed25519 {
    type KeyPair = KeyPair;
    type PublicKey = PublicKey;
    type Signature = Signature;
}

pub struct KeyPair(ed25519_dalek::Keypair);
impl crypto_provider::ed25519::KeyPair for KeyPair {
    type PublicKey = PublicKey;
    type Signature = Signature;

    fn to_bytes(&self) -> [u8; KEY_PAIR_LENGTH] {
        self.0.to_bytes()
    }

    fn from_bytes(bytes: [u8; KEY_PAIR_LENGTH]) -> Result<Self, InvalidBytes> {
        ed25519_dalek::Keypair::from_bytes(&bytes)
            .map(Self)
            .map_err(|_| InvalidBytes)
    }

    #[allow(clippy::expect_used)]
    fn sign(&self, msg: &[u8]) -> Self::Signature {
        Self::Signature::from_bytes(&self.0.sign(msg).to_bytes())
            .expect("a signature will always produce valid bytes for creating a Signature")
    }

    //TODO: allow providing a crypto rng and make it a no-op for openssl if the need arises to
    // improve perf of keypair generation
    fn generate() -> Self {
        let mut csprng = rand::rngs::ThreadRng::default();
        Self(ed25519_dalek::Keypair::generate(
            &mut rand_core_05_adapter::RandWrapper::from(&mut csprng),
        ))
    }

    fn public(&self) -> Self::PublicKey {
        PublicKey(self.0.public)
    }
}

pub struct Signature(ed25519_dalek::Signature);
impl crypto_provider::ed25519::Signature for Signature {
    fn from_bytes(bytes: &[u8]) -> Result<Self, InvalidSignature> {
        if bytes.len() != SIGNATURE_LENGTH {
            return Err(InvalidSignature);
        }
        ed25519_dalek::Signature::from_bytes(bytes)
            .map(Self)
            .map_err(|_| InvalidSignature)
    }

    fn to_bytes(&self) -> [u8; SIGNATURE_LENGTH] {
        self.0.to_bytes()
    }
}

pub struct PublicKey(ed25519_dalek::PublicKey);
impl crypto_provider::ed25519::PublicKey for PublicKey {
    type Signature = Signature;

    fn to_bytes(&self) -> [u8; KEY_LENGTH] {
        self.0.to_bytes()
    }

    fn verify_strict(
        &self,
        message: &[u8],
        signature: &Self::Signature,
    ) -> Result<(), SignatureError> {
        self.0
            .verify_strict(message, &signature.0)
            .map_err(|_| SignatureError)
    }
}

#[cfg(test)]
mod tests {
    use crate::ed25519::Ed25519;
    use crypto_provider::ed25519::testing::{run_rfc_test_vectors, run_wycheproof_test_vectors};

    #[test]
    fn wycheproof_test_ed25519_rustcrypto() {
        run_wycheproof_test_vectors::<Ed25519>()
    }

    #[test]
    fn rfc_test_ed25519_rustcrypto() {
        run_rfc_test_vectors::<Ed25519>()
    }
}
