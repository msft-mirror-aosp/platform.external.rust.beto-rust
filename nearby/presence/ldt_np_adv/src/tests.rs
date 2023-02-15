// Copyright 2022 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
#![allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::panic,
    clippy::expect_used
)]

extern crate alloc;

use crate::{
    ldt_xts_aes_128, salt_padder, LdtAdvDecryptError, LdtAdvDecrypterAes, LdtXtsAes128, LegacySalt,
    LDT_XTS_AES_MAX_LEN, NP_LEGACY_METADATA_KEY_LEN,
};
use alloc::vec::Vec;
use crypto_provider::CryptoProvider;
use crypto_provider_rustcrypto::RustCrypto;
use ldt::{DefaultPadder, LdtError, LdtKey, XorPadder};
use rand_ext::{random_vec, seeded_rng};

#[test]
fn decrypt_matches_correct_ciphertext() {
    let mut rng = seeded_rng();
    for _ in 0..1_000 {
        let test_state = make_test_components::<_, RustCrypto>(&mut rng);

        let cipher = LdtAdvDecrypterAes {
            ldt: test_state.ldt,
            metadata_key_hmac: test_state.hmac,
            metadata_key_hmac_key: test_state.hmac_key,
        };
        let decrypted = cipher
            .decrypt_and_verify(&test_state.ciphertext, &test_state.padder)
            .unwrap();

        assert_eq!(&test_state.plaintext, decrypted.as_ref());
    }
}

#[test]
fn decrypt_doesnt_match_when_ciphertext_mangled() {
    let mut rng = seeded_rng();
    for _ in 0..1_000 {
        let mut test_state = make_test_components::<_, RustCrypto>(&mut rng);

        // mangle the ciphertext
        test_state.ciphertext[0] ^= 0xAA;

        let cipher = LdtAdvDecrypterAes {
            ldt: test_state.ldt,
            metadata_key_hmac: test_state.hmac,
            metadata_key_hmac_key: test_state.hmac_key,
        };
        assert_eq!(
            Err(LdtAdvDecryptError::MacMismatch),
            cipher.decrypt_and_verify(&test_state.ciphertext, &test_state.padder)
        );
    }
}

#[test]
fn decrypt_doesnt_match_when_plaintext_doesnt_match_mac() {
    let mut rng = seeded_rng();
    for _ in 0..1_000 {
        let mut test_state = make_test_components::<_, RustCrypto>(&mut rng);

        // mangle the mac
        test_state.hmac[0] ^= 0xAA;

        let cipher = LdtAdvDecrypterAes {
            ldt: test_state.ldt,
            metadata_key_hmac: test_state.hmac,
            metadata_key_hmac_key: test_state.hmac_key,
        };

        assert_eq!(
            Err(LdtAdvDecryptError::MacMismatch),
            cipher.decrypt_and_verify(&test_state.ciphertext, &test_state.padder)
        );
    }
}

#[test]
#[allow(deprecated)]
fn encrypt_works() {
    let mut rng = seeded_rng();
    for _ in 0..1_000 {
        let test_state = make_test_components::<_, RustCrypto>(&mut rng);

        let cipher = LdtAdvDecrypterAes {
            ldt: test_state.ldt,
            metadata_key_hmac: test_state.hmac,
            metadata_key_hmac_key: test_state.hmac_key,
        };

        let mut plaintext_copy = test_state.plaintext.clone();
        cipher
            .encrypt(&mut plaintext_copy[..], &test_state.padder)
            .unwrap();

        assert_eq!(test_state.ciphertext, plaintext_copy);
    }
}

#[test]
#[allow(deprecated)]
fn encrypt_too_short_err() {
    let ldt = ldt_xts_aes_128::<RustCrypto>(&LdtKey::from_concatenated(&[0; 64]));
    let adv_cipher = LdtAdvDecrypterAes {
        ldt,
        metadata_key_hmac: [0; 32],
        metadata_key_hmac_key: np_hkdf::NpHmacSha256Key::<RustCrypto>::from([0; 32]),
    };

    let mut payload = [0; 7];
    assert_eq!(
        Err(LdtError::InvalidLength(7)),
        adv_cipher.encrypt(&mut payload, &DefaultPadder::default())
    );
}

#[test]
#[allow(deprecated)]
fn encrypt_too_long_err() {
    let ldt = ldt_xts_aes_128::<RustCrypto>(&LdtKey::from_concatenated(&[0; 64]));
    let adv_cipher = LdtAdvDecrypterAes {
        ldt,
        metadata_key_hmac: [0; 32],
        metadata_key_hmac_key: np_hkdf::NpHmacSha256Key::<RustCrypto>::from([0; 32]),
    };

    let mut payload = [0; 40];
    assert_eq!(
        Err(LdtError::InvalidLength(40)),
        adv_cipher.encrypt(&mut payload, &DefaultPadder::default())
    );
}

#[test]
fn decrypt_too_short_err() {
    let ldt = ldt_xts_aes_128::<RustCrypto>(&LdtKey::from_concatenated(&[0; 64]));
    let adv_cipher = LdtAdvDecrypterAes {
        ldt,
        metadata_key_hmac: [0; 32],
        metadata_key_hmac_key: np_hkdf::NpHmacSha256Key::<RustCrypto>::from([0; 32]),
    };

    let payload = [0; 7];
    assert_eq!(
        Err(LdtAdvDecryptError::InvalidLength(7)),
        adv_cipher.decrypt_and_verify(&payload, &DefaultPadder::default())
    );
}

#[test]
fn decrypt_too_long_err() {
    let ldt = ldt_xts_aes_128::<RustCrypto>(&LdtKey::from_concatenated(&[0; 64]));
    let adv_cipher = LdtAdvDecrypterAes {
        ldt,
        metadata_key_hmac: [0; 32],
        metadata_key_hmac_key: np_hkdf::NpHmacSha256Key::<RustCrypto>::from([0; 32]),
    };

    let payload = [0; 40];
    assert_eq!(
        Err(LdtAdvDecryptError::InvalidLength(40)),
        adv_cipher.decrypt_and_verify(&payload, &DefaultPadder::default())
    );
}

/// Returns (plaintext, ciphertext, padder, hmac key, MAC, ldt)
fn make_test_components<R: rand::Rng, C: crypto_provider::CryptoProvider>(
    rng: &mut R,
) -> LdtAdvTestComponents<C> {
    // [1, 2) blocks of XTS-AES
    let payload_len = rng
        .gen_range(crypto_provider::aes::BLOCK_SIZE..=(crypto_provider::aes::BLOCK_SIZE * 2 - 1));
    let plaintext = random_vec(rng, payload_len);

    let salt = LegacySalt { bytes: rng.gen() };
    let padder = salt_padder::<16, C>(salt);

    let key_seed: [u8; 32] = rng.gen();
    let hkdf = np_hkdf::NpKeySeedHkdf::new(&key_seed);
    let ldt_key = hkdf.legacy_ldt_key();
    let hmac_key = hkdf.legacy_metadata_key_hmac_key();
    let hmac: [u8; 32] = hmac_key.calculate_hmac(&plaintext[..NP_LEGACY_METADATA_KEY_LEN]);

    let ldt = ldt_xts_aes_128::<C>(&ldt_key);

    let mut ciphertext = [0_u8; LDT_XTS_AES_MAX_LEN];
    ciphertext[..plaintext.len()].copy_from_slice(&plaintext);
    ldt.encrypt(&mut ciphertext[..plaintext.len()], &padder)
        .unwrap();

    LdtAdvTestComponents {
        plaintext,
        ciphertext: ciphertext[..payload_len].to_vec(),
        padder,
        hmac_key,
        hmac,
        ldt,
    }
}

struct LdtAdvTestComponents<C: CryptoProvider> {
    plaintext: Vec<u8>,
    ciphertext: Vec<u8>,
    padder: XorPadder<{ crypto_provider::aes::BLOCK_SIZE }>,
    hmac_key: np_hkdf::NpHmacSha256Key<C>,
    hmac: [u8; 32],
    ldt: LdtXtsAes128<C>,
}
