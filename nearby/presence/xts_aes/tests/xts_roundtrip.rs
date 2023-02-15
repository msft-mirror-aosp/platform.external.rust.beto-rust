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

use aes::{cipher, cipher::KeyInit as _};
use crypto_provider::{aes::*, CryptoProvider};
use crypto_provider_rustcrypto::RustCrypto;
use rand::{self, distributions, Rng as _};
use rand_ext::seeded_rng;
use xts_aes::*;

#[test]
fn roundtrip_self() {
    let mut rng = seeded_rng();
    for _ in 0..100_000 {
        if rng.gen() {
            let mut key = [0_u8; 32];
            rng.fill(&mut key);
            do_roundtrip(
                build_xts_aes::<_, <RustCrypto as CryptoProvider>::Aes128>(&XtsAes128Key::from(
                    &key,
                )),
                &mut rng,
            )
        } else {
            let mut key = [0_u8; 64];
            rng.fill(&mut key);
            do_roundtrip(
                build_xts_aes::<_, <RustCrypto as CryptoProvider>::Aes256>(&XtsAes256Key::from(
                    &key,
                )),
                &mut rng,
            )
        };
    }

    fn do_roundtrip<A: Aes, R: rand::Rng>(xts: Xts<A>, rng: &mut R) {
        let plaintext_len_range = distributions::Uniform::new_inclusive(BLOCK_SIZE, BLOCK_SIZE * 4);
        let mut plaintext = Vec::<u8>::new();
        plaintext.extend(
            (0..rng.sample(plaintext_len_range))
                .into_iter()
                .map(|_| rng.gen::<u8>()),
        );

        let mut ciphertext = plaintext.clone();
        let tweak: Tweak = rng.gen::<u128>().into();
        xts.encrypt_data_unit(tweak.clone(), &mut ciphertext)
            .unwrap();

        assert_eq!(plaintext.len(), ciphertext.len());
        assert_ne!(plaintext, ciphertext);

        xts.decrypt_data_unit(tweak, &mut ciphertext).unwrap();
        assert_eq!(plaintext, ciphertext);
    }
}

#[test]
fn identical_to_xtsmode_crate() {
    // xts-mode crate exists, but is tied to RustCrypto, which we can't necessarily use with
    // whatever C/assembly we need to use on embedded platforms. Thus, we have our own, but
    // we can compare our impl's results with theirs.

    let mut rng = seeded_rng();

    for _ in 0..100_000 {
        if rng.gen() {
            let mut key = [0; 32];
            rng.fill(&mut key);
            let xts = build_xts_aes::<_, <RustCrypto as CryptoProvider>::Aes128>(
                &XtsAes128Key::from(&key),
            );

            let primary_cipher =
                aes::Aes128::new(cipher::generic_array::GenericArray::from_slice(&key[0..16]));
            let tweak_cipher =
                aes::Aes128::new(cipher::generic_array::GenericArray::from_slice(&key[16..]));
            let other_xts = xts_mode::Xts128::new(primary_cipher, tweak_cipher);

            do_roundtrip(xts, other_xts, &mut rng)
        } else {
            let mut key = [0; 64];
            rng.fill(&mut key);
            let xts = build_xts_aes::<_, <RustCrypto as CryptoProvider>::Aes256>(
                &XtsAes256Key::from(&key),
            );

            let primary_cipher =
                aes::Aes256::new(cipher::generic_array::GenericArray::from_slice(&key[0..32]));
            let tweak_cipher =
                aes::Aes256::new(cipher::generic_array::GenericArray::from_slice(&key[32..]));
            let other_xts = xts_mode::Xts128::new(primary_cipher, tweak_cipher);

            do_roundtrip(xts, other_xts, &mut rng)
        };
    }

    fn do_roundtrip<
        A: Aes,
        C: cipher::BlockEncrypt + cipher::BlockDecrypt + cipher::BlockCipher,
        R: rand::Rng,
    >(
        xts: Xts<A>,
        other_xts: xts_mode::Xts128<C>,
        rng: &mut R,
    ) {
        // 1-3 blocks
        let plaintext_len_range = distributions::Uniform::new_inclusive(BLOCK_SIZE, BLOCK_SIZE * 4);
        let mut plaintext = Vec::<u8>::new();
        plaintext.extend(
            (0..rng.sample(plaintext_len_range))
                .into_iter()
                .map(|_| rng.gen::<u8>()),
        );

        // encrypt with our impl
        let mut ciphertext = plaintext.clone();
        let tweak: Tweak = rng.gen::<u128>().into();
        xts.encrypt_data_unit(tweak.clone(), &mut ciphertext)
            .unwrap();

        // encrypt with the other impl
        let mut other_ciphertext = plaintext.clone();
        let tweak_bytes = tweak.le_bytes();
        other_xts.encrypt_sector(&mut other_ciphertext[..], tweak_bytes);

        assert_eq!(ciphertext, other_ciphertext);

        // decrypt ciphertext in place
        xts.decrypt_data_unit(tweak, &mut ciphertext).unwrap();
        assert_eq!(plaintext, ciphertext);

        // and with the other impl
        other_xts.decrypt_sector(&mut other_ciphertext[..], tweak_bytes);

        assert_eq!(ciphertext, other_ciphertext);
    }
}
