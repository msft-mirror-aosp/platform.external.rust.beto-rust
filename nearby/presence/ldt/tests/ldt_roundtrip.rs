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

use crypto_provider::aes::BLOCK_SIZE;
use crypto_provider_rustcrypto::RustCrypto;
use ldt::*;
use ldt_tbc::TweakableBlockCipher;
use rand::{self, distributions, Rng as _, SeedableRng as _};
use rand_ext::{random_bytes, random_vec};
use xts_aes::{XtsAes128, XtsAes256};

#[test]
fn roundtrip_normal_padder() {
    let mut rng = rand::rngs::StdRng::from_entropy();
    let plaintext_len_range = distributions::Uniform::new_inclusive(BLOCK_SIZE, BLOCK_SIZE * 2 - 1);

    for _ in 0..100_000 {
        if rng.gen() {
            do_roundtrip(
                Ldt::<16, XtsAes128<RustCrypto>, Swap>::new(&LdtKey::from_random(&mut rng)),
                &DefaultPadder::default(),
                &mut rng,
                &plaintext_len_range,
            )
        } else {
            do_roundtrip(
                Ldt::<16, XtsAes256<RustCrypto>, Swap>::new(&LdtKey::from_random(&mut rng)),
                &DefaultPadder::default(),
                &mut rng,
                &plaintext_len_range,
            )
        };
    }
}

#[test]
fn roundtrip_xor_padder() {
    let mut rng = rand::rngs::StdRng::from_entropy();
    // 2 bytes smaller becauwe're using a 2 byte salt
    let plaintext_len_range =
        distributions::Uniform::new_inclusive(BLOCK_SIZE, BLOCK_SIZE * 2 - 1 - 2);

    for _ in 0..100_000 {
        let padder: XorPadder<BLOCK_SIZE> = random_bytes(&mut rng).into();
        if rng.gen() {
            do_roundtrip(
                Ldt::<16, XtsAes128<RustCrypto>, Swap>::new(&LdtKey::from_random(&mut rng)),
                &padder,
                &mut rng,
                &plaintext_len_range,
            )
        } else {
            do_roundtrip(
                Ldt::<16, XtsAes256<RustCrypto>, Swap>::new(&LdtKey::from_random(&mut rng)),
                &padder,
                &mut rng,
                &plaintext_len_range,
            )
        };
    }
}

fn do_roundtrip<
    const B: usize,
    T: TweakableBlockCipher<B>,
    P: Padder<B, T>,
    M: Mix,
    R: rand::Rng,
>(
    ldt: Ldt<B, T, M>,
    padder: &P,
    rng: &mut R,
    plaintext_len_range: &distributions::Uniform<usize>,
) {
    let len = rng.sample(plaintext_len_range);
    let plaintext = random_vec(rng, len);

    let mut ciphertext = plaintext.clone();
    ldt.encrypt(&mut ciphertext, padder).unwrap();

    assert_eq!(plaintext.len(), ciphertext.len());
    assert_ne!(plaintext, ciphertext);

    ldt.decrypt(&mut ciphertext, padder).unwrap();
    assert_eq!(plaintext, ciphertext);
}
