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

//! Implementation of `crypto_provider::aes` types using RustCrypto's `aes`.
#![forbid(unsafe_code)]

/// Module implementing AES-CBC.
#[cfg(feature = "alloc")]
pub(crate) mod cbc;

use aes::cipher::{
    generic_array, BlockDecrypt as _, BlockEncrypt as _, KeyInit as _, KeyIvInit as _,
    StreamCipher as _,
};
use crypto_provider::aes::AesKey as _;

/// Wrapper around Rust Crypto's AES-128 impl
pub struct Aes128 {
    aes: aes::Aes128,
}

/// Wrapper around Rust Crypto's AES-256 impl
pub struct Aes256 {
    aes: aes::Aes256,
}

impl crypto_provider::aes::Aes for Aes128 {
    type Key = crypto_provider::aes::Aes128Key;

    fn new(key: &Self::Key) -> Self {
        Aes128 {
            aes: aes::Aes128::new(key.as_array().into()),
        }
    }

    fn encrypt(&self, block: &mut crypto_provider::aes::AesBlock) {
        self.aes
            .encrypt_block(generic_array::GenericArray::from_mut_slice(
                block.as_mut_slice(),
            ));
    }

    fn decrypt(&self, block: &mut crypto_provider::aes::AesBlock) {
        self.aes
            .decrypt_block(generic_array::GenericArray::from_mut_slice(
                block.as_mut_slice(),
            ))
    }
}

// identical to Aes128 impl
impl crypto_provider::aes::Aes for Aes256 {
    type Key = crypto_provider::aes::Aes256Key;

    fn new(key: &Self::Key) -> Self {
        Aes256 {
            aes: aes::Aes256::new(key.as_array().into()),
        }
    }

    fn encrypt(&self, block: &mut crypto_provider::aes::AesBlock) {
        self.aes
            .encrypt_block(generic_array::GenericArray::from_mut_slice(
                block.as_mut_slice(),
            ));
    }

    fn decrypt(&self, block: &mut crypto_provider::aes::AesBlock) {
        self.aes
            .decrypt_block(generic_array::GenericArray::from_mut_slice(
                block.as_mut_slice(),
            ))
    }
}

/// RustCrypto implementation of AES-CTR 128.
pub struct AesCtr128 {
    cipher: ctr::Ctr128BE<aes::Aes128>,
}

impl crypto_provider::aes::ctr::AesCtr for AesCtr128 {
    type Key = crypto_provider::aes::Aes128Key;

    fn new(key: &Self::Key, iv: [u8; 16]) -> Self {
        Self {
            cipher: ctr::Ctr128BE::new(key.as_array().into(), &iv.into()),
        }
    }

    fn encrypt(&mut self, data: &mut [u8]) {
        self.cipher.apply_keystream(data);
    }

    fn decrypt(&mut self, data: &mut [u8]) {
        self.cipher.apply_keystream(data);
    }
}

/// RustCrypto implementation of AES-CTR 256.
pub struct AesCtr256 {
    cipher: ctr::Ctr128BE<aes::Aes256>,
}

impl crypto_provider::aes::ctr::AesCtr for AesCtr256 {
    type Key = crypto_provider::aes::Aes256Key;

    fn new(key: &Self::Key, iv: [u8; 16]) -> Self {
        Self {
            cipher: ctr::Ctr128BE::new(key.as_array().into(), &iv.into()),
        }
    }

    fn encrypt(&mut self, data: &mut [u8]) {
        self.cipher.apply_keystream(data);
    }

    fn decrypt(&mut self, data: &mut [u8]) {
        self.cipher.apply_keystream(data);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::marker::PhantomData;
    use crypto_provider::aes::ctr::testing::*;
    use crypto_provider::aes::testing::*;

    #[apply(aes_128_ctr_test_cases)]
    fn aes_128_ctr_test(testcase: CryptoProviderTestCase<AesCtr128>) {
        testcase(PhantomData);
    }

    #[apply(aes_256_ctr_test_cases)]
    fn aes_256_ctr_test(testcase: CryptoProviderTestCase<AesCtr256>) {
        testcase(PhantomData);
    }

    #[apply(aes_128_test_cases)]
    fn aes_128_test(testcase: CryptoProviderTestCase<Aes128>) {
        testcase(PhantomData);
    }

    #[apply(aes_256_test_cases)]
    fn aes_256_test(testcase: CryptoProviderTestCase<Aes256>) {
        testcase(PhantomData);
    }
}
