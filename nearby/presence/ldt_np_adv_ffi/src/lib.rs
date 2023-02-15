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
#![no_std]
#![deny(
    missing_docs,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::panic,
    clippy::expect_used
)]
// These features are needed to support no_std + alloc
#![feature(lang_items)]
#![feature(alloc_error_handler)]

//! Rust ffi wrapper of ldt_np_adv, can be called from C/C++ Clients

#[cfg(test)]
mod tests;

// Allow using Box in no_std
extern crate alloc;

// if the std feature is turned on we will bring in the std library for allocating and panicking
#[cfg(feature = "std")]
extern crate std;

// Test pulls in std which causes duplicate errors
#[cfg(not(test))]
#[cfg(not(feature = "std"))]
mod no_std;

use alloc::{boxed::Box, collections::btree_map::BTreeMap};
use core::slice;
use lazy_static::lazy_static;
use ldt_np_adv::*;
use rand_chacha::{
    rand_core::{RngCore, SeedableRng},
    ChaCha20Rng,
};
use zerocopy::{AsBytes, FromBytes, LayoutVerified, Unaligned};

#[cfg(feature = "openssl")]
use crypto_provider_openssl::Openssl as CryptoProviderImpl;

#[cfg(not(feature = "openssl"))]
use crypto_provider_rustcrypto::RustCrypto as CryptoProviderImpl;

type LdtAdvDecrypterAes128 = LdtAdvDecrypterAes<CryptoProviderImpl>;

// Global hashmap to track valid pointers, this is a safety precaution to make sure we are not
// reading from unsafe memory address's passed in by caller.
lazy_static! {
    static ref HANDLE_MAP: spin::Mutex<BTreeMap<u64, Box<LdtAdvDecrypterAes128>>> =
        spin::Mutex::new(BTreeMap::new());
}

const SUCCESS: i32 = 0;

#[repr(C)]
struct NpLdtKeySeed {
    bytes: [u8; 32],
}

#[repr(C)]
struct NpMetadataKeyHmac {
    bytes: [u8; 32],
}

#[derive(Unaligned, FromBytes, AsBytes, Debug, PartialEq)]
#[repr(C)]
struct NpLdtAesBlock {
    bytes: [u8; 16],
}

#[repr(C)]
struct NpLdtSalt {
    bytes: [u8; 2],
}

#[no_mangle]
extern "C" fn NpLdtCreate(key_seed: NpLdtKeySeed, metadata_key_hmac: NpMetadataKeyHmac) -> u64 {
    // check the alignment of the platform, if it is wrong return 0
    let mut test_block = [0u8; 16];
    if LayoutVerified::<&mut [u8], NpLdtAesBlock>::new_unaligned(test_block.as_mut_slice())
        .is_none()
    {
        return 0;
    }

    let ldt_adv_cipher_config = LdtAdvCipherConfig::new(key_seed.bytes, metadata_key_hmac.bytes);
    let cipher = ldt_adv_cipher_config.build_adv_decrypter_xts_aes_128::<CryptoProviderImpl>();

    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed)
        .map(|_| {
            let mut rng = ChaCha20Rng::from_seed(seed);
            let handle: u64 = rng.next_u64();
            let cipher = Box::new(cipher);
            HANDLE_MAP.lock().insert(handle, cipher);
            handle
        })
        .unwrap_or(0)
}

#[no_mangle]
extern "C" fn NpLdtClose(handle: u64) -> i32 {
    map_to_error_code(|| {
        HANDLE_MAP
            .lock()
            .remove(&handle)
            .ok_or(CloseCipherError::InvalidHandle)
            .map(|_| 0)
    })
}

#[no_mangle]
// continue to use LdtAdvDecrypter::encrypt() for now, but we should expose a higher level API
// and get rid of this.
#[allow(deprecated)]
extern "C" fn NpLdtEncrypt(
    handle: u64,
    buffer: *mut u8,
    buffer_len: usize,
    salt: NpLdtSalt,
) -> i32 {
    map_to_error_code(|| {
        let data = unsafe { slice::from_raw_parts_mut(buffer, buffer_len) };
        let padder = salt_padder::<16, CryptoProviderImpl>(LegacySalt::from(salt.bytes));
        HANDLE_MAP
            .lock()
            .get(&handle)
            .map(|cipher| {
                cipher
                    .encrypt(data, &padder)
                    .map(|_| 0)
                    .map_err(|e| match e {
                        ldt::LdtError::InvalidLength(_) => EncryptError::InvalidLength,
                    })
            })
            .unwrap_or(Err(EncryptError::InvalidHandle))
    })
}

#[no_mangle]
extern "C" fn NpLdtDecryptAndVerify(
    handle: u64,
    buffer: *mut u8,
    buffer_len: usize,
    salt: NpLdtSalt,
) -> i32 {
    map_to_error_code(|| {
        let data = unsafe { slice::from_raw_parts_mut(buffer, buffer_len) };
        let padder = salt_padder::<16, CryptoProviderImpl>(LegacySalt::from(salt.bytes));
        HANDLE_MAP
            .lock()
            .get(&handle)
            .map(|cipher| {
                cipher
                    .decrypt_and_verify(data, &padder)
                    .map_err(|e| match e {
                        LdtAdvDecryptError::InvalidLength(_) => DecryptError::InvalidLength,
                        LdtAdvDecryptError::MacMismatch => DecryptError::HmacDoesntMatch,
                    })
                    .map(|plaintext| {
                        data.copy_from_slice(plaintext.as_slice());
                        SUCCESS
                    })
            })
            .unwrap_or(Err(DecryptError::InvalidHandle))
    })
}

fn map_to_error_code<T, E: ErrorEnum<T>, F: Fn() -> Result<T, E>>(f: F) -> T {
    f().unwrap_or_else(|e| e.to_error_code())
}

trait ErrorEnum<C> {
    fn to_error_code(&self) -> C;
}

enum CloseCipherError {
    InvalidHandle,
}

impl ErrorEnum<i32> for CloseCipherError {
    fn to_error_code(&self) -> i32 {
        match self {
            Self::InvalidHandle => -3,
        }
    }
}

enum EncryptError {
    InvalidLength,
    InvalidHandle,
}

impl ErrorEnum<i32> for EncryptError {
    fn to_error_code(&self) -> i32 {
        match self {
            Self::InvalidLength => -1,
            Self::InvalidHandle => -3,
        }
    }
}

enum DecryptError {
    HmacDoesntMatch,
    InvalidLength,
    InvalidHandle,
}

impl ErrorEnum<i32> for DecryptError {
    fn to_error_code(&self) -> i32 {
        match self {
            Self::InvalidLength => -1,
            Self::HmacDoesntMatch => -2,
            Self::InvalidHandle => -3,
        }
    }
}
