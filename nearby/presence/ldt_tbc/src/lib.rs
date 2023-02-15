#![no_std]
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
#![forbid(unsafe_code)]
#![deny(
    missing_docs,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::panic,
    clippy::expect_used
)]

//! Defining traits for an LDT specific Tweakable Block Cipher

/// `B` is the block size in bytes.
pub trait TweakableBlockCipher<const B: usize> {
    /// The tweak type used with encryption/decryption.
    type Tweak: From<[u8; B]>;

    /// the tweakable block cipher key type for the tbc
    type Key: TweakableBlockCipherKey;

    /// Create a new tweakable block cipher for ldt from a tbc key
    fn new(key: &Self::Key) -> Self;

    /// Encrypt `block` in place using the specified `tweak`.
    fn encrypt(&self, tweak: Self::Tweak, block: &mut [u8; B]);

    /// Decrypt `block` in place using the specified `tweak`.
    fn decrypt(&self, tweak: Self::Tweak, block: &mut [u8; B]);
}

/// A tweakable block cipher key as used by LDT
pub trait TweakableBlockCipherKey: Sized {
    /// Two tweakable block cipher keys concatenated, as used by LDT
    type ConcatenatedKeyArray: ConcatenatedKeyArray;

    /// Split a concatenated array of two keys' bytes into individual keys.
    fn split_from_concatenated(key: &Self::ConcatenatedKeyArray) -> (Self, Self);

    /// Concatenate with another key to form an array of both key's bytes.
    fn concatenate_with(&self, other: &Self) -> Self::ConcatenatedKeyArray;
}

/// The array form of two concatenated tweakable block cipher keys.
pub trait ConcatenatedKeyArray: Sized {
    /// Build a concatenated key from a secure RNG.
    fn from_random<R: rand::Rng + rand::CryptoRng>(rng: &mut R) -> Self;
}

impl ConcatenatedKeyArray for [u8; 64] {
    fn from_random<R: rand::Rng + rand::CryptoRng>(rng: &mut R) -> Self {
        let mut arr = [0; 64];
        rng.fill(&mut arr);
        arr
    }
}

impl ConcatenatedKeyArray for [u8; 128] {
    fn from_random<R: rand::Rng + rand::CryptoRng>(rng: &mut R) -> Self {
        let mut arr = [0; 128];
        rng.fill(&mut arr);
        arr
    }
}
