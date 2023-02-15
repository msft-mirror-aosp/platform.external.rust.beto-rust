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

//! Nearby Presence-specific usage of LDT.
#![no_std]
#![forbid(unsafe_code)]
#![deny(
    missing_docs,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::panic,
    clippy::expect_used
)]

#[cfg(test)]
mod np_adv_test_vectors;
#[cfg(test)]
mod tests;

use array_view::ArrayView;
use core::fmt;
use crypto_provider::hmac::Hmac;
use crypto_provider::CryptoProvider;
use ldt::{Ldt, LdtError, LdtKey, Mix, Padder, Swap, XorPadder};
use ldt_tbc::TweakableBlockCipher;
use np_hkdf::legacy_ldt_expanded_salt;
use xts_aes::{XtsAes128, XtsAes128Key, XtsAes256, XtsAes256Key};

/// Max LDT-XTS-AES data size: `(2 * AES block size) - 1`
pub const LDT_XTS_AES_MAX_LEN: usize = 31;
/// Legacy (v0) format uses 14-byte metadata key
pub const NP_LEGACY_METADATA_KEY_LEN: usize = 14;

/// The salt included in an NP advertisement
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LegacySalt {
    /// Salt bytes extracted from the incoming NP advertisement
    bytes: [u8; 2],
}

impl LegacySalt {
    /// Returns the salt as a byte array.
    pub fn bytes(&self) -> &[u8; 2] {
        &self.bytes
    }
}

impl From<[u8; 2]> for LegacySalt {
    fn from(arr: [u8; 2]) -> Self {
        Self { bytes: arr }
    }
}

/// Config for one individual cipher, corresponding to a particular NP identity/credential
pub struct LdtAdvCipherConfig {
    /// The key seed in the NP credential from which other keys will be derived
    key_seed: [u8; 32],
    /// The metadata key HMAC in the NP credential
    metadata_key_hmac: [u8; 32],
}

impl LdtAdvCipherConfig {
    /// Build a config from the provided key seed and metadata key hmac.
    pub fn new(key_seed: [u8; 32], metadata_key_mac: [u8; 32]) -> Self {
        Self {
            key_seed,
            metadata_key_hmac: metadata_key_mac,
        }
    }

    /// Build an LdtAdvCipher using XTS-AES128 and keys derived from the key seed.
    pub fn build_adv_decrypter_xts_aes_128<C: CryptoProvider>(&self) -> LdtAdvDecrypterAes<C> {
        let hkdf = np_hkdf::NpKeySeedHkdf::new(&self.key_seed);

        LdtAdvDecrypter {
            ldt: ldt_xts_aes_128::<C>(&hkdf.legacy_ldt_key()),
            metadata_key_hmac: self.metadata_key_hmac,
            metadata_key_hmac_key: hkdf.legacy_metadata_key_hmac_key(),
        }
    }
}

/// Decrypts and validates a NP legacy format advertisement encrypted with LDT.
///
/// Use an [LdtAdvCipherConfig] to build one from an NP `key_seed`.
///
/// `B` is the underlying block cipher block size.
/// `O` is the max output size (must be 2 * B - 1).
/// `T` is the tweakable block cipher used by LDT.
/// `M` is the mix function used by LDT.
pub struct LdtAdvDecrypter<
    const B: usize,
    const O: usize,
    T: TweakableBlockCipher<B>,
    M: Mix,
    C: CryptoProvider,
> {
    ldt: Ldt<B, T, M>,
    metadata_key_hmac: [u8; 32],
    metadata_key_hmac_key: np_hkdf::NpHmacSha256Key<C>,
}

/// An LdtAdvCipher with block size set appropriately for AES.
pub type LdtAdvDecrypterAes<C> = LdtAdvDecrypter<
    { crypto_provider::aes::BLOCK_SIZE },
    LDT_XTS_AES_MAX_LEN,
    xts_aes::XtsAes128<C>,
    Swap,
    C,
>;

impl<const B: usize, const O: usize, T, M, C> LdtAdvDecrypter<B, O, T, M, C>
where
    T: TweakableBlockCipher<B>,
    M: Mix,
    C: CryptoProvider,
{
    /// Decrypt an advertisement payload using the provided padder.
    ///
    /// If the plaintext's metadata key matches this item's MAC, return the plaintext, otherwise `None`.
    ///
    /// # Errors
    /// - If `payload` has a length outside of `[B, B * 2)`.
    /// - If the decrypted plaintext fails its HMAC validation
    pub fn decrypt_and_verify<P: Padder<B, T>>(
        &self,
        payload: &[u8],
        padder: &P,
    ) -> Result<ArrayView<u8, O>, LdtAdvDecryptError> {
        assert_eq!(B * 2 - 1, O); // should be compiled away

        // have to check length before passing to LDT to ensure copying into the buffer is safe
        if payload.len() < B || payload.len() > O {
            return Err(LdtAdvDecryptError::InvalidLength(payload.len()));
        }

        // we copy to avoid exposing plaintext that hasn't been validated w/ hmac
        let mut buffer = [0_u8; O];
        buffer[..payload.len()].copy_from_slice(payload);

        #[allow(clippy::expect_used)]
        self.ldt
            .decrypt(&mut buffer[..payload.len()], padder)
            .map_err(|e| match e {
                LdtError::InvalidLength(l) => LdtAdvDecryptError::InvalidLength(l),
            })
            .and_then(|_| {
                let mut hmac = self.metadata_key_hmac_key.build_hmac();
                hmac.update(&buffer[..NP_LEGACY_METADATA_KEY_LEN]);
                hmac.verify_slice(&self.metadata_key_hmac)
                    .map_err(|_| LdtAdvDecryptError::MacMismatch)
                    .map(|_| {
                        ArrayView::try_from_array(buffer, payload.len())
                            .expect("this will never be hit because the length is validated above")
                    })
            })
    }

    /// Encrypt the payload in place using the provided padder.
    ///
    /// No validation is done to ensure that the metadata key is correct.
    ///
    /// # Errors
    /// - If `payload` has a length outside of `[B, B * 2)`.
    // Leaving it in place, but deprecating it, to avoid breaking ldt_np_adv_ffi which will be
    // replaced by a much more expansive FFI API soon.
    #[deprecated]
    pub fn encrypt<P: Padder<B, T>>(&self, payload: &mut [u8], padder: &P) -> Result<(), LdtError> {
        assert_eq!(B * 2 - 1, O); // should be compiled away

        self.ldt.encrypt(payload, padder)
    }

    /// Construct a cipher from its component parts.
    ///
    /// See also [LdtAdvCipherConfig] to build a cipher from an NP key seed.
    pub fn new(
        ldt: Ldt<B, T, M>,
        metadata_key_hmac: [u8; 32],
        metadata_key_hmac_key: np_hkdf::NpHmacSha256Key<C>,
    ) -> Self {
        Self {
            ldt,
            metadata_key_hmac,
            metadata_key_hmac_key,
        }
    }
}

/// Errors that can occur during [LdtAdvCipher.decrypt_and_verify].
#[derive(Debug, PartialEq, Eq)]
pub enum LdtAdvDecryptError {
    /// The ciphertext data was an invalid length.
    InvalidLength(usize),
    /// The MAC calculated from the plaintext did not match the expected value
    MacMismatch,
}

impl fmt::Display for LdtAdvDecryptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LdtAdvDecryptError::InvalidLength(len) => {
                write!(f, "Adv decrypt error: invalid length ({len})")
            }
            LdtAdvDecryptError::MacMismatch => write!(f, "Adv decrypt error: MAC mismatch"),
        }
    }
}
/// Build a XorPadder by HKDFing the NP advertisement salt
pub fn salt_padder<const B: usize, C: CryptoProvider>(salt: LegacySalt) -> XorPadder<{ B }> {
    // Assuming that the tweak size == the block size here, which it is for XTS.
    // If that's ever not true, yet another generic parameter will address that.
    XorPadder::from(legacy_ldt_expanded_salt::<B, C>(&salt.bytes))
}

/// [Ldt] parameterized for XTS-AES-128 with the [Swap] mix function.
pub type LdtXtsAes128<C> = Ldt<{ crypto_provider::aes::BLOCK_SIZE }, XtsAes128<C>, Swap>;

/// Build an [Ldt] with [xts_aes::Xts]-AES-128 and the [Swap] mix function.
pub fn ldt_xts_aes_128<C: CryptoProvider>(key: &LdtKey<XtsAes128Key>) -> LdtXtsAes128<C> {
    Ldt::new(key)
}

/// [Ldt] parameterized for XTS-AES-256 with the [Swap] mix function.
pub type LdtXtsAes256<C> = Ldt<{ crypto_provider::aes::BLOCK_SIZE }, XtsAes256<C>, Swap>;

/// Build an [Ldt] with [xts_aes::Xts]-AES-256 and the [Swap] mix function.
pub fn ldt_xts_aes_256<C: CryptoProvider>(key: &LdtKey<XtsAes256Key>) -> LdtXtsAes256<C> {
    Ldt::new(key)
}
