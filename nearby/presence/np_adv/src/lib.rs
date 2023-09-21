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
//! Serialization and deserialization for v0 (legacy) and v1 (extended) Nearby Presence
//! advertisements.
//!
//! See `tests/examples_v0.rs` and `tests/examples_v1.rs` for some tests that show common
//! deserialization scenarios.

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

extern crate alloc;
extern crate core;
use crate::{
    credential::{
        source::{BothCredentialSource, CredentialSource},
        v0::V0CryptoMaterial,
        v1::{BorrowableIdentityResolutionMaterial, V1CryptoMaterial},
        MatchedCredFromCred, MatchedCredential, V0Credential, V1Credential,
    },
    extended::deserialize::{
        encrypted_section::*, parse_sections, CiphertextSection, DataElements, DecryptedSection,
        IntermediateSection, PlaintextSection, Section, SectionDeserializeError,
    },
    legacy::deserialize::{
        DecryptError, DecryptedAdvContents, IntermediateAdvContents, PlaintextAdvContents,
    },
};
use alloc::vec::Vec;
#[cfg(feature = "devtools")]
use array_view::ArrayView;
use core::{fmt::Debug, marker};
use crypto_provider::CryptoProvider;
#[cfg(feature = "devtools")]
use extended::NP_ADV_MAX_SECTION_LEN;
use legacy::{data_elements::DataElementDeserializeError, deserialize::AdvDeserializeError};
use nom::{combinator, number};
pub use strum;

pub mod credential;
pub mod de_type;
#[cfg(test)]
mod deser_v0_tests;
#[cfg(test)]
mod deser_v1_tests;
pub mod extended;
#[cfg(test)]
mod header_parse_tests;
pub mod legacy;
pub mod shared_data;
/// Canonical form of NP's service UUID.
///
/// Note that UUIDs are encoded in BT frames in little-endian order, so these bytes may need to be
/// reversed depending on the host BT API.
pub const NP_SVC_UUID: [u8; 2] = [0xFC, 0xF1];

/// Parse, deserialize, decrypt, and validate a complete NP advertisement (the entire contents of
/// the service data for the NP UUID).
pub fn deserialize_advertisement<'s, C0, C1, M, S, P>(
    adv: &'s [u8],
    cred_source: &'s S,
) -> Result<DeserializedAdvertisement<'s, M>, AdvDeserializationError>
where
    C0: V0Credential<Matched<'s> = M> + 's,
    C1: V1Credential<Matched<'s> = M> + 's,
    M: MatchedCredential<'s>,
    S: BothCredentialSource<C0, C1>,
    P: CryptoProvider,
{
    let (remaining, header) =
        parse_adv_header(adv).map_err(|_e| AdvDeserializationError::HeaderParseError)?;
    match header {
        AdvHeader::V1(header) => {
            deser_decrypt_v1::<C1, S::V1Source, P>(cred_source.v1(), remaining, header)
                .map(DeserializedAdvertisement::V1)
        }
        AdvHeader::V0 => deser_decrypt_v0::<C0, S::V0Source, P>(cred_source.v0(), remaining)
            .map(DeserializedAdvertisement::V0),
    }
}

/// Parse, deserialize, decrypt, and validate a complete V0 NP advertisement (the entire contents
/// of the service data for the NP UUID). If the advertisement version header does not match V0,
/// this method will return an [`AdvDeserializationError::HeaderParseError`]
pub fn deserialize_v0_advertisement<'s, C, S, P>(
    adv: &[u8],
    cred_source: &'s S,
) -> Result<V0AdvertisementContents<'s, C>, AdvDeserializationError>
where
    C: V0Credential,
    S: CredentialSource<C>,
    P: CryptoProvider,
{
    let (remaining, header) =
        parse_adv_header(adv).map_err(|_e| AdvDeserializationError::HeaderParseError)?;

    match header {
        AdvHeader::V0 => deser_decrypt_v0::<C, S, P>(cred_source, remaining),
        AdvHeader::V1(_) => Err(AdvDeserializationError::HeaderParseError),
    }
}

/// Parse, deserialize, decrypt, and validate a complete V1 NP advertisement (the entire contents
/// of the service data for the NP UUID). If the advertisement version header does not match V1,
/// this method will return an [`AdvDeserializationError::HeaderParseError`]
pub fn deserialize_v1_advertisement<'s, C, S, P>(
    adv: &'s [u8],
    cred_source: &'s S,
) -> Result<V1AdvertisementContents<'s, C>, AdvDeserializationError>
where
    C: V1Credential,
    S: CredentialSource<C>,
    P: CryptoProvider,
{
    let (remaining, header) =
        parse_adv_header(adv).map_err(|_e| AdvDeserializationError::HeaderParseError)?;

    match header {
        AdvHeader::V0 => Err(AdvDeserializationError::HeaderParseError),
        AdvHeader::V1(header) => deser_decrypt_v1::<C, S, P>(cred_source, remaining, header),
    }
}

type V1AdvertisementContents<'s, C> = V1AdvContents<'s, MatchedCredFromCred<'s, C>>;

/// The encryption scheme used for a V1 advertisement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum V1EncryptionScheme {
    /// Indicates MIC-based encryption and verification.
    Mic,
    /// Indicates signature-based encryption and verification.
    Signature,
}

/// Error in decryption operations for `deser_decrypt_v1_section_bytes_for_dev_tools`.
#[cfg(feature = "devtools")]
#[derive(Debug, Clone)]
pub enum AdvDecryptionError {
    /// Cannot decrypt because the input section is not encrypted.
    InputNotEncrypted,
    /// Error parsing the given section.
    ParseError,
    /// No suitable credential found to decrypt the given section.
    NoMatchingCredentials,
}

/// Decrypt, but do not further deserialize the v1 bytes, intended for developer tooling uses only.
/// Production uses should use [deserialize_v1_advertisement] instead, which deserializes to a
/// structured format and provides extra type safety.
#[cfg(feature = "devtools")]
pub fn deser_decrypt_v1_section_bytes_for_dev_tools<S, V1, P>(
    cred_source: &S,
    header_byte: u8,
    section_bytes: &[u8],
) -> Result<(ArrayView<u8, NP_ADV_MAX_SECTION_LEN>, V1EncryptionScheme), AdvDecryptionError>
where
    S: CredentialSource<V1>,
    V1: V1Credential,
    P: CryptoProvider,
{
    let header = V1Header { header_byte };
    let int_sections =
        parse_sections(header, section_bytes).map_err(|_| AdvDecryptionError::ParseError)?;
    let cipher_section = match &int_sections[0] {
        IntermediateSection::Plaintext(_) => Err(AdvDecryptionError::InputNotEncrypted)?,
        IntermediateSection::Ciphertext(section) => section,
    };

    for cred in cred_source.iter() {
        let crypto_material = cred.crypto_material();
        if let Some(plaintext) =
            cipher_section.try_resolve_identity_and_decrypt::<_, P>(crypto_material)
        {
            let encryption_scheme = match cipher_section {
                CiphertextSection::SignatureEncryptedIdentity(_) => V1EncryptionScheme::Signature,
                CiphertextSection::MicEncryptedIdentity(_) => V1EncryptionScheme::Mic,
            };
            return Ok((plaintext, encryption_scheme));
        }
    }
    Err(AdvDecryptionError::NoMatchingCredentials)
}

/// A ciphertext section which has not yet been
/// resolved to an identity, but for which some
/// `SectionIdentityResolutionContents` have been
/// pre-computed for speedy identity-resolution.
struct ResolvableCiphertextSection<'a> {
    identity_resolution_contents: SectionIdentityResolutionContents,
    ciphertext_section: CiphertextSection<'a>,
}

/// A collection of possibly-deserialized sections which are separated according
/// to whether/not they're intermediate encrypted sections (of either type)
/// or fully-deserialized, with a running count of the number of malformed sections.
/// Each potentially-valid section is tagged with a 0-based index derived from the original
/// section ordering as they appeared within the original advertisement to ensure
/// that the fully-deserialized advertisement may be correctly reconstructed.
struct SectionsInProcessing<'a, M: MatchedCredential<'a>> {
    deserialized_sections: Vec<(usize, V1DeserializedSection<'a, M>)>,
    encrypted_sections: Vec<(usize, ResolvableCiphertextSection<'a>)>,
    malformed_sections_count: usize,
}

impl<'a, M: MatchedCredential<'a>> SectionsInProcessing<'a, M> {
    /// Attempts to parse a V1 advertisement's contents after the version header
    /// into a collection of not-yet-fully-deserialized sections which may
    /// require credentials to be decrypted.
    fn from_advertisement_contents<C: CryptoProvider>(
        header: V1Header,
        remaining: &'a [u8],
    ) -> Result<Self, AdvDeserializationError> {
        let int_sections =
            parse_sections(header, remaining).map_err(|_| AdvDeserializationError::ParseError {
                details_hazmat: AdvDeserializationErrorDetailsHazmat::AdvertisementDeserializeError,
            })?;
        let mut deserialized_sections = Vec::new();
        let mut encrypted_sections = Vec::new();
        // keep track of ordering for later sorting during `self.finished_with_decryption_attempts()`.
        for (idx, s) in int_sections.into_iter().enumerate() {
            match s {
                IntermediateSection::Plaintext(p) => {
                    deserialized_sections.push((idx, V1DeserializedSection::Plaintext(p)))
                }
                IntermediateSection::Ciphertext(ciphertext_section) => {
                    let identity_resolution_contents =
                        ciphertext_section.contents().compute_identity_resolution_contents::<C>();
                    let resolvable_ciphertext_section = ResolvableCiphertextSection {
                        identity_resolution_contents,
                        ciphertext_section,
                    };
                    encrypted_sections.push((idx, resolvable_ciphertext_section));
                }
            }
        }
        Ok(Self { deserialized_sections, encrypted_sections, malformed_sections_count: 0 })
    }

    /// Returns true iff we have resolved all sections to identities.
    fn resolved_all_identities(&self) -> bool {
        self.encrypted_sections.is_empty()
    }

    /// Runs through all of the encrypted sections in processing, and attempts
    /// to use the given credential to decrypt them. Suitable for situations
    /// where iterating over credentials is relatively slow compared to
    /// the cost of iterating over sections-in-memory.
    fn try_decrypt_with_credential<C, P: CryptoProvider>(&mut self, cred: &'a C)
    where
        C: V1Credential<Matched<'a> = M> + 'a,
    {
        let crypto_material = cred.crypto_material();
        let mut i = 0;
        while i < self.encrypted_sections.len() {
            let (section_idx, section): &(usize, ResolvableCiphertextSection) =
                &self.encrypted_sections[i];
            // Fast-path: Check for an identity match, ignore if there's no identity match.
            let identity_resolution_contents = &section.identity_resolution_contents;
            let identity_resolution_material = match &section.ciphertext_section {
                CiphertextSection::MicEncryptedIdentity(_) => {
                    BorrowableIdentityResolutionMaterial::unsigned_from_crypto_material::<_, P>(
                        crypto_material,
                    )
                }
                CiphertextSection::SignatureEncryptedIdentity(_) => {
                    BorrowableIdentityResolutionMaterial::signed_from_crypto_material::<_, P>(
                        crypto_material,
                    )
                }
            };
            match identity_resolution_contents
                .try_match::<P>(identity_resolution_material.as_raw_resolution_material())
            {
                None => {
                    // Try again with another credential
                    i += 1;
                    continue;
                }
                Some(identity_match) => {
                    // The identity matched, so now we need to more closely scrutinize
                    // the provided ciphertext. Try to decrypt and parse the section.
                    let deserialization_result = match &section.ciphertext_section {
                        CiphertextSection::SignatureEncryptedIdentity(c) => c
                            .try_deserialize(
                                identity_match,
                                &crypto_material.signed_verification_material::<P>(),
                            )
                            .map_err(SectionDeserializeError::from),
                        CiphertextSection::MicEncryptedIdentity(c) => c
                            .try_deserialize(
                                identity_match,
                                &crypto_material.unsigned_verification_material::<P>(),
                            )
                            .map_err(SectionDeserializeError::from),
                    };
                    match deserialization_result {
                        Ok(s) => {
                            self.deserialized_sections.push((
                                *section_idx,
                                V1DeserializedSection::Decrypted(WithMatchedCredential::new(
                                    cred.matched(),
                                    s,
                                )),
                            ));
                        }
                        Err(e) => match e {
                            SectionDeserializeError::IncorrectCredential => {
                                // keep it around to try with another credential
                                i += 1;
                                continue;
                            }
                            SectionDeserializeError::ParseError => {
                                // the credential worked, but the section itself was bogus
                                self.malformed_sections_count += 1;
                            }
                        },
                    }
                    // By default, if we have an identity match, assume that decrypting the section worked,
                    // or that the section was somehow invalid.
                    // We don't care about maintaining order, so use O(1) remove
                    self.encrypted_sections.swap_remove(i);
                    // don't advance i -- it now points to a new element
                }
            }
        }
    }

    /// Packages the current state of the deserialization process into a
    /// `V1AdvContents` representing a fully-deserialized V1 advertisement.
    ///
    /// This method should only be called after all sections were either successfully
    /// decrypted or have had all relevant credentials checked against
    /// them without obtaining a successful identity-match and/or subsequent
    /// cryptographic verification of the section contents.
    fn finished_with_decryption_attempts(mut self) -> V1AdvContents<'a, M> {
        // Invalid sections = malformed sections + number of encrypted sections
        // which we could not manage to decrypt with any of our credentials
        let invalid_sections_count = self.malformed_sections_count + self.encrypted_sections.len();

        // Put the deserialized sections back into the original ordering for
        // the returned `V1AdvContents`
        self.deserialized_sections.sort_by_key(|(idx, _section)| *idx);
        let ordered_sections = self.deserialized_sections.into_iter().map(|(_idx, s)| s).collect();
        V1AdvContents::new(ordered_sections, invalid_sections_count)
    }
}

/// Deserialize and decrypt the contents of a v1 adv after the version header
fn deser_decrypt_v1<'s, C, S, P>(
    cred_source: &'s S,
    remaining: &'s [u8],
    header: V1Header,
) -> Result<V1AdvertisementContents<'s, C>, AdvDeserializationError>
where
    C: V1Credential,
    S: CredentialSource<C>,
    P: CryptoProvider,
{
    let mut sections_in_processing =
        SectionsInProcessing::from_advertisement_contents::<P>(header, remaining)?;

    // Hot loop
    // We assume that iterating credentials is more expensive than iterating sections
    for cred in cred_source.iter() {
        sections_in_processing.try_decrypt_with_credential::<C, P>(cred);
        if sections_in_processing.resolved_all_identities() {
            // No need to consider the other credentials
            break;
        }
    }
    Ok(sections_in_processing.finished_with_decryption_attempts())
}

type V0AdvertisementContents<'s, C> = V0AdvContents<'s, MatchedCredFromCred<'s, C>>;

/// Deserialize and decrypt the contents of a v0 adv after the version header
fn deser_decrypt_v0<'s, C, S, P>(
    cred_source: &'s S,
    remaining: &[u8],
) -> Result<V0AdvertisementContents<'s, C>, AdvDeserializationError>
where
    C: V0Credential,
    S: CredentialSource<C>,
    P: CryptoProvider,
{
    let contents = legacy::deserialize::deserialize_adv_contents::<P>(remaining)?;
    return match contents {
        IntermediateAdvContents::Plaintext(p) => Ok(V0AdvContents::Plaintext(p)),
        IntermediateAdvContents::Ciphertext(c) => {
            for cred in cred_source.iter() {
                let cm = cred.crypto_material();
                let ldt = cm.ldt_adv_cipher::<P>();
                match c.try_decrypt(&ldt) {
                    Ok(c) => {
                        return Ok(V0AdvContents::Decrypted(WithMatchedCredential::new(
                            cred.matched(),
                            c,
                        )))
                    }
                    Err(e) => match e {
                        DecryptError::DecryptOrVerifyError => continue,
                        DecryptError::DeserializeError(e) => {
                            return Err(e.into());
                        }
                    },
                }
            }
            Ok(V0AdvContents::NoMatchingCredentials)
        }
    };
}
/// Parse a NP advertisement header.
///
/// This can be used on all versions of advertisements since it's the header that determines the
/// version.
///
/// Returns a `nom::IResult` with the parsed header and the remaining bytes of the advertisement.
fn parse_adv_header(adv: &[u8]) -> nom::IResult<&[u8], AdvHeader> {
    // header bits: VVVxxxxx
    let (remaining, (header_byte, version, _low_bits)) = combinator::verify(
        // splitting a byte at a bit boundary to take lower 5 bits
        combinator::map(number::complete::u8, |byte| (byte, byte >> 5, byte & 0x1F)),
        |&(_header_byte, version, low_bits)| match version {
            // reserved bits, for any version, must be zero
            PROTOCOL_VERSION_LEGACY | PROTOCOL_VERSION_EXTENDED => low_bits == 0,
            _ => false,
        },
    )(adv)?;
    match version {
        PROTOCOL_VERSION_LEGACY => Ok((remaining, AdvHeader::V0)),
        PROTOCOL_VERSION_EXTENDED => Ok((remaining, AdvHeader::V1(V1Header { header_byte }))),
        _ => unreachable!(),
    }
}
#[derive(Debug, PartialEq, Eq, Clone)]
pub(crate) enum AdvHeader {
    V0,
    V1(V1Header),
}
/// An NP advertisement with its header parsed.
#[derive(Debug, PartialEq, Eq)]
pub enum DeserializedAdvertisement<'m, M: MatchedCredential<'m>> {
    /// V0 header has all reserved bits, so there is no data to represent other than the version
    /// itself.
    V0(V0AdvContents<'m, M>),
    /// V1 advertisement
    V1(V1AdvContents<'m, M>),
}
/// The contents of a deserialized and decrypted V1 advertisement.
#[derive(Debug, PartialEq, Eq)]
pub struct V1AdvContents<'m, M: MatchedCredential<'m>> {
    sections: Vec<V1DeserializedSection<'m, M>>,
    invalid_sections: usize,
}
impl<'m, M: MatchedCredential<'m>> V1AdvContents<'m, M> {
    fn new(sections: Vec<V1DeserializedSection<'m, M>>, invalid_sections: usize) -> Self {
        Self { sections, invalid_sections }
    }
    /// Destructures this V1 advertisement into just the sections
    /// which could be successfully deserialized and decrypted
    pub fn into_valid_sections(self) -> Vec<V1DeserializedSection<'m, M>> {
        self.sections
    }
    /// The sections that could be successfully deserialized and decrypted
    pub fn sections(&self) -> impl Iterator<Item = &V1DeserializedSection<M>> {
        self.sections.iter()
    }
    /// The number of sections that could not be parsed or decrypted.
    pub fn invalid_sections_count(&self) -> usize {
        self.invalid_sections
    }
}
/// Advertisement content that was either already plaintext or has been decrypted.
#[derive(Debug, PartialEq, Eq)]
pub enum V0AdvContents<'m, M: MatchedCredential<'m>> {
    /// Contents of an originally plaintext advertisement
    Plaintext(PlaintextAdvContents),
    /// Contents that was ciphertext in the original advertisement, and has been decrypted
    /// with the credential in the [MatchedCredential]
    Decrypted(WithMatchedCredential<'m, M, DecryptedAdvContents>),
    /// The advertisement was encrypted, but no credentials matched
    NoMatchingCredentials,
}
/// Advertisement content that was either already plaintext or has been decrypted.
#[derive(Debug, PartialEq, Eq)]
pub enum V1DeserializedSection<'m, M: MatchedCredential<'m>> {
    /// Section that was plaintext in the original advertisement
    Plaintext(PlaintextSection),
    /// Section that was ciphertext in the original advertisement, and has been decrypted
    /// with the credential in the [MatchedCredential]
    Decrypted(WithMatchedCredential<'m, M, DecryptedSection>),
}
impl<'m, M> Section for V1DeserializedSection<'m, M>
where
    M: MatchedCredential<'m>,
{
    type Iterator<'d>  = DataElements<'d> where Self: 'd;
    fn data_elements(&'_ self) -> Self::Iterator<'_> {
        match self {
            V1DeserializedSection::Plaintext(p) => p.data_elements(),
            V1DeserializedSection::Decrypted(d) => d.contents.data_elements(),
        }
    }
}
/// Decrypted advertisement content with the [MatchedCredential] from the credential that decrypted
/// it.
#[derive(Debug, PartialEq, Eq)]
pub struct WithMatchedCredential<'m, M: MatchedCredential<'m>, T> {
    matched: M,
    contents: T,
    // the compiler sees 'm as unused
    marker: marker::PhantomData<&'m ()>,
}
impl<'m, M: MatchedCredential<'m>, T> WithMatchedCredential<'m, M, T> {
    fn new(matched: M, contents: T) -> Self {
        Self { matched, contents, marker: marker::PhantomData }
    }
    /// Credential data for the credential that decrypted the content.
    pub fn matched_credential(&self) -> &M {
        &self.matched
    }
    /// The decrypted advertisement content.
    pub fn contents(&self) -> &T {
        &self.contents
    }
}
/// Data in a V1 advertisement header.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub(crate) struct V1Header {
    header_byte: u8,
}
const PROTOCOL_VERSION_LEGACY: u8 = 0;
const PROTOCOL_VERSION_EXTENDED: u8 = 1;

/// Errors that can occur during advertisement deserialization.
#[derive(PartialEq)]
pub enum AdvDeserializationError {
    /// The advertisement header could not be parsed
    HeaderParseError,
    /// The advertisement content could not be parsed
    ParseError {
        /// Potentially hazardous details about deserialization errors. Read the documentation for
        /// [AdvDeserializationErrorDetailsHazmat] before using this field.
        details_hazmat: AdvDeserializationErrorDetailsHazmat,
    },
}

impl Debug for AdvDeserializationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            AdvDeserializationError::HeaderParseError => write!(f, "HeaderParseError"),
            AdvDeserializationError::ParseError { .. } => write!(f, "ParseError"),
        }
    }
}

/// Potentially hazardous details about deserialization errors. These error information can
/// potentially expose side-channel information about the plaintext of the advertisements and/or
/// the keys used to decrypt them. For any place that you avoid exposing the keys directly
/// (e.g. across FFIs, print to log, etc), avoid exposing these error details as well.
#[derive(PartialEq)]
pub enum AdvDeserializationErrorDetailsHazmat {
    /// Parsing the overall advertisement or DE structure failed
    AdvertisementDeserializeError,
    /// Deserializing an individual DE from its DE contents failed
    V0DataElementDeserializeError(DataElementDeserializeError),
    /// Must not have any other top level data elements if there is an encrypted identity DE
    TooManyTopLevelDataElements,
    /// Must not have an identity DE inside an identity DE
    InvalidDataElementHierarchy,
    /// Must have an identity DE
    MissingIdentity,
}

impl From<AdvDeserializeError> for AdvDeserializationError {
    fn from(err: AdvDeserializeError) -> Self {
        match err {
            AdvDeserializeError::AdvertisementDeserializeError => {
                AdvDeserializationError::ParseError {
                    details_hazmat:
                        AdvDeserializationErrorDetailsHazmat::AdvertisementDeserializeError,
                }
            }
            AdvDeserializeError::DataElementDeserializeError(e) => {
                AdvDeserializationError::ParseError {
                    details_hazmat:
                        AdvDeserializationErrorDetailsHazmat::V0DataElementDeserializeError(e),
                }
            }
            AdvDeserializeError::TooManyTopLevelDataElements => {
                AdvDeserializationError::ParseError {
                    details_hazmat:
                        AdvDeserializationErrorDetailsHazmat::TooManyTopLevelDataElements,
                }
            }
            AdvDeserializeError::InvalidDataElementHierarchy => {
                AdvDeserializationError::ParseError {
                    details_hazmat:
                        AdvDeserializationErrorDetailsHazmat::InvalidDataElementHierarchy,
                }
            }
            AdvDeserializeError::MissingIdentity => AdvDeserializationError::ParseError {
                details_hazmat: AdvDeserializationErrorDetailsHazmat::MissingIdentity,
            },
        }
    }
}

/// DE length is out of range (e.g. > 4 bits for encoded V0, > max DE size for actual V0, >127 for
/// V1) or invalid for the relevant DE type.
#[derive(Debug, PartialEq, Eq)]
pub struct DeLengthOutOfRange;

/// The identity mode for a deserialized plaintext section or advertisement.
#[derive(PartialEq, Eq, Debug, Clone, Copy)]
pub enum PlaintextIdentityMode {
    /// A "Public Identity" DE was present in the section
    Public,
}

/// A "public identity" -- a nonspecific "empty identity".
///
/// Used when serializing V0 advertisements or V1 sections.
#[derive(Default, Debug)]
pub struct PublicIdentity {}
