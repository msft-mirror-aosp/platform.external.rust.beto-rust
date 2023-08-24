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

extern crate std;
use super::*;
use crate::extended::serialize::section_tests::{fill_section_builder, DummyDataElement};
use np_hkdf::v1_salt::DataElementOffset;
use std::{prelude::rust_2021::*, vec};

#[test]
fn adv_encode_no_salt() {
    let mut adv_builder = AdvBuilder::new(AdvertisementType::Plaintext);

    let mut public_identity_section_builder =
        adv_builder.section_builder(PublicSectionEncoder::default()).unwrap();
    public_identity_section_builder
        .add_de(|_| DummyDataElement { de_type: 30_u32.into(), data: vec![] })
        .unwrap();

    public_identity_section_builder.add_to_advertisement();

    assert_eq!(
        &[
            0x20, // adv header
            0x3,  // section header
            0x3,  // public identity
            0x80, 30, // de header
        ],
        adv_builder.into_advertisement().as_slice()
    )
}

#[test]
fn adding_any_allowed_section_length_always_works_for_single_section() {
    // up to section len - 1 to leave room for section header
    for section_contents_len in 0..NP_ADV_MAX_SECTION_LEN - 1 {
        let mut adv_builder = AdvBuilder::new(AdvertisementType::Plaintext);
        let mut section_builder =
            adv_builder.section_builder(PublicSectionEncoder::default()).unwrap();
        fill_section_builder(section_contents_len, &mut section_builder);

        section_builder.add_to_advertisement();

        let adv = adv_builder.into_advertisement();
        assert_eq!(
            section_contents_len + 1 + 1 + 1, // adv and section headers and identity
            adv.as_slice().len(),
            "adv: {:?}\nsection contents len: {}",
            adv.as_slice(),
            section_contents_len
        );
    }
}

#[test]
fn building_capacity_0_section_works() {
    let mut adv_builder = AdvBuilder::new(AdvertisementType::Plaintext);

    let mut section_builder = adv_builder.section_builder(PublicSectionEncoder::default()).unwrap();

    // leave room for section header and the public identity
    fill_section_builder(NP_ADV_MAX_SECTION_LEN - 2, &mut section_builder);

    assert_eq!(NP_ADV_MAX_SECTION_LEN, section_builder.section.capacity);
    assert_eq!(NP_ADV_MAX_SECTION_LEN, section_builder.section.len());

    section_builder.add_to_advertisement();

    assert_eq!(BLE_ADV_SVC_CONTENT_LEN, adv_builder.into_advertisement().as_slice().len());
}

/// A placeholder identity with a huge prefix
#[derive(Default, PartialEq, Eq, Debug)]
struct EnormousIdentity {}

impl SectionEncoder for EnormousIdentity {
    const PREFIX_LEN: usize = 200;
    const SUFFIX_LEN: usize = 0;
    const INITIAL_DE_OFFSET: DataElementOffset = DataElementOffset::ZERO;
    const ADVERTISEMENT_TYPE: AdvertisementType = AdvertisementType::Plaintext;

    fn postprocess(
        &mut self,
        _adv_header_byte: u8,
        _section_header: u8,
        _section_contents: &mut [u8],
    ) {
        panic!("should never be called, just used for its huge prefix")
    }

    type DerivedSalt = ();
    fn de_salt(&self, _de_offset: DataElementOffset) -> Self::DerivedSalt {
        panic!("should never be called, just used for its huge prefix")
    }
}
