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
#![allow(clippy::unwrap_used)]

use crate::NpLdtAesBlock;
use zerocopy::LayoutVerified;

#[test]
fn test_platform_alignment() {
    let mut test_block = [0u8; 16];
    assert_eq!(
        NpLdtAesBlock { bytes: test_block },
        LayoutVerified::<&mut [u8], NpLdtAesBlock>::new_unaligned(test_block.as_mut_slice())
            .unwrap()
            .read()
    );
}

#[test]
fn test_invalid_platform_alignment() {
    let mut test_block = [0u8; 17];
    assert_eq!(
        None,
        LayoutVerified::<&mut [u8], NpLdtAesBlock>::new_unaligned(test_block.as_mut_slice())
    );
}
