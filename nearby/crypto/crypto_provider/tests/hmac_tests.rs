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

use core::cmp::min;
use crypto_provider::CryptoProvider;
use crypto_provider_openssl::Openssl;
use crypto_provider_rustcrypto::RustCrypto;
use wycheproof::TestResult;

#[test]
fn hmac_sha_256_wycheproof_test_vectors_rustcrypto() {
    run_hmac_test_vectors::<32, <RustCrypto as CryptoProvider>::HmacSha256>(HashAlg::Sha256)
}

#[test]
fn hmac_sha_256_wycheproof_test_vectors_openssl() {
    run_hmac_test_vectors::<32, <Openssl as CryptoProvider>::HmacSha256>(HashAlg::Sha256)
}

#[test]
fn hmac_sha_512_wycheproof_test_vectors_rustcrypto() {
    run_hmac_test_vectors::<64, <RustCrypto as CryptoProvider>::HmacSha512>(HashAlg::Sha512)
}

#[test]
fn hmac_sha_512_wycheproof_test_vectors_openssl() {
    run_hmac_test_vectors::<64, <Openssl as CryptoProvider>::HmacSha512>(HashAlg::Sha512)
}

enum HashAlg {
    Sha256,
    Sha512,
}

// Tests vectors from Project Wycheproof:
// https://github.com/google/wycheproof
fn run_hmac_test_vectors<const N: usize, H: crypto_provider::hmac::Hmac<N>>(hash: HashAlg) {
    let test_name = match hash {
        HashAlg::Sha256 => wycheproof::mac::TestName::HmacSha256,
        HashAlg::Sha512 => wycheproof::mac::TestName::HmacSha512,
    };
    let test_set =
        wycheproof::mac::TestSet::load(test_name).expect("should be able to load test set");

    for test_group in test_set.test_groups {
        for test in test_group.tests {
            let key = test.key;
            let msg = test.msg;
            let tag = test.tag;
            let tc_id = test.tc_id;
            let valid = match test.result {
                TestResult::Valid | TestResult::Acceptable => true,
                TestResult::Invalid => false,
            };

            if let Some(desc) =
                run_test::<N, H>(key.as_slice(), msg.as_slice(), tag.as_slice(), valid)
            {
                panic!(
                    "\n\
                         Failed test {tc_id}: {desc}\n\
                         key:\t{key:?}\n\
                         msg:\t{msg:?}\n\
                         tag:\t{tag:?}\n",
                );
            }
        }
    }
}

fn run_test<const N: usize, H: crypto_provider::hmac::Hmac<N>>(
    key: &[u8],
    input: &[u8],
    tag: &[u8],
    valid_data: bool,
) -> Option<&'static str> {
    let mut mac = H::new_from_slice(key).unwrap();
    mac.update(input);
    let result = mac.finalize();
    let n = tag.len();
    let result_bytes = &result[..n];

    if valid_data {
        if result_bytes != tag {
            return Some("whole message");
        }
    } else {
        return if result_bytes == tag {
            Some("invalid should not match")
        } else {
            None
        };
    }

    // test reading different chunk sizes
    for chunk_size in 1..min(64, input.len()) {
        let mut mac = H::new_from_slice(key).unwrap();
        for chunk in input.chunks(chunk_size) {
            mac.update(chunk);
        }
        let res = mac.verify_truncated_left(tag);
        if res.is_err() {
            return Some("chunked message");
        }
    }

    None
}
