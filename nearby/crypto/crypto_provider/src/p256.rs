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

extern crate alloc;

use crate::elliptic_curve::{Curve, EcdhProvider, PublicKey};
use alloc::vec::Vec;
use core::fmt::Debug;

/// Marker type for P256 implementation. This is used by EcdhProvider as its type parameter.
#[derive(Debug, PartialEq, Eq)]
pub enum P256 {}
impl Curve for P256 {}

/// Trait for a NIST-P256 public key.
pub trait P256PublicKey: Sized + PartialEq + Debug {
    /// The error type associated with this implementation.
    type Error: Debug;

    /// Creates a public key from the given sec1-encoded bytes, as described in section 2.3.4 of
    /// the SECG SEC 1 ("Elliptic Curve Cryptography") standard.
    fn from_sec1_bytes(bytes: &[u8]) -> Result<Self, Self::Error>;

    /// Serializes this key into sec1-encoded bytes, as described in section 2.3.3 of the SECG SEC 1
    /// ("Elliptic Curve Cryptography") standard. Note that it is not necessarily true that
    /// `from_sec1_bytes(bytes)?.to_sec1_bytes() == bytes` because of point compression. (But it is
    /// always true that `from_sec1_bytes(key.to_sec1_bytes())? == key`).
    fn to_sec1_bytes(&self) -> Vec<u8>;

    /// Converts this public key's x and y coordinates on the elliptic curve to big endian octet
    /// strings.
    fn to_affine_coordinates(&self) -> Result<([u8; 32], [u8; 32]), Self::Error>;

    /// Creates a public key from the X and Y coordinates on the elliptic curve.
    fn from_affine_coordinates(x: &[u8; 32], y: &[u8; 32]) -> Result<Self, Self::Error>;
}

impl<P: P256PublicKey> PublicKey<P256> for P {
    type Error = <Self as P256PublicKey>::Error;

    fn from_bytes(bytes: &[u8]) -> Result<Self, Self::Error> {
        Self::from_sec1_bytes(bytes)
    }

    fn to_bytes(&self) -> Vec<u8> {
        Self::to_sec1_bytes(self)
    }
}

/// Equivalent to EcdhProvider<P256, PublicKey: P256PublicKey> if associated type bounds are
/// supported.
pub trait P256EcdhProvider:
    EcdhProvider<P256, PublicKey = <Self as P256EcdhProvider>::PublicKey>
{
    /// Same as EcdhProvider::PublicKey.
    type PublicKey: P256PublicKey;
}

impl<E> P256EcdhProvider for E
where
    E: EcdhProvider<P256>,
    E::PublicKey: P256PublicKey,
{
    type PublicKey = E::PublicKey;
}

/// Utilities for testing. Implementations can use the test cases and functions provided to test
/// their implementation.
#[cfg(feature = "testing")]
pub mod testing {
    extern crate std;
    use super::{P256PublicKey, P256};
    pub use crate::testing::prelude::*;
    use crate::{
        elliptic_curve::{EcdhProvider, EphemeralSecret, EphemeralSecretForTesting, PublicKey},
        testing::TestError,
    };
    use core::marker::PhantomData;
    use hex_literal::hex;
    use rstest_reuse::template;

    /// An ECDH provider that provides associated types for testing purposes. This can be mostly
    /// considered "aliases" for the otherwise long fully-qualified associated types.
    pub trait EcdhProviderForP256Test {
        /// The ECDH Provider that is "wrapped" by this type.
        type EcdhProvider: EcdhProvider<
            P256,
            PublicKey = <Self as EcdhProviderForP256Test>::PublicKey,
            EphemeralSecret = <Self as EcdhProviderForP256Test>::EphemeralSecret,
            SharedSecret = <Self as EcdhProviderForP256Test>::SharedSecret,
        >;
        /// The public key type.
        type PublicKey: P256PublicKey;
        /// The ephemeral secret type.
        type EphemeralSecret: EphemeralSecretForTesting<P256, Impl = Self::EcdhProvider>;
        /// The shared secret type.
        type SharedSecret: Into<[u8; 32]>;
    }

    impl<E> EcdhProviderForP256Test for E
    where
        E: EcdhProvider<P256>,
        E::PublicKey: P256PublicKey,
        E::EphemeralSecret: EphemeralSecretForTesting<P256>,
    {
        type EcdhProvider = E;
        type PublicKey = E::PublicKey;
        type EphemeralSecret = E::EphemeralSecret;
        type SharedSecret = E::SharedSecret;
    }

    /// Test for P256PublicKey::to_bytes
    pub fn to_bytes_test<E: EcdhProviderForP256Test>(_: PhantomData<E>) {
        let sec1_bytes = hex!(
            "04756c07ba5b596fa96c9099e6619dc62deac4297a8fc1d803d74dc5caa9197c09f0b6da270d2a58a06022
             8bbe76c6dc1643088107636deff8aa79e8002a157b92"
        );
        let key = E::PublicKey::from_sec1_bytes(&sec1_bytes).unwrap();
        let sec1_bytes_compressed =
            hex!("02756c07ba5b596fa96c9099e6619dc62deac4297a8fc1d803d74dc5caa9197c09");
        assert_eq!(sec1_bytes_compressed.to_vec(), key.to_bytes());
    }

    /// Random test for P256PublicKey::to_bytes
    pub fn to_bytes_random_test<E: EcdhProviderForP256Test>(_: PhantomData<E>) {
        let mut rng = rand::thread_rng();
        for _ in 1..100 {
            let public_key_bytes = E::EphemeralSecret::generate_random(&mut rng).public_key_bytes();
            let public_key = E::PublicKey::from_bytes(&public_key_bytes).unwrap();
            assert_eq!(
                E::PublicKey::from_bytes(&public_key.to_bytes()).unwrap(),
                public_key,
                "from_bytes should return the same key for `{public_key_bytes:?}`",
            );
        }
    }

    /// Test for P256PublicKey::from_affine_coordinates
    pub fn from_affine_coordinates_test<E: EcdhProviderForP256Test>(_: PhantomData<E>) {
        // https://www.secg.org/sec1-v2.pdf, section 2.3.3
        let x = hex!("756c07ba5b596fa96c9099e6619dc62deac4297a8fc1d803d74dc5caa9197c09");
        let y = hex!("f0b6da270d2a58a060228bbe76c6dc1643088107636deff8aa79e8002a157b92");
        let sec1 = hex!(
            "04756c07ba5b596fa96c9099e6619dc62deac4297a8fc1d803d74dc5caa9197c09f0b6da270d2a58a06022
             8bbe76c6dc1643088107636deff8aa79e8002a157b92"
        );
        let expected_key = E::PublicKey::from_sec1_bytes(&sec1).unwrap();
        assert!(
            E::PublicKey::from_affine_coordinates(&x, &y).unwrap() == expected_key,
            "Public key does not match"
        );
    }

    /// Test for P256PublicKey::from_affine_coordinates
    pub fn from_affine_coordinates_not_on_curve_test<E: EcdhProviderForP256Test>(
        _: PhantomData<E>,
    ) {
        // (Invalid) coordinate from wycheproof ecdh_secp256r1_ecpoint_test.json, tcId 193
        let x = hex!("0000000000000000000000000000000000000000000000000000000000000000");
        let y = hex!("0000000000000000000000000000000000000000000000000000000000000000");
        let result = E::PublicKey::from_affine_coordinates(&x, &y);
        assert!(
            result.is_err(),
            "Creating public key from invalid affine coordinate should fail"
        );
    }

    /// Test for P256PublicKey::from_sec1_bytes
    pub fn from_sec1_bytes_not_on_curve_test<E: EcdhProviderForP256Test>(_: PhantomData<E>) {
        // (Invalid) sec1 encoding from wycheproof ecdh_secp256r1_ecpoint_test.json, tcId 193
        let sec1 = hex!(
            "04000000000000000000000000000000000000000000000000000000000000000000000000000000000000
             00000000000000000000000000000000000000000000"
        );
        let result = E::PublicKey::from_sec1_bytes(&sec1);
        assert!(
            result.is_err(),
            "Creating public key from point not on curve should fail"
        );
    }

    /// Test for P256PublicKey::to_affine_coordinates
    pub fn public_key_to_affine_coordinates_test<E: EcdhProviderForP256Test>(_: PhantomData<E>) {
        // https://www.secg.org/sec1-v2.pdf, section 2.3.3
        let expected_x = hex!("756c07ba5b596fa96c9099e6619dc62deac4297a8fc1d803d74dc5caa9197c09");
        let expected_y = hex!("f0b6da270d2a58a060228bbe76c6dc1643088107636deff8aa79e8002a157b92");
        let sec1 = hex!(
            "04756c07ba5b596fa96c9099e6619dc62deac4297a8fc1d803d74dc5caa9197c09f0b6da270d2a58a06022
             8bbe76c6dc1643088107636deff8aa79e8002a157b92"
        );
        let public_key = E::PublicKey::from_sec1_bytes(&sec1).unwrap();
        let (actual_x, actual_y) = public_key.to_affine_coordinates().unwrap();
        assert_eq!(actual_x, expected_x);
        assert_eq!(actual_y, expected_y);
    }

    /// Test for P256 Diffie-Hellman key exchange.
    pub fn p256_ecdh_test<E: EcdhProviderForP256Test>(_: PhantomData<E>) {
        // From wycheproof ecdh_secp256r1_ecpoint_test.json, tcId 1
        // http://google3/third_party/wycheproof/testvectors/ecdh_secp256r1_ecpoint_test.json;l=22;rcl=375894991
        // sec1 public key manually extracted from the ASN encoded test data
        let public_key_sec1 = hex!(
            "0462d5bd3372af75fe85a040715d0f502428e07046868b0bfdfa61d731afe44f
            26ac333a93a9e70a81cd5a95b5bf8d13990eb741c8c38872b4a07d275a014e30cf"
        );
        let private = hex!("0612465c89a023ab17855b0a6bcebfd3febb53aef84138647b5352e02c10c346");
        let expected_shared_secret =
            hex!("53020d908b0219328b658b525f26780e3ae12bcd952bb25a93bc0895e1714285");
        let actual_shared_secret = p256_ecdh_test_impl::<E>(&public_key_sec1, &private).unwrap();
        assert_eq!(actual_shared_secret.into(), expected_shared_secret);
    }

    fn p256_ecdh_test_impl<E: EcdhProviderForP256Test>(
        public_key_sec1: &[u8],
        private: &[u8; 32],
    ) -> Result<E::SharedSecret, TestError> {
        let public_key = E::PublicKey::from_sec1_bytes(public_key_sec1).map_err(TestError::new)?;
        let ephemeral_secret = E::EphemeralSecret::from_private_components(private, &public_key)
            .map_err(TestError::new)?;
        ephemeral_secret
            .diffie_hellman(&public_key)
            .map_err(TestError::new)
    }

    /// Wycheproof test for P256 Diffie-Hellman.
    pub fn wycheproof_p256_test<E: EcdhProviderForP256Test>(_: PhantomData<E>) {
        // Test cases from https://github.com/randombit/wycheproof-rs/blob/master/src/data/ecdh_secp256r1_ecpoint_test.json
        let test_set =
            wycheproof::ecdh::TestSet::load(wycheproof::ecdh::TestName::EcdhSecp256r1Ecpoint)
                .unwrap();
        for test_group in test_set.test_groups {
            for test in test_group.tests {
                if test.private_key.len() != 32 {
                    // Some Wycheproof test cases have private key length that are not 32 bytes, but
                    // the RustCrypto implementation doesn't support that (it always take 32 bytes
                    // from the given RNG when generating a new key).
                    continue;
                };
                std::println!("Testing {}", test.tc_id);
                let result = p256_ecdh_test_impl::<E>(
                    &test.public_key,
                    &test
                        .private_key
                        .try_into()
                        .expect("Private key should be 32 bytes long"),
                );
                match test.result {
                    wycheproof::TestResult::Valid => {
                        let shared_secret =
                            result.unwrap_or_else(|_| panic!("Test {} should succeed", test.tc_id));
                        assert_eq!(test.shared_secret, shared_secret.into());
                    }
                    wycheproof::TestResult::Invalid => {
                        result
                            .err()
                            .unwrap_or_else(|| panic!("Test {} should fail", test.tc_id));
                    }
                    wycheproof::TestResult::Acceptable => {
                        if let Ok(shared_secret) = result {
                            assert_eq!(test.shared_secret, shared_secret.into());
                        }
                        // Test passes if `result` is an error because this test is "acceptable"
                    }
                }
            }
        }
    }

    /// Generates the test cases to validate the P256 implementation.
    /// For example, to test `MyCryptoProvider`:
    ///
    /// ```
    /// use crypto_provider::p256::testing::*;
    ///
    /// mod tests {
    ///     #[apply(p256_test_cases)]
    ///     fn p256_tests(testcase: CryptoProviderTestCase<MyCryptoProvider> {
    ///         testcase(PhantomData::<MyCryptoProvider>);
    ///     }
    /// }
    /// ```
    #[template]
    #[export]
    #[rstest]
    #[case::to_bytes(to_bytes_test)]
    #[case::to_bytes_random(to_bytes_random_test)]
    #[case::from_sec1_bytes_not_on_curve(from_sec1_bytes_not_on_curve_test)]
    #[case::from_affine_coordinates(from_affine_coordinates_test)]
    #[case::from_affine_coordinates_not_on_curve(from_affine_coordinates_not_on_curve_test)]
    #[case::public_key_to_affine_coordinates(public_key_to_affine_coordinates_test)]
    #[case::p256_ecdh(p256_ecdh_test)]
    #[case::wycheproof_p256(wycheproof_p256_test)]
    fn p256_test_cases<C: CryptoProvider>(#[case] testcase: CryptoProviderTestCase<C>) {}
}
