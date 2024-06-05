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

use jni::{
    signature::{JavaType, Primitive},
    sys::jint,
    JNIEnv,
};
use np_ffi_core::deserialize::{v0::DeserializedV0IdentityKind, v1::DeserializedV1IdentityKind};
use pourover::desc::{ClassDesc, StaticFieldDesc};
use std::sync::RwLock;

use crate::class::V0AdvertisementError;

static IDENTITY_KIND_CLASS: ClassDesc =
    ClassDesc::new("com/google/android/nearby/presence/rust/IdentityKind");

/// Rust representation of `@IdentityKind`. These are `jints` on the Java side, so this type can't
/// be instantiated.
pub enum IdentityKind {}

impl IdentityKind {
    /// Fetch the `NO_MATCHING_CREDENTIALS` constant
    pub fn no_matching_credentials<'local>(env: &mut JNIEnv<'local>) -> jni::errors::Result<jint> {
        static NO_MATCHING_CREDENTIALS: StaticFieldDesc =
            IDENTITY_KIND_CLASS.static_field("NO_MATCHING_CREDENTIALS", "I");
        static VALUE: RwLock<Option<jint>> = RwLock::new(None);
        Self::lookup_static_value(env, &NO_MATCHING_CREDENTIALS, &VALUE)
    }

    /// Fetch the `PLAINTEXT` constant
    pub fn plaintext<'local>(env: &mut JNIEnv<'local>) -> jni::errors::Result<jint> {
        static PLAINTEXT: StaticFieldDesc = IDENTITY_KIND_CLASS.static_field("PLAINTEXT", "I");
        static VALUE: RwLock<Option<jint>> = RwLock::new(None);
        Self::lookup_static_value(env, &PLAINTEXT, &VALUE)
    }

    /// Fetch the `DECRYPTED` constant
    pub fn decrypted<'local>(env: &mut JNIEnv<'local>) -> jni::errors::Result<jint> {
        static DECRYPTED: StaticFieldDesc = IDENTITY_KIND_CLASS.static_field("DECRYPTED", "I");
        static VALUE: RwLock<Option<jint>> = RwLock::new(None);
        Self::lookup_static_value(env, &DECRYPTED, &VALUE)
    }

    /// Look up the given field and cache it in the given cache. The lookup will only be performed
    /// once if successful. This uses `RwLock` instead of `OnceCell` since the fallible `OnceCell`
    /// APIs are nightly only.
    fn lookup_static_value<'local>(
        env: &mut JNIEnv<'local>,
        field: &StaticFieldDesc,
        cache: &RwLock<Option<jint>>,
    ) -> jni::errors::Result<jint> {
        // Read from cache
        if let Some(value) = *cache.read().unwrap_or_else(|poison| poison.into_inner()) {
            return Ok(value);
        }

        // Get exclusive access to the cache for the lookup
        let mut guard = cache.write().unwrap_or_else(|poison| poison.into_inner());

        // In case of races, only lookup the value once
        if let Some(value) = *guard {
            return Ok(value);
        }

        let value = env
            .get_static_field_unchecked(field.cls(), field, JavaType::Primitive(Primitive::Int))
            .and_then(|ret| ret.i())?;

        *guard = Some(value);

        Ok(value)
    }

    /// Get the Java representation of [`V0AdvertisementError`].
    pub fn error_for_v0<'local>(
        env: &mut JNIEnv<'local>,
        identity: V0AdvertisementError,
    ) -> jni::errors::Result<jint> {
        match identity {
            V0AdvertisementError::NoMatchingCredentials => Self::no_matching_credentials(env),
        }
    }

    /// Get the Java representation of [`DeserializedV0IdentityKind`].
    pub fn value_for_v0<'local>(
        env: &mut JNIEnv<'local>,
        identity: DeserializedV0IdentityKind,
    ) -> jni::errors::Result<jint> {
        match identity {
            DeserializedV0IdentityKind::Plaintext => Self::plaintext(env),
            DeserializedV0IdentityKind::Decrypted => Self::decrypted(env),
        }
    }

    /// Get the Java representation of [`DeserializedV1IdentityKind`].
    pub fn value_for_v1<'local>(
        env: &mut JNIEnv<'local>,
        identity: DeserializedV1IdentityKind,
    ) -> jni::errors::Result<jint> {
        match identity {
            DeserializedV1IdentityKind::Plaintext => Self::plaintext(env),
            DeserializedV1IdentityKind::Decrypted => Self::decrypted(env),
        }
    }
}
