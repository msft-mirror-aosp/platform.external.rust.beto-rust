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
    objects::{JClass, JObject},
    sys::{jint, jlong},
    JNIEnv,
};

use crate::class::{v1_data_element::Generic, DeserializedV1Section};
use handle_map::{Handle, HandleLike};
use np_ffi_core::deserialize::v1::{
    GetV1DEResult, GetV1SectionResult, LegibleV1Sections as LegibleSectionsHandle, V1DataElement,
};
use pourover::{desc::ClassDesc, jni_method};

static LEGIBLE_V1_SECTIONS: ClassDesc =
    ClassDesc::new("com/google/android/nearby/presence/rust/LegibleV1Sections");

/// Rust representation for `class LegibleV1Sections`.
#[repr(transparent)]
pub struct LegibleV1Sections<Obj>(pub Obj);

impl<'local> LegibleV1Sections<JObject<'local>> {
    /// Create new Java instance for the given handle. On the Java side this an `OwnedHandle` and
    /// Java will be responsible to deallocating it.
    pub fn construct(
        env: &mut JNIEnv<'local>,
        handle: LegibleSectionsHandle,
    ) -> jni::errors::Result<Self> {
        let handle_id = handle.get_as_handle().get_id() as jlong;

        pourover::call_constructor!(env, &LEGIBLE_V1_SECTIONS, "(J)V", handle_id,).map(Self)
    }
}

impl<'local, Obj: AsRef<JObject<'local>>> LegibleV1Sections<Obj> {
    /// Get a reference to the inner `jni` crate [`JObject`].
    pub fn as_obj(&self) -> &JObject<'local> {
        self.0.as_ref()
    }

    /// Get the Rust [`HandleLike`] representation from this Java object.
    pub fn as_rust_handle<'env>(
        &self,
        env: &mut JNIEnv<'env>,
    ) -> jni::errors::Result<LegibleSectionsHandle> {
        let handle_id = self.get_handle_id(env)?;
        Ok(LegibleSectionsHandle::from_handle(Handle::from_id(handle_id as u64)))
    }

    /// Get `long handleId` from the Java object
    fn get_handle_id<'env_local>(
        &self,
        env: &mut JNIEnv<'env_local>,
    ) -> jni::errors::Result<jlong> {
        use jni::signature::{Primitive, ReturnType};
        use pourover::desc::FieldDesc;

        static HANDLE_ID_FIELD: FieldDesc = LEGIBLE_V1_SECTIONS.field("handleId", "J");

        env.get_field_unchecked(
            self.0.as_ref(),
            &HANDLE_ID_FIELD,
            ReturnType::Primitive(Primitive::Long),
        )
        .and_then(|val| val.j())
    }
}

// Native method implementations

#[jni_method(package = "com.google.android.nearby.presence.rust", class = "LegibleV1Sections")]
extern "system" fn nativeGetSection<'local>(
    mut env: JNIEnv<'local>,
    legible_sections_obj: LegibleV1Sections<JObject<'local>>,
    index: jint,
) -> JObject<'local> {
    let Ok(legible_sections) = legible_sections_obj.as_rust_handle(&mut env) else {
        return JObject::null();
    };
    let Ok(index) = u8::try_from(index) else {
        return JObject::null();
    };

    let GetV1SectionResult::Success(section) = legible_sections.get_section(index) else {
        return JObject::null();
    };

    match DeserializedV1Section::construct(
        &mut env,
        legible_sections_obj,
        index,
        section.num_des(),
        section.identity_kind(),
    ) {
        Ok(section) => section.0,
        Err(_) => JObject::null(),
    }
}

#[jni_method(package = "com.google.android.nearby.presence.rust", class = "LegibleV1Sections")]
extern "system" fn nativeGetSectionDataElement<'local>(
    mut env: JNIEnv<'local>,
    legible_sections_obj: LegibleV1Sections<JObject<'local>>,
    section_index: jint,
    de_index: jint,
) -> JObject<'local> {
    let Ok(legible_sections) = legible_sections_obj.as_rust_handle(&mut env) else {
        return JObject::null();
    };
    let Ok(section_index) = u8::try_from(section_index) else {
        return JObject::null();
    };
    let Ok(de_index) = u8::try_from(de_index) else {
        return JObject::null();
    };

    let GetV1DEResult::Success(de) = legible_sections.get_section_de(section_index, de_index)
    else {
        return JObject::null();
    };

    let ret = match de {
        V1DataElement::Generic(generic) => {
            let de_type = jlong::from(generic.de_type().to_u32());
            let Some(slice) = generic.payload.as_slice() else {
                return JObject::null();
            };

            env.byte_array_from_slice(slice)
                .and_then(|data| Generic::construct(&mut env, de_type, data))
                .map(|obj| obj.0)
        }
    };

    ret.unwrap_or_else(|_err| JObject::null())
}

#[jni_method(package = "com.google.android.nearby.presence.rust", class = "LegibleV1Sections")]
extern "system" fn deallocate<'local>(
    _env: JNIEnv<'local>,
    _cls: JClass<'local>,
    handle_id: jlong,
) {
    // Swallow errors here since there's nothing meaningful to do.
    let _ = LegibleSectionsHandle::from_handle(Handle::from_id(handle_id as u64)).deallocate();
}
