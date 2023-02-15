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

use std::collections::HashMap;
use std::sync::mpsc::Sender;
use std::thread;

use jni::objects::{GlobalRef, JClass, JObject, JString};
use jni::sys::{jboolean, jbyteArray, jint, jlong, jobject, JNI_TRUE};
use jni::{JNIEnv, JavaVM};
use lazy_static::lazy_static;
use rand::Rng;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use spin::Mutex;

use ukey2_connections::{
    D2DConnectionContextV1, D2DHandshakeContext, DecodeError, DeserializeError, HandleMessageError,
    HandshakeError, HandshakeImplementation, InitiatorD2DHandshakeContext,
    ServerD2DHandshakeContext,
};
use ukey2_rs::{ErrorHandler, Severity};

cfg_if::cfg_if! {
    if #[cfg(feature = "rustcrypto")] {
        use crypto_provider_rustcrypto::RustCrypto as CryptoProvider;
    } else {
        use crypto_provider_openssl::Openssl as CryptoProvider;
    }
}
// Handle management

type D2DBox = Box<dyn D2DHandshakeContext>;
type ConnectionBox = Box<D2DConnectionContextV1>;

lazy_static! {
    static ref HANDLE_MAPPING: Mutex<HashMap<u64, D2DBox>> = Mutex::new(HashMap::new());
    static ref CONNECTION_HANDLE_MAPPING: Mutex<HashMap<u64, ConnectionBox>> =
        Mutex::new(HashMap::new());
    static ref RNG: Mutex<ChaCha20Rng> = Mutex::new(ChaCha20Rng::from_entropy());
}

fn generate_handle() -> u64 {
    RNG.lock().gen()
}

pub(crate) fn insert_handshake_handle(item: D2DBox) -> u64 {
    let handle = generate_handle();
    HANDLE_MAPPING.lock().insert(handle, item);
    handle
}

pub(crate) fn insert_conn_handle(item: ConnectionBox) -> u64 {
    let handle = generate_handle();
    CONNECTION_HANDLE_MAPPING.lock().insert(handle, item);
    handle
}

#[derive(Debug)]
enum JniError {
    BadHandle,
    DecodeError(DecodeError),
    HandleMessageError(HandleMessageError),
    HandshakeError(HandshakeError),
}

struct JniLogger {
    tx: Sender<LogMessage>,
}

struct LogMessage(String, Severity, String, u32);

impl JniLogger {
    fn new(jvm: JavaVM, logger: GlobalRef) -> Self {
        let (tx, rx) = std::sync::mpsc::channel::<LogMessage>();
        thread::spawn(move || {
            let attach_guard = jvm.attach_current_thread().unwrap();
            let env = *attach_guard;
            while let Ok(LogMessage(message, severity, origin_file, origin_line)) = rx.recv() {
                let message_jval = {
                    let msg_jstr: JString = env.new_string(message).unwrap();
                    msg_jstr.into()
                };
                let origin_file_jval = {
                    let origin_file_jstr: JString = env.new_string(origin_file).unwrap();
                    origin_file_jstr.into()
                };
                if !env.exception_check().unwrap_or(false) {
                    let _ = env.call_method(
                        &logger,
                        "log",
                        "(ILjava/lang/String;Ljava/lang/String;I)V",
                        &[
                            (severity as jint).into(),
                            message_jval,
                            origin_file_jval,
                            (origin_line as jint).into(),
                        ],
                    );
                }
            }
        });
        Self { tx }
    }
}

impl ErrorHandler for JniLogger {
    fn log_full_err(
        &self,
        severity: Severity,
        message: String,
        origin_file: &str,
        origin_line: u32,
    ) {
        let _unused = self.tx.send(LogMessage(
            message,
            severity,
            origin_file.to_string(),
            origin_line,
        ));
    }
}

// D2DHandshakeContext
#[no_mangle]
pub extern "system" fn Java_com_google_security_cryptauth_lib_securegcm_D2DHandshakeContext_is_1handshake_1complete(
    env: JNIEnv,
    _: JClass,
    context_handle: jlong,
) -> jboolean {
    let mut is_complete = false;
    if let Some(ctx) = HANDLE_MAPPING.lock().get(&(context_handle as u64)) {
        is_complete = ctx.is_handshake_complete();
    } else {
        env.throw_new(
            "com/google/security/cryptauth/lib/securegcm/BadHandleException",
            "",
        )
        .expect("failed to find error class");
    }
    is_complete as jboolean
}

/// # Safety
/// We get a raw jobject as the logger from the Java program, so we need to convert that to an
/// object with an explicit lifetime in order to pin it in the JVM.
#[no_mangle]
pub unsafe extern "system" fn Java_com_google_security_cryptauth_lib_securegcm_D2DHandshakeContext_create_1context(
    env: JNIEnv,
    _: JClass,
    is_client: jboolean,
    logger: jobject,
) -> jlong {
    if is_client == JNI_TRUE {
        let client_obj = Box::new(InitiatorD2DHandshakeContext::<CryptoProvider, _>::new(
            HandshakeImplementation::Weird,
            JniLogger::new(
                env.get_java_vm().unwrap(),
                env.new_global_ref(unsafe { JObject::from_raw(logger) })
                    .unwrap(),
            ),
        ));
        insert_handshake_handle(client_obj) as jlong
    } else {
        let server_obj = Box::new(ServerD2DHandshakeContext::<CryptoProvider, _>::new(
            HandshakeImplementation::Weird,
            JniLogger::new(
                env.get_java_vm().unwrap(),
                env.new_global_ref(unsafe { JObject::from_raw(logger) })
                    .unwrap(),
            ),
        ));
        insert_handshake_handle(server_obj) as jlong
    }
}

#[no_mangle]
pub extern "system" fn Java_com_google_security_cryptauth_lib_securegcm_D2DHandshakeContext_get_1next_1handshake_1message(
    env: JNIEnv,
    _: JClass,
    context_handle: jlong,
) -> jbyteArray {
    let empty_arr = env.new_byte_array(0).unwrap();
    let next_message = if let Some(ctx) = HANDLE_MAPPING.lock().get(&(context_handle as u64)) {
        ctx.get_next_handshake_message()
    } else {
        env.throw_new(
            "com/google/security/cryptauth/lib/securegcm/BadHandleException",
            "",
        )
        .expect("failed to find error class");
        None
    };
    // TODO error handling
    if let Some(message) = next_message {
        env.byte_array_from_slice(message.as_slice()).unwrap()
    } else {
        empty_arr
    }
}

#[no_mangle]
pub extern "system" fn Java_com_google_security_cryptauth_lib_securegcm_D2DHandshakeContext_can_1send_1payload_1in_1handshake_1message(
    env: JNIEnv,
    _: JClass,
    context_handle: jlong,
) -> jboolean {
    let can_send = if let Some(ctx) = HANDLE_MAPPING.lock().get(&(context_handle as u64)) {
        ctx.can_send_payload_in_handshake_message()
    } else {
        env.throw_new(
            "com/google/security/cryptauth/lib/securegcm/BadHandleException",
            "",
        )
        .expect("failed to find error class");
        false
    };
    can_send as jboolean
}

#[no_mangle]
pub extern "system" fn Java_com_google_security_cryptauth_lib_securegcm_D2DHandshakeContext_parse_1handshake_1message(
    env: JNIEnv,
    _: JClass,
    context_handle: jlong,
    message: jbyteArray,
) -> jbyteArray {
    let empty_array = env.new_byte_array(0).unwrap();
    let rust_buffer = env.convert_byte_array(message).unwrap();
    let result = if let Some(ctx) = HANDLE_MAPPING.lock().get_mut(&(context_handle as u64)) {
        ctx.handle_handshake_message(rust_buffer.as_slice())
            .map_err(JniError::HandleMessageError)
    } else {
        env.throw_new(
            "com/google/security/cryptauth/lib/securegcm/BadHandleException",
            "",
        )
        .expect("failed to find error class");
        Err(JniError::BadHandle)
    };
    if let Err(e) = result {
        if !env.exception_check().unwrap() {
            env.throw_new(
                "com/google/security/cryptauth/lib/securegcm/HandshakeException",
                match e {
                    JniError::BadHandle => "Bad handle",
                    JniError::DecodeError(_) => "Unable to decode message",
                    JniError::HandleMessageError(_) => "Unable to handle message",
                    JniError::HandshakeError(_) => "Handshake incomplete",
                },
            )
            .expect("failed to find error class");
        }
    }
    empty_array
}

#[no_mangle]
pub extern "system" fn Java_com_google_security_cryptauth_lib_securegcm_D2DHandshakeContext_get_1verification_1string(
    env: JNIEnv,
    _: JClass,
    context_handle: jlong,
    length: jint,
) -> jbyteArray {
    let empty_array = env.new_byte_array(0).unwrap();
    let result = if let Some(ctx) = HANDLE_MAPPING.lock().get_mut(&(context_handle as u64)) {
        ctx.to_completed_handshake()
            .map_err(|_| JniError::HandshakeError(HandshakeError::HandshakeNotComplete))
            .map(|h| {
                h.auth_string::<CryptoProvider>()
                    .derive_vec(length as usize)
                    .unwrap()
            })
    } else {
        env.throw_new(
            "com/google/security/cryptauth/lib/securegcm/BadHandleException",
            "",
        )
        .expect("failed to find error class");
        Err(JniError::BadHandle)
    };
    if let Err(e) = result {
        if !env.exception_check().unwrap() {
            env.throw_new(
                "com/google/security/cryptauth/lib/securegcm/HandshakeException",
                match e {
                    JniError::BadHandle => "Bad handle",
                    JniError::DecodeError(_) => "Unable to decode message",
                    JniError::HandleMessageError(_) => "Unable to handle message",
                    JniError::HandshakeError(_) => "Handshake incomplete",
                },
            )
            .expect("failed to find error class");
        }
        empty_array
    } else {
        let ret_vec = result.unwrap();
        env.byte_array_from_slice(&ret_vec).unwrap()
    }
}

#[no_mangle]
pub extern "system" fn Java_com_google_security_cryptauth_lib_securegcm_D2DHandshakeContext_to_1connection_1context(
    env: JNIEnv,
    _: JClass,
    context_handle: jlong,
) -> jlong {
    let conn_context = if let Some(ctx) = HANDLE_MAPPING.lock().get_mut(&(context_handle as u64)) {
        ctx.to_connection_context()
            .map_err(JniError::HandshakeError)
    } else {
        Err(JniError::BadHandle)
    };
    if let Err(error) = conn_context {
        env.throw_new(
            "com/google/security/cryptauth/lib/securegcm/HandshakeException",
            match error {
                JniError::BadHandle => "Bad context handle",
                JniError::HandshakeError(_) => "Handshake not complete",
                JniError::DecodeError(_) | JniError::HandleMessageError(_) => "Unknown exception",
            },
        )
        .expect("failed to find error class");
        return -1;
    } else {
        HANDLE_MAPPING.lock().remove(&(context_handle as u64));
    }
    insert_conn_handle(Box::new(conn_context.unwrap())) as jlong
}

// D2DConnectionContextV1
#[no_mangle]
pub extern "system" fn Java_com_google_security_cryptauth_lib_securegcm_D2DConnectionContextV1_encode_1message_1to_1peer(
    env: JNIEnv,
    _: JClass,
    context_handle: jlong,
    payload: jbyteArray,
    associated_data: jbyteArray,
) -> jbyteArray {
    // We create the empty array here so we don't run into issues requesting a new byte array from
    // the JNI env while an exception is being thrown.
    let empty_array = env.new_byte_array(0).unwrap();
    let result = if let Some(ctx) = CONNECTION_HANDLE_MAPPING
        .lock()
        .get_mut(&(context_handle as u64))
    {
        Ok(ctx.encode_message_to_peer::<CryptoProvider, _>(
            env.convert_byte_array(payload).unwrap().as_slice(),
            if associated_data.is_null() {
                None
            } else {
                Some(env.convert_byte_array(associated_data).unwrap())
            },
        ))
    } else {
        Err(JniError::BadHandle)
    };
    if let Ok(ret_vec) = result {
        env.byte_array_from_slice(ret_vec.as_slice())
            .expect("unable to create jByteArray")
    } else {
        env.throw_new(
            "com/google/security/cryptauth/lib/securegcm/BadHandleException",
            "",
        )
        .expect("failed to find error class");
        empty_array
    }
}

#[no_mangle]
pub extern "system" fn Java_com_google_security_cryptauth_lib_securegcm_D2DConnectionContextV1_decode_1message_1from_1peer(
    env: JNIEnv,
    _: JClass,
    context_handle: jlong,
    message: jbyteArray,
    associated_data: jbyteArray,
) -> jbyteArray {
    let empty_array = env.new_byte_array(0).unwrap();
    let result = if let Some(ctx) = CONNECTION_HANDLE_MAPPING
        .lock()
        .get_mut(&(context_handle as u64))
    {
        ctx.decode_message_from_peer::<CryptoProvider, _>(
            env.convert_byte_array(message).unwrap().as_slice(),
            if associated_data.is_null() {
                None
            } else {
                Some(env.convert_byte_array(associated_data).unwrap())
            },
        )
        .map_err(JniError::DecodeError)
    } else {
        Err(JniError::BadHandle)
    };
    if let Ok(message) = result {
        env.byte_array_from_slice(message.as_slice())
            .expect("unable to create jByteArray")
    } else {
        env.throw_new(
            "com/google/security/cryptauth/lib/securegcm/CryptoException",
            match result.unwrap_err() {
                JniError::BadHandle => "Bad context handle",
                JniError::DecodeError(e) => match e {
                    DecodeError::BadData => "Bad data",
                    DecodeError::BadSequenceNumber => "Bad sequence number",
                },
                // None of these should ever occur in this case.
                JniError::HandleMessageError(_) | JniError::HandshakeError(_) => "Unknown error",
            },
        )
        .expect("failed to find exception class");
        empty_array
    }
}

#[no_mangle]
pub extern "system" fn Java_com_google_security_cryptauth_lib_securegcm_D2DConnectionContextV1_get_1sequence_1number_1for_1encoding(
    env: JNIEnv,
    _: JClass,
    context_handle: jlong,
) -> jint {
    if let Some(ctx) = CONNECTION_HANDLE_MAPPING
        .lock()
        .get(&(context_handle as u64))
    {
        ctx.get_sequence_number_for_encoding() as jint
    } else {
        env.throw_new(
            "com/google/security/cryptauth/lib/securegcm/BadHandleException",
            "",
        )
        .expect("failed to find error class");
        -1 as jint
    }
}

#[no_mangle]
pub extern "system" fn Java_com_google_security_cryptauth_lib_securegcm_D2DConnectionContextV1_get_1sequence_1number_1for_1decoding(
    env: JNIEnv,
    _: JClass,
    context_handle: jlong,
) -> jint {
    if let Some(ctx) = CONNECTION_HANDLE_MAPPING
        .lock()
        .get(&(context_handle as u64))
    {
        ctx.get_sequence_number_for_decoding() as jint
    } else {
        env.throw_new(
            "com/google/security/cryptauth/lib/securegcm/BadHandleException",
            "",
        )
        .expect("failed to find error class");
        -1 as jint
    }
}

#[no_mangle]
pub extern "system" fn Java_com_google_security_cryptauth_lib_securegcm_D2DConnectionContextV1_save_1session(
    env: JNIEnv,
    _: JClass,
    context_handle: jlong,
) -> jbyteArray {
    let empty_array = env.new_byte_array(0).unwrap();
    if let Some(ctx) = CONNECTION_HANDLE_MAPPING
        .lock()
        .get(&(context_handle as u64))
    {
        env.byte_array_from_slice(ctx.save_session().as_slice())
            .expect("unable to save session")
    } else {
        env.throw_new(
            "com/google/security/cryptauth/lib/securegcm/BadHandleException",
            "",
        )
        .expect("failed to find error class");
        empty_array
    }
}

#[no_mangle]
pub extern "system" fn Java_com_google_security_cryptauth_lib_securegcm_D2DConnectionContextV1_from_1saved_1session(
    env: JNIEnv,
    _: JClass,
    session_info: jbyteArray,
) -> jlong {
    let session_info_rust = env
        .convert_byte_array(session_info)
        .expect("bad session_info data");
    let ctx = D2DConnectionContextV1::from_saved_session(session_info_rust.as_slice());
    if ctx.is_err() {
        env.throw_new(
            "com/google/security/cryptauth/lib/securegcm/SessionRestoreException",
            match ctx.err().unwrap() {
                DeserializeError::BadDataLength => "DeserializeError: bad session_info length",
                DeserializeError::BadProtocolVersion => "DeserializeError: bad protocol version",
                DeserializeError::BadData => "DeserializeError: bad data",
            },
        )
        .expect("failed to find exception class");
        return -1;
    }
    let final_ctx = ctx.ok().unwrap();
    let conn_context_final = Box::new(final_ctx);
    insert_conn_handle(conn_context_final) as jlong
}

#[no_mangle]
pub extern "system" fn Java_com_google_security_cryptauth_lib_securegcm_D2DConnectionContextV1_get_1session_1unique(
    env: JNIEnv,
    _: JClass,
    context_handle: jlong,
) -> jbyteArray {
    let empty_array = env.new_byte_array(0).unwrap();
    if let Some(ctx) = CONNECTION_HANDLE_MAPPING
        .lock()
        .get(&(context_handle as u64))
    {
        env.byte_array_from_slice(ctx.get_session_unique::<CryptoProvider>().as_slice())
            .expect("unable to get unique session id")
    } else {
        env.throw_new(
            "com/google/security/cryptauth/lib/securegcm/BadHandleException",
            "",
        )
        .expect("failed to find error class");
        empty_array
    }
}
