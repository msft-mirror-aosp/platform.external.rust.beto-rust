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

#include "ukey2.h"

#include <cstring>
#include <iostream>
#include <string>

CFFIByteArray messageToByteArray(const std::string message) {
    return {
        .handle = (uint8_t*) (new std::string(message))->c_str(),
        .len = message.length(),
    };
}

CFFIByteArray nullByteArray() {
    return {
        .handle = nullptr,
        .len = 0,
    };
}

int main() {
    Ukey2HandshakeContextHandle responder_handle = responder_new();
    Ukey2HandshakeContextHandle initiator_handle = initiator_new();
    printf("Created handshakes");
    // Run the handshake
    RustFFIByteArray handshake_msg = get_next_handshake_message(initiator_handle);
    parse_handshake_message(responder_handle, handshake_msg);
    printf("parsed clientinit\n");
    parse_handshake_message(initiator_handle, get_next_handshake_message(responder_handle));
    printf("parsed serverinit\n");
    parse_handshake_message(responder_handle, get_next_handshake_message(initiator_handle));
    printf("parsed clientfinish\n");
    // Print verification strings
    RustFFIByteArray init_verif_str = get_verification_string(initiator_handle, 16);
    auto init_verif_ccstr = std::string((const char*) init_verif_str.handle, init_verif_str.len);
    std::cout << init_verif_ccstr << std::endl;
    RustFFIByteArray serv_verif_str = get_verification_string(responder_handle, 16);
    auto serv_verif_ccstr = std::string((const char*) serv_verif_str.handle, serv_verif_str.len);
    std::cout << serv_verif_ccstr << std::endl;
    std::cout << "Verification strings equality: " << ((init_verif_ccstr == serv_verif_ccstr) ? "true" : "false") << std::endl;
    // Create connection contexts.
    Ukey2ConnectionContextHandle responder_connection = to_connection_context(responder_handle);
    Ukey2HandshakeContextHandle initiator_connection = to_connection_context(initiator_handle);
    RustFFIByteArray encoded = encode_message_to_peer(responder_connection, messageToByteArray("hello world"), nullByteArray());
    RustFFIByteArray decoded = decode_message_from_peer(initiator_connection, encoded, nullByteArray());
    std::cout << std::string((const char*) decoded.handle, decoded.len) << std::endl;
    // clean up
    rust_dealloc_ffi_byte_array(encoded);
    rust_dealloc_ffi_byte_array(decoded);
}
