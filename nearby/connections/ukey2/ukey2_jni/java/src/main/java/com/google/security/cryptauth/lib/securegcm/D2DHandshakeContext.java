/*
 * Copyright 2023 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.google.security.cryptauth.lib.securegcm;

import javax.annotation.Nonnull;

public class D2DHandshakeContext {
    static {
        System.loadLibrary("ukey2_jni");
    }

    public enum Role {
        Initiator,
        Responder,
    }

    private final long context_ptr;

    private static native boolean is_handshake_complete(long context_ptr) throws BadHandleException;

    private static native long create_context(boolean is_client, Ukey2Logger logger);

    private static native byte[] get_next_handshake_message(long context_ptr) throws BadHandleException;

    private static native boolean can_send_payload_in_handshake_message(long context_ptr) throws BadHandleException;

    private static native byte[] parse_handshake_message(long context_ptr, byte[] message) throws BadHandleException, HandshakeException;

    private static native byte[] get_verification_string(long context_ptr, int length) throws BadHandleException, HandshakeException;

    private static native long to_connection_context(long context_ptr) throws HandshakeException;

    public D2DHandshakeContext(@Nonnull Role role, @Nonnull Ukey2Logger logger) {
        this.context_ptr = create_context(role == Role.Initiator, logger);
    }

    /**
     * Convenience constructor that creates a UKEY2 D2DHandshakeContext for the initiator role.
     *
     * @param logger       - The {@link Ukey2Logger} instance to log any debug/error messages to.
     * @return a D2DHandshakeContext for the role of initiator in the handshake.
     */
    public static D2DHandshakeContext forInitiator(@Nonnull Ukey2Logger logger) {
        return new D2DHandshakeContext(Role.Initiator, logger);
    }

    /**
     * Convenience constructor that creates a UKEY2 D2DHandshakeContext for the initiator role.
     *
     * @param logger       - The {@link Ukey2Logger} instance to log any debug/error messages to.
     * @return a D2DHandshakeContext for the role of responder/server in the handshake.
     */
    public static D2DHandshakeContext forResponder(@Nonnull Ukey2Logger logger) {
        return new D2DHandshakeContext(Role.Responder, logger);
    }

    /**
     * Function that checks if the handshake is completed.
     *
     * @return true/false depending on if the handshake is complete.
     */
    public boolean isHandshakeComplete() throws BadHandleException {
        return is_handshake_complete(context_ptr);
    }

    /**
     * Gets the next handshake message in the exchange.
     *
     * @return handshake message encoded in a SecureMessage.
     */
    public @Nonnull byte[] getNextHandshakeMessage() throws BadHandleException {
        return get_next_handshake_message(context_ptr);
    }

    /**
     * Indicates if extra information can be shared during the handshake at the current stage.
     *
     * @return if we can send extra informatino to the responder over the handshake.
     */
    public boolean canSendPayloadInHandshakeMessage() throws BadHandleException {
        return can_send_payload_in_handshake_message(context_ptr);
    }

    /**
     * Parses the handshake message and returns the encoded payload if any.
     *
     * @param message - handshake message from the other side.
     * @return - extra information, if any, should correspond with {@link D2DHandshakeContext#canSendPayloadInHandshakeMessage}
     */
    public @Nonnull byte[] parseHandshakeMessage(@Nonnull byte[] message) throws BadHandleException, HandshakeException {
        return parse_handshake_message(context_ptr, message);
    }

    /**
     * Returns an authentication string suitable for authenticating the handshake out-of-band. Note
     * that the authentication string can be short (e.g., a 6 digit visual confirmation code). Note:
     * this should only be called when {#isHandshakeComplete} returns true.
     * This code is analogous to the authentication string described in the spec.
     *
     * @param length - The length of the returned verification string.
     * @return - The returned verification string as a byte array.
     * @throws BadHandleException - Thrown if the handle is no longer valid, for example after calling {@link D2DHandshakeContext#toConnectionContext}
     * @throws HandshakeException - Thrown if the handshake is not complete when this function is called.
     */
    public @Nonnull byte[] getVerificationString(int length) throws BadHandleException, HandshakeException {
        return get_verification_string(context_ptr, length);
    }

    /**
     * Function to create a secure communication channel from the handshake after confirming the auth string generated by
     * the handshake out-of-band (i.e. via a user-facing UI).
     *
     * @return a new {@link D2DConnectionContextV1} with the next protocol specified when creating the D2DHandshakeContext.
     * @throws HandshakeException if the handsshake is not complete when this function is called.
     */
    public D2DConnectionContextV1 toConnectionContext() throws HandshakeException {
        return new D2DConnectionContextV1(to_connection_context(context_ptr));
    }
}
