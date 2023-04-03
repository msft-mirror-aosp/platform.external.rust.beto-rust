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

/*
 * This Java source file was generated by the Gradle 'init' task.
 */
package com.google.security.cryptauth.lib.securegcm

import java.nio.charset.StandardCharsets
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertDoesNotThrow
import org.junit.jupiter.api.assertThrows

// Driver code
// Tests exception handling and the handshake routine, as well as encrypting/decrypting short message between the server and initiator contexts.
@Suppress("UNUSED_VARIABLE")
class TestUkey2Protocol {
    @Test
    fun testHandshake() {
        val initiatorContext =
            D2DHandshakeContext(D2DHandshakeContext.Role.Initiator, NoOpLogger)
        assertFalse(initiatorContext.isHandshakeComplete)
        val serverContext =
            D2DHandshakeContext(D2DHandshakeContext.Role.Responder, NoOpLogger)
        assertFalse(serverContext.isHandshakeComplete)
        assertDoesNotThrow {
            serverContext.parseHandshakeMessage(initiatorContext.nextHandshakeMessage)
            initiatorContext.parseHandshakeMessage(serverContext.nextHandshakeMessage)
            serverContext.parseHandshakeMessage(initiatorContext.nextHandshakeMessage)
            assertTrue(initiatorContext.isHandshakeComplete)
            assertTrue(serverContext.isHandshakeComplete)
        }
    }

    @Test
    fun testSendReceiveMessage() {
        val initiatorContext =
            D2DHandshakeContext(D2DHandshakeContext.Role.Initiator, NoOpLogger)
        val serverContext =
            D2DHandshakeContext(D2DHandshakeContext.Role.Responder, NoOpLogger)
        assertDoesNotThrow {
            serverContext.parseHandshakeMessage(initiatorContext.nextHandshakeMessage)
            initiatorContext.parseHandshakeMessage(serverContext.nextHandshakeMessage)
            serverContext.parseHandshakeMessage(initiatorContext.nextHandshakeMessage)
            val connContext = initiatorContext.toConnectionContext()
            val serverConnContext = serverContext.toConnectionContext()
            val initialShareString = "Nearby sharing to server"
            val encoded = connContext.encodeMessageToPeer(
                initialShareString.toByteArray(
                    StandardCharsets.UTF_8
                ), null
            )
            val response =
                String(serverConnContext.decodeMessageFromPeer(encoded, null), StandardCharsets.UTF_8)
            assertEquals(response, initialShareString)
        }
    }

    @Test
    fun testSaveRestoreSession() {
        val initiatorContext =
            D2DHandshakeContext(D2DHandshakeContext.Role.Initiator, NoOpLogger)
        val serverContext =
            D2DHandshakeContext(D2DHandshakeContext.Role.Responder, NoOpLogger)
        assertDoesNotThrow {
            serverContext.parseHandshakeMessage(initiatorContext.nextHandshakeMessage)
            initiatorContext.parseHandshakeMessage(serverContext.nextHandshakeMessage)
            serverContext.parseHandshakeMessage(initiatorContext.nextHandshakeMessage)
            val connContext = initiatorContext.toConnectionContext()
            val serverConnContext = serverContext.toConnectionContext()
            val initiatorSavedSession = connContext.saveSession()
            val restored = D2DConnectionContextV1.fromSavedSession(initiatorSavedSession)
            assertArrayEquals(connContext.sessionUnique, restored.sessionUnique)
            val initialShareString = "Nearby sharing to server"
            val encoded = serverConnContext.encodeMessageToPeer(
                initialShareString.toByteArray(
                    StandardCharsets.UTF_8
                ), null
            )
            val response = String(restored.decodeMessageFromPeer(encoded, null), StandardCharsets.UTF_8)
            assertEquals(response, initialShareString)
        }
    }

    @Test
    fun testSaveRestoreBadSession() {
        val initiatorContext =
            D2DHandshakeContext(D2DHandshakeContext.Role.Initiator, NoOpLogger)
        val serverContext =
            D2DHandshakeContext(D2DHandshakeContext.Role.Responder, NoOpLogger)
        val deriveInitiatorSavedSession = {
            assertDoesNotThrow {
                serverContext.parseHandshakeMessage(initiatorContext.nextHandshakeMessage)
                initiatorContext.parseHandshakeMessage(serverContext.nextHandshakeMessage)
                serverContext.parseHandshakeMessage(initiatorContext.nextHandshakeMessage)
                val connContext = initiatorContext.toConnectionContext()
                val serverConnContext = serverContext.toConnectionContext()
                connContext.saveSession()
            }
        }
        assertThrows<SessionRestoreException> {
            val unused = D2DConnectionContextV1.fromSavedSession(deriveInitiatorSavedSession().copyOfRange(0, 20))
        }
    }

    @Test
    fun tryReuseHandshakeContext() {
        val initiatorContext =
            D2DHandshakeContext(D2DHandshakeContext.Role.Initiator, NoOpLogger)
        val serverContext =
            D2DHandshakeContext(D2DHandshakeContext.Role.Responder, NoOpLogger)
        assertDoesNotThrow {
            serverContext.parseHandshakeMessage(initiatorContext.nextHandshakeMessage)
            initiatorContext.parseHandshakeMessage(serverContext.nextHandshakeMessage)
            serverContext.parseHandshakeMessage(initiatorContext.nextHandshakeMessage)
            val connContext = initiatorContext.toConnectionContext()
            val serverConnContext = serverContext.toConnectionContext()
        }
        assertThrows<BadHandleException> {
            val unused = serverContext.nextHandshakeMessage
        }
    }

    @Test
    fun testSendReceiveMessageWithAssociatedData() {
        val initiatorContext =
            D2DHandshakeContext(D2DHandshakeContext.Role.Initiator, NoOpLogger)
        val serverContext =
            D2DHandshakeContext(D2DHandshakeContext.Role.Responder, NoOpLogger)
        val associatedData = "Associated data.".toByteArray()
        assertDoesNotThrow {
            serverContext.parseHandshakeMessage(initiatorContext.nextHandshakeMessage)
            initiatorContext.parseHandshakeMessage(serverContext.nextHandshakeMessage)
            serverContext.parseHandshakeMessage(initiatorContext.nextHandshakeMessage)
            val connContext = initiatorContext.toConnectionContext()
            val serverConnContext = serverContext.toConnectionContext()
            val initialShareString = "Nearby sharing to server"
            val encoded = connContext.encodeMessageToPeer(
                initialShareString.toByteArray(
                    StandardCharsets.UTF_8
                ), associatedData
            )
            val response =
                String(serverConnContext.decodeMessageFromPeer(encoded, associatedData), StandardCharsets.UTF_8)
            assertEquals(response, initialShareString)
        }
    }

    @Test
    fun testVerificationString() {
        val initiatorContext =
            D2DHandshakeContext(D2DHandshakeContext.Role.Initiator, NoOpLogger)
        val serverContext =
            D2DHandshakeContext(D2DHandshakeContext.Role.Responder, NoOpLogger)
        assertDoesNotThrow {
            serverContext.parseHandshakeMessage(initiatorContext.nextHandshakeMessage)
            initiatorContext.parseHandshakeMessage(serverContext.nextHandshakeMessage)
            serverContext.parseHandshakeMessage(initiatorContext.nextHandshakeMessage)
        }
        assert(serverContext.isHandshakeComplete)
        assert(initiatorContext.isHandshakeComplete)
        assertArrayEquals(serverContext.getVerificationString(32), initiatorContext.getVerificationString(32))
    }
}