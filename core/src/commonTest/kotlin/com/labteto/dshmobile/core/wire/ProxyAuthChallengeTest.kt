package com.labteto.dshmobile.core.wire

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * A 401 from the reverse proxy in front of a harness is not a 401 from the harness.
 *
 * The harness answers 401 bare — its session is a cookie, not an HTTP credential — while a proxy
 * doing Basic auth answers 401 with `WWW-Authenticate: Basic`. The challenge is the whole
 * distinction: it decides whether the connect screen says "proxy password" or "launch token",
 * and getting it wrong sends the person to paste a token the proxy will refuse before the
 * harness can read it.
 */
class ProxyAuthChallengeTest {

    @Test
    fun aBasicChallengeIsRecognised() {
        assertTrue(isBasicAuthChallenge("Basic realm=\"Restricted\""))
        assertTrue(isBasicAuthChallenge("basic realm=\"Restricted\""))
        assertFalse(isBasicAuthChallenge(null))
        assertFalse(isBasicAuthChallenge("Bearer realm=\"api\""))
        assertFalse(isBasicAuthChallenge("Digest realm=\"api\""))
    }

    @Test
    fun aBasicChallenged401ClassifiesAsAProxyRefusal() {
        assertEquals(
            TransportFailure.PROXY_UNAUTHENTICATED,
            TransportFailures.classify(
                RpcTransportException(401, "unauthorized", wwwAuthenticate = "Basic realm=\"Restricted\""),
            ),
        )
    }

    @Test
    fun aBare401IsStillTheHarnessAskingForASession() {
        assertEquals(
            TransportFailure.UNAUTHENTICATED,
            TransportFailures.classify(RpcTransportException(401, "unauthorized")),
        )
        assertEquals(
            TransportFailure.UNAUTHENTICATED,
            TransportFailures.classify(
                RpcTransportException(401, "unauthorized", wwwAuthenticate = "Bearer realm=\"api\""),
            ),
        )
    }

    @Test
    fun theCarrierMessageNamesTheProxyWhenChallenged() {
        assertTrue(carrierMessage(401, null, "Basic realm=\"Restricted\"").contains("reverse proxy"))
        assertTrue(carrierMessage(401).contains("browser session"))
    }
}
