package com.labteto.dshmobile.security

import kotlinx.coroutines.test.runTest
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Protocol
import okhttp3.Response
import okhttp3.ResponseBody.Companion.toResponseBody
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The gateway against a canned HTTP layer: no network, no DataStore.
 *
 * The point is the contract, not the transport: a 404 means the server component is not
 * installed, a 200 with the documented JSON parses, and the login finish hands back the
 * DSH session cookie from `Set-Cookie`. That is the behaviour the app leans on when the
 * component finally exists, and the behaviour it must already show while it does not.
 */
class PasskeyGatewayTest {

    private fun gateway(responses: Map<String, Pair<Int, String>>, cookies: Map<String, String> = emptyMap()): PasskeyGateway {
        val http = OkHttpClient.Builder().addInterceptor { chain ->
            val url = chain.request().url.toString()
            val (code, body) = responses[url] ?: (404 to "")
            val response = Response.Builder()
                .request(chain.request())
                .protocol(Protocol.HTTP_1_1)
                .code(code)
                .message("test")
                .body(body.toResponseBody("application/json".toMediaType()))
            cookies[url]?.let { response.addHeader("Set-Cookie", it) }
            response.build()
        }.build()
        return PasskeyGateway(http, { "Basic ZHNoOnBhc3M" }, { "dsh-auth-x=abc" })
    }

    @Test
    fun `probe says installed when the component answers, missing on 404`() = runTest {
        val installed = gateway(
            mapOf(BASE + "passkey/status" to (200 to """{"installed":true}""")),
        )
        assertEquals(GatewayResult.Ok(true), installed.probePasskey(BASE, "host-1"))

        val missing = gateway(emptyMap())
        assertEquals(GatewayResult.Ok(false), missing.probePasskey(BASE, "host-1"))
    }

    @Test
    fun `register begin parses the challenge, missing on 404`() = runTest {
        val gateway = gateway(
            mapOf(BASE + "passkey/register/begin" to (200 to """{"challenge":"Y2hhbGxlbmdl","userId":"dXNlcg","userName":"dsh","rpId":"wuh30617.dpdns.org","excludeCredentials":[]}""")),
        )
        val result = gateway.beginRegister(BASE, "host-1")
        assertTrue(result is GatewayResult.Ok)
        assertEquals("Y2hhbGxlbmdl", (result as GatewayResult.Ok).value.challengeBase64Url)

        assertEquals(GatewayResult.ServerMissing(404), gateway(emptyMap()).beginRegister(BASE, "host-1"))
    }

    @Test
    fun `login finish hands back the session cookie`() = runTest {
        val gateway = gateway(
            mapOf(BASE + "passkey/login/finish" to (200 to """{"ok":true}""")),
            cookies = mapOf(BASE + "passkey/login/finish" to "dsh-auth-wuh30617.dpdns.org=sessionvalue; Path=/; HttpOnly"),
        )
        val assertion = PasskeyAssertion(
            id = "Y3JlZA",
            rawIdBase64Url = "Y3JlZA",
            authenticatorDataBase64Url = "YXV0aA",
            clientDataJsonBase64Url = "Y2xpZW50",
            signatureBase64Url = "c2ln",
        )
        val result = gateway.finishLogin(BASE, "host-1", assertion)
        assertTrue(result is GatewayResult.Ok)
        assertEquals("dsh-auth-wuh30617.dpdns.org=sessionvalue", (result as GatewayResult.Ok).value)
    }

    @Test
    fun `decryptor probe is ready only on an explicit ready answer`() = runTest {
        val ready = gateway(mapOf(BASE + "content/v1/status" to (200 to """{"ready":true}""")))
        assertEquals(GatewayResult.Ok(true), ready.probeDecryptor(BASE, "host-1"))

        val notReady = gateway(mapOf(BASE + "content/v1/status" to (200 to """{"ready":false}""")))
        assertEquals(GatewayResult.Ok(false), notReady.probeDecryptor(BASE, "host-1"))

        val missing = gateway(emptyMap())
        assertEquals(GatewayResult.Ok(false), missing.probeDecryptor(BASE, "host-1"))
    }

    @Test
    fun `repair returns the raw key bytes`() = runTest {
        val raw = byteArrayOf(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32)
        val encoded = java.util.Base64.getEncoder().encodeToString(raw)
        val gateway = gateway(mapOf(BASE + "content/v1/repair" to (200 to """{"key":"$encoded"}""")))
        val result = gateway.repairKey(BASE, "host-1")
        assertTrue(result is GatewayResult.Ok)
        assertEquals(raw.toList(), (result as GatewayResult.Ok).value.toList())
        assertEquals(GatewayResult.ServerMissing(404), gateway(emptyMap()).repairKey(BASE, "host-1"))
    }

    private companion object {
        const val BASE = "https://wuh30617.dpdns.org/dsh/"
    }
}
