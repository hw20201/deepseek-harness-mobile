package com.labteto.dshmobile.security

import com.labteto.dshmobile.core.wire.WireJson
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class PasskeyJsonTest {

    @Test
    fun `create request carries the challenge, rp and user verification`() {
        val json = buildCreateRequestJson(
            rpId = "wuh30617.dpdns.org",
            rpName = "DSH (wuh30617.dpdns.org)",
            userIdBase64Url = "dXNlcg",
            userName = "dsh",
            userDisplayName = "dsh",
            challengeBase64Url = "Y2hhbGxlbmdl",
            excludeCredentialIds = listOf("ZXhjbHVkZWQ"),
        )
        val root = WireJson.parseToJsonElement(json).jsonObject
        assertEquals("wuh30617.dpdns.org", root["rp"]?.jsonObject?.get("id")?.jsonPrimitive?.content)
        assertEquals("Y2hhbGxlbmdl", root["challenge"]?.jsonPrimitive?.content)
        assertEquals("dsh", root["user"]?.jsonObject?.get("name")?.jsonPrimitive?.content)
        assertEquals("required", root["authenticatorSelection"]?.jsonObject?.get("userVerification")?.jsonPrimitive?.content)
        assertEquals("platform", root["authenticatorSelection"]?.jsonObject?.get("authenticatorAttachment")?.jsonPrimitive?.content)
        assertEquals("ZXhjbHVkZWQ", root["excludeCredentials"]?.jsonArray?.first()?.jsonObject?.get("id")?.jsonPrimitive?.content)
        val algs = root["pubKeyCredParams"]?.jsonArray?.map { it.jsonObject["alg"]?.jsonPrimitive?.content }
        assertTrue(algs!!.contains("-7"))
    }

    @Test
    fun `get request carries the challenge and the allowed credentials`() {
        val json = buildGetRequestJson(
            rpId = "wuh30617.dpdns.org",
            challengeBase64Url = "Y2hhbGxlbmdl",
            allowCredentialIds = listOf("YWxsb3dlZA"),
        )
        val root = WireJson.parseToJsonElement(json).jsonObject
        assertEquals("wuh30617.dpdns.org", root["rpId"]?.jsonPrimitive?.content)
        assertEquals("required", root["userVerification"]?.jsonPrimitive?.content)
        assertEquals("YWxsb3dlZA", root["allowCredentials"]?.jsonArray?.first()?.jsonObject?.get("id")?.jsonPrimitive?.content)
    }

    @Test
    fun `create response parses and rejects the wrong shape`() {
        val good = """{"id":"Y3JlZA","rawId":"Y3JlZA","type":"public-key","response":{"attestationObject":"YXR0ZXN0","clientDataJSON":"Y2xpZW50"}}"""
        val attestation = parseCreateResponseJson(good)
        assertNotNull(attestation)
        assertEquals("Y3JlZA", attestation!!.rawIdBase64Url)
        assertEquals("YXR0ZXN0", attestation.attestationObjectBase64Url)
        assertEquals("Y2xpZW50", attestation.clientDataJsonBase64Url)

        // Not a public-key credential, missing fields, or malformed JSON: all rejected here.
        assertNull(parseCreateResponseJson("""{"id":"x","rawId":"x","type":"password","response":{}}"""))
        assertNull(parseCreateResponseJson("""{"id":"x","rawId":"x","type":"public-key","response":{"attestationObject":"a"}}"""))
        assertNull(parseCreateResponseJson("not json"))
    }

    @Test
    fun `get response parses and rejects a missing signature`() {
        val good = """{"id":"Y3JlZA","rawId":"Y3JlZA","type":"public-key","response":{"authenticatorData":"YXV0aA","clientDataJSON":"Y2xpZW50","signature":"c2ln"}}"""
        val assertion = parseGetResponseJson(good)
        assertNotNull(assertion)
        assertEquals("c2ln", assertion!!.signatureBase64Url)
        assertNull(assertion.userHandleBase64Url)

        assertNull(parseGetResponseJson("""{"id":"x","rawId":"x","type":"public-key","response":{"authenticatorData":"a","clientDataJSON":"c"}}"""))
    }

    @Test
    fun `base64url round-trips without padding`() {
        val bytes = byteArrayOf(0x00, 0x01, 0x02, 0xfb.toByte(), 0xff.toByte())
        val encoded = bytes.toBase64Url()
        assertTrue(!encoded.contains('='))
        assertTrue(!encoded.contains('+'))
        assertTrue(!encoded.contains('/'))
        assertEquals(bytes.toList(), encoded.base64UrlToBytes().toList())
    }

    @Test
    fun `register begin parses the challenge answer`() {
        val begin = parseRegisterBegin(
            """{"challenge":"Y2hhbGxlbmdl","userId":"dXNlcg","userName":"dsh","rpId":"wuh30617.dpdns.org","excludeCredentials":[{"id":"ZXhjbHVkZWQ"}]}""",
        )
        assertNotNull(begin)
        assertEquals("Y2hhbGxlbmdl", begin!!.challengeBase64Url)
        assertEquals("wuh30617.dpdns.org", begin.rpId)
        assertEquals(listOf("ZXhjbHVkZWQ"), begin.excludeCredentialIds)
        assertNull(parseRegisterBegin("""{"challenge":"x"}"""))
    }

    @Test
    fun `login begin parses the allow list`() {
        val begin = parseLoginBegin(
            """{"challenge":"Y2hhbGxlbmdl","rpId":"wuh30617.dpdns.org","allowCredentials":[{"id":"YWxsb3dlZA"}]}""",
        )
        assertNotNull(begin)
        assertEquals(listOf("YWxsb3dlZA"), begin!!.allowCredentialIds)
        assertNull(parseLoginBegin("""{"rpId":"wuh30617.dpdns.org"}"""))
    }
}
