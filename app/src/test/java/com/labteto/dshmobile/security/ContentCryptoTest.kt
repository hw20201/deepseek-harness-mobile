package com.labteto.dshmobile.security

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class ContentCryptoTest {

    @Test
    fun `encrypt then decrypt round-trips the message`() {
        val key = ContentCrypto.generateKey()
        val envelope = ContentCrypto.encrypt(key, "请把登录页的按钮改成玻璃质感")
        assertTrue(ContentCrypto.isEnvelope(envelope))
        assertFalse(ContentCrypto.isEnvelope("请把登录页的按钮改成玻璃质感"))
        assertEquals("请把登录页的按钮改成玻璃质感", ContentCrypto.decrypt(key, envelope))
    }

    @Test
    fun `the same text encrypts differently every time`() {
        val key = ContentCrypto.generateKey()
        val first = ContentCrypto.encrypt(key, "same text")
        val second = ContentCrypto.encrypt(key, "same text")
        assertNotEquals(first, second)
        assertEquals("same text", ContentCrypto.decrypt(key, first))
        assertEquals("same text", ContentCrypto.decrypt(key, second))
    }

    @Test
    fun `a different key cannot open the envelope`() {
        val key = ContentCrypto.generateKey()
        val other = ContentCrypto.generateKey()
        val envelope = ContentCrypto.encrypt(key, "secret task")
        assertNull(ContentCrypto.decrypt(other, envelope))
    }

    @Test
    fun `a tampered envelope fails instead of yielding wrong text`() {
        val key = ContentCrypto.generateKey()
        val envelope = ContentCrypto.encrypt(key, "secret task")
        // Flip a character inside the ciphertext half.
        val tampered = envelope.dropLast(2) + if (envelope.last() == 'A') "B" else "A"
        assertNull(ContentCrypto.decrypt(key, tampered))
        assertNull(ContentCrypto.decrypt(key, "dsh-enc-v1:not json"))
        assertNull(ContentCrypto.decrypt(key, "plain text, not an envelope"))
    }

    @Test
    fun `fingerprint names the key without revealing it`() {
        val key = ContentCrypto.generateKey()
        val again = ContentCrypto.keyFromBytes(key.encoded)
        assertEquals(ContentCrypto.fingerprint(key), ContentCrypto.fingerprint(again))
        assertNotEquals(ContentCrypto.fingerprint(key), ContentCrypto.fingerprint(ContentCrypto.generateKey()))
        assertTrue(ContentCrypto.fingerprint(key).length == 16)
    }
}
