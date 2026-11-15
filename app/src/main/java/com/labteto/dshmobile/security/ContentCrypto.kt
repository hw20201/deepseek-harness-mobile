package com.labteto.dshmobile.security

import com.labteto.dshmobile.core.wire.WireJson
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Message-content encryption: AES-256-GCM over the text of a prompt, with a JSON envelope.
 *
 * This file is the pure part — it takes a [SecretKey] and knows nothing about where the key
 * lives. The Keystore half is [ContentKeyStore]; the policy half (on/off, the server
 * decryptor probe, backup) is [ContentEncryptionService]. Keeping the crypto pure is what
 * lets the unit tests run it on the JVM: the algorithm is the same on both sides of that
 * line, and a test that encrypts and decrypts with an in-memory key proves the envelope
 * round-trips without needing an Android device.
 *
 * Wire format, one line of text so it rides `session/prompt`'s text part unchanged:
 *
 *     dsh-enc-v1:{"v":1,"alg":"AES-256-GCM","kid":"<key fingerprint>","iv":"<base64url>","ct":"<base64url>"}
 *
 * The `dsh-enc-v1:` prefix is the discriminator: the server decryptor (and the app's
 * [ContentEncryptionService.maybeDecrypt]) recognise an encrypted payload by it, and plain
 * text never starts with it, so a mixed transcript — some messages encrypted, some not —
 * is readable on both sides without a flag per message. The IV is random per message and
 * travels in the envelope; it is not a secret, only a value that must never repeat under
 * one key. The GCM tag rides inside `ct`, so a tampered envelope fails decryption instead
 * of yielding wrong text.
 */
object ContentCrypto {
    const val ENVELOPE_PREFIX = "dsh-enc-v1:"
    const val ALGORITHM = "AES-256-GCM"
    private const val TRANSFORMATION = "AES/GCM/NoPadding"
    private const val TAG_BITS = 128
    private const val IV_BYTES = 12

    /** A fresh 256-bit content key. Used once, at first setup; afterwards the Keystore holds it. */
    fun generateKey(): SecretKey {
        val generator = KeyGenerator.getInstance("AES")
        generator.init(256, SecureRandom())
        return generator.generateKey()
    }

    /** Rebuild a key from raw bytes — the backup / re-pairing path. */
    fun keyFromBytes(raw: ByteArray): SecretKey = SecretKeySpec(raw, "AES")

    /**
     * Short fingerprint of a key, for the Settings card: the first 16 hex chars of the
     * SHA-256 of the encoded key. It names the key without revealing it — two phones that
     * show the same fingerprint hold the same key, which is how a re-pair is checked.
     *
     * A key held inside the `AndroidKeyStore` never yields its bytes (`encoded` is null) —
     * such a key must never reach this function: [ContentKeyStore] hands out in-memory keys
     * precisely so the fingerprint, the backup and the envelope all have bytes to work with.
     * Refusing loudly here, rather than the NullPointerException `digest(null)` used to
     * throw, is what makes that contract visible if it is ever broken again.
     */
    fun fingerprint(key: SecretKey): String {
        val encoded = key.encoded
            ?: throw IllegalStateException("key has no exportable bytes; fingerprint needs them")
        val digest = MessageDigest.getInstance("SHA-256").digest(encoded)
        return digest.take(8).joinToString("") { "%02x".format(it) }
    }

    /** Encrypt [plaintext] under [key]; the result is one line starting with [ENVELOPE_PREFIX]. */
    fun encrypt(key: SecretKey, plaintext: String): String {
        val iv = ByteArray(IV_BYTES).also { SecureRandom().nextBytes(it) }
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(TAG_BITS, iv))
        val body = cipher.doFinal(plaintext.toByteArray(Charsets.UTF_8))
        val envelope = WireJson.encodeToString(
            JsonObject.serializer(),
            buildJsonObject {
                put("v", 1)
                put("alg", ALGORITHM)
                put("kid", fingerprint(key))
                put("iv", iv.toBase64Url())
                put("ct", body.toBase64Url())
            },
        )
        return ENVELOPE_PREFIX + envelope
    }

    /**
     * Decrypt an envelope produced by [encrypt].
     *
     * Returns null — never wrong text — when the input is not an envelope, the JSON is
     * malformed, the algorithm or version is unknown, or the GCM tag does not check out.
     * A tag failure means the ciphertext was tampered with or a different key was used;
     * either way there is nothing to show.
     */
    fun decrypt(key: SecretKey, envelope: String): String? {
        if (!isEnvelope(envelope)) return null
        val root = runCatching {
            WireJson.parseToJsonElement(envelope.removePrefix(ENVELOPE_PREFIX)).jsonObject
        }.getOrNull() ?: return null
        if (root["v"]?.jsonPrimitive?.content != "1") return null
        if (root["alg"]?.jsonPrimitive?.content != ALGORITHM) return null
        val iv = runCatching { root["iv"]?.jsonPrimitive?.content?.base64UrlToBytes() }.getOrNull() ?: return null
        val body = runCatching { root["ct"]?.jsonPrimitive?.content?.base64UrlToBytes() }.getOrNull() ?: return null
        return runCatching {
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(TAG_BITS, iv))
            String(cipher.doFinal(body), Charsets.UTF_8)
        }.getOrNull()
    }

    /** Whether [text] is an encrypted envelope, as opposed to plain message text. */
    fun isEnvelope(text: String): Boolean = text.startsWith(ENVELOPE_PREFIX)
}
