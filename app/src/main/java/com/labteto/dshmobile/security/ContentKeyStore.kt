package com.labteto.dshmobile.security

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringPreferencesKey
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.withContext
import java.security.GeneralSecurityException
import java.security.KeyStore
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.inject.Inject
import javax.inject.Singleton

/**
 * The content-encryption key, held as raw bytes encrypted in DataStore.
 *
 * The shape is deliberately the same as [com.labteto.dshmobile.connection.ProxyCredentialStore]:
 * the raw 32 bytes live encrypted (AES-GCM) in one DataStore blob, under a wrapping key that
 * lives in the `AndroidKeyStore` and never leaves it. The key is handed out as an in-memory
 * [SecretKeySpec], so [SecretKey.getEncoded] works on it — the fingerprint, the passphrase
 * backup and the envelope all need the raw bytes.
 *
 * That last point is why the key is *not* held as a Keystore entry itself, the way an earlier
 * build did it: a key generated inside the `AndroidKeyStore` never yields its bytes
 * (`getEncoded()` returns null — the material never leaves the store), so the first time the
 * Settings card computed the fingerprint of the key it had just generated, the app crashed
 * with a NullPointerException. The wrapping key here *is* a Keystore key, which is fine: it
 * only ever wraps and unwraps through the cipher, in place, and never needs to be exported.
 *
 * User authentication is deliberately *not* required on the wrapping key, for the same reason
 * as the relay and proxy stores: the key must be usable whenever the app sends a message, and
 * a per-message biometric prompt would make the feature unusable in practice. The phone's
 * lock screen is the boundary here; the fingerprint step belongs to the passkey, which gates
 * *access*, while this key gates *readability of the words themselves*.
 *
 * A blob that will not decrypt is dropped rather than raised, for the same reason as the
 * relay and proxy stores: the wrapping key was invalidated, and the result is the same
 * terminal state as having no key — re-pair or restore from backup.
 */
@Singleton
class ContentKeyStore @Inject constructor(
    private val dataStore: DataStore<Preferences>,
) {
    /** The key as loaded this process, so a synchronous read never touches disk. */
    @Volatile
    private var cached: SecretKey? = null

    /** The content key if one is stored, loading it into memory first. Null when there is none. */
    suspend fun loadExisting(): SecretKey? {
        cached?.let { return it }
        val blob = dataStore.data.first()[KEY] ?: return null
        val raw = runCatching { withContext(Dispatchers.Default) { decrypt(blob) } }.getOrNull()
            ?: run {
                dataStore.edit { it.remove(KEY) }
                return null
            }
        return ContentCrypto.keyFromBytes(raw).also { cached = it }
    }

    /** The in-memory copy, or null when no key has been loaded yet this process. Never touches disk. */
    fun existingKey(): SecretKey? = cached

    /** The content key, generating it on first use. */
    suspend fun key(): SecretKey {
        loadExisting()?.let { return it }
        val fresh = ContentCrypto.generateKey()
        val blob = withContext(Dispatchers.Default) { encrypt(fresh.encoded) }
        dataStore.edit { it[KEY] = blob }
        cached = fresh
        // One-time cleanup: builds before this one held the key as a non-exportable Keystore
        // entry (alias dsh_content_key). That entry can never yield its bytes, so nothing was
        // ever encrypted with it; drop it so it does not linger under a misleading name.
        runCatching { withContext(Dispatchers.Default) { dropLegacyKeystoreEntry() } }
        return fresh
    }

    /** The raw bytes of the current key. Null when there is no key yet. */
    suspend fun exportRaw(): ByteArray? = loadExisting()?.encoded

    /**
     * Replace the stored key with [raw] bytes — the backup-restore and re-pairing paths.
     *
     * It never generates a fresh key on its own — a fresh key here would orphan every earlier
     * encrypted message.
     */
    suspend fun importRaw(raw: ByteArray) {
        val blob = withContext(Dispatchers.Default) { encrypt(raw) }
        dataStore.edit { it[KEY] = blob }
        cached = ContentCrypto.keyFromBytes(raw)
    }

    /** Forget the key. The encrypted messages stay encrypted — including from their owner. */
    suspend fun clear() {
        dataStore.edit { it.remove(KEY) }
        cached = null
    }

    /**
     * AES-GCM, with the IV prefixed to the ciphertext.
     *
     * GCM generates its own IV per encryption and the Keystore refuses a caller-supplied one for
     * this key, so the IV has to be read back off the cipher and carried with the payload — it is
     * not a secret, only a value that must never repeat under one key.
     */
    private fun encrypt(plain: ByteArray): String {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, wrappingKey())
        val body = cipher.doFinal(plain)
        val encoder = Base64.getEncoder()
        return encoder.encodeToString(cipher.iv) + SEPARATOR + encoder.encodeToString(body)
    }

    private fun decrypt(blob: String): ByteArray {
        val parts = blob.split(SEPARATOR)
        if (parts.size != 2) throw GeneralSecurityException("malformed content key blob")
        val decoder = Base64.getDecoder()
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, wrappingKey(), GCMParameterSpec(TAG_BITS, decoder.decode(parts[0])))
        return cipher.doFinal(decoder.decode(parts[1]))
    }

    /** The Keystore wrapping key, generated on first use. It only ever wraps and unwraps. */
    private fun wrappingKey(): SecretKey {
        val keyStore = KeyStore.getInstance(PROVIDER).apply { load(null) }
        (keyStore.getEntry(WRAP_ALIAS, null) as? KeyStore.SecretKeyEntry)?.let { return it.secretKey }
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, PROVIDER)
        generator.init(
            KeyGenParameterSpec.Builder(WRAP_ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setUserAuthenticationRequired(false)
                .build(),
        )
        return generator.generateKey()
    }

    private fun dropLegacyKeystoreEntry() {
        val keyStore = KeyStore.getInstance(PROVIDER).apply { load(null) }
        if (keyStore.containsAlias(LEGACY_ALIAS)) keyStore.deleteEntry(LEGACY_ALIAS)
    }

    private companion object {
        val KEY = stringPreferencesKey("content_key_blob")
        const val PROVIDER = "AndroidKeyStore"
        const val WRAP_ALIAS = "dsh_content_key_wrap"
        const val LEGACY_ALIAS = "dsh_content_key"
        const val TRANSFORMATION = "AES/GCM/NoPadding"
        const val TAG_BITS = 128

        /** Not valid base64, so it cannot occur inside either half. */
        const val SEPARATOR = ":"
    }
}
