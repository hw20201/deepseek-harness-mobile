package com.labteto.dshmobile.connection

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringPreferencesKey
import com.labteto.dshmobile.core.wire.WireJson
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.withContext
import kotlinx.serialization.builtins.MapSerializer
import kotlinx.serialization.builtins.serializer
import okhttp3.Credentials
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
 * Reverse-proxy Basic credentials, encrypted at rest.
 *
 * The mirror of [RelayCredentialStore] for the other credential this app holds: the username and
 * password for a reverse proxy in front of a harness (nginx `auth_basic`, say). The shape is the
 * same on purpose — one encrypted blob per host id in DataStore, AES-GCM under a key that lives
 * in the `AndroidKeyStore` and never leaves it — because the power is the same: presenting this
 * credential reaches the machine behind the proxy with the harness's authority, and the harness
 * behind it runs commands there.
 *
 * The username travels in the blob beside the password rather than being read back off
 * [HostConfig.proxyUsername]. That record only marks that a proxy credential exists; the store is
 * the one place that can turn a host id into a header, so the token exchange — which knows only
 * the host id — does not need a second lookup to build one. A blob that will not decrypt is
 * dropped rather than raised, for the same reason as the relay store's: the Keystore key was
 * invalidated, and the result is the same terminal state as a wrong password — this device has
 * no credential and the user retypes it in the connect form.
 *
 * User authentication is deliberately *not* required on the key, for the same reason as the relay
 * store's: the foreground service and [KeepAliveWorker] reconnect while the screen is locked.
 */
@Singleton
class ProxyCredentialStore @Inject constructor(
    private val dataStore: DataStore<Preferences>,
) {
    private val serializer = MapSerializer(String.serializer(), String.serializer())

    /**
     * The `Authorization` value for [hostId] — the full `Basic …` header — or null when this
     * device holds no proxy credential for it.
     */
    suspend fun authorization(hostId: String): String? {
        val (username, password) = credentials(hostId) ?: return null
        return Credentials.basic(username, password)
    }

    /** The stored username and password for [hostId], or null when there is none this device can still read. */
    suspend fun credentials(hostId: String): Pair<String, String>? {
        val blob = blobs()[hostId] ?: return null
        val plain = withContext(Dispatchers.Default) { runCatching { decrypt(blob) }.getOrNull() }
        if (plain == null) {
            remove(hostId)
            return null
        }
        val fields = runCatching {
            WireJson.decodeFromString(MapSerializer(String.serializer(), String.serializer()), plain)
        }.getOrNull()
        val username = fields?.get(USERNAME_KEY)
        val password = fields?.get(PASSWORD_KEY)
        if (username == null || password == null) {
            remove(hostId)
            return null
        }
        return username to password
    }

    /** Remember [username] and [password] for [hostId], replacing any previous pair. */
    suspend fun put(hostId: String, username: String, password: String) {
        val plain = WireJson.encodeToString(
            MapSerializer(String.serializer(), String.serializer()),
            mapOf(USERNAME_KEY to username, PASSWORD_KEY to password),
        )
        val blob = withContext(Dispatchers.Default) { encrypt(plain) }
        write(blobs() + (hostId to blob))
    }

    /** Forget the credential for [hostId]. Safe to call when there is none. */
    suspend fun remove(hostId: String) {
        val current = blobs()
        if (hostId !in current) return
        write(current - hostId)
    }

    /** Forget every credential — the Settings "clear data" action, and forgetting every host. */
    suspend fun clear() {
        dataStore.edit { it.remove(KEY) }
    }

    private suspend fun blobs(): Map<String, String> {
        val raw = dataStore.data.first()[KEY] ?: return emptyMap()
        return runCatching { WireJson.decodeFromString(serializer, raw) }.getOrDefault(emptyMap())
    }

    private suspend fun write(next: Map<String, String>) {
        dataStore.edit { it[KEY] = WireJson.encodeToString(serializer, next) }
    }

    /**
     * AES-GCM, with the IV prefixed to the ciphertext.
     *
     * GCM generates its own IV per encryption and the Keystore refuses a caller-supplied one for
     * this key, so the IV has to be read back off the cipher and carried with the payload — it is
     * not a secret, only a value that must never repeat under one key.
     */
    private fun encrypt(plain: String): String {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, secretKey())
        val body = cipher.doFinal(plain.toByteArray(Charsets.UTF_8))
        val encoder = Base64.getEncoder()
        return encoder.encodeToString(cipher.iv) + SEPARATOR + encoder.encodeToString(body)
    }

    private fun decrypt(blob: String): String {
        val parts = blob.split(SEPARATOR)
        if (parts.size != 2) throw GeneralSecurityException("malformed credential blob")
        val decoder = Base64.getDecoder()
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, secretKey(), GCMParameterSpec(TAG_BITS, decoder.decode(parts[0])))
        return String(cipher.doFinal(decoder.decode(parts[1])), Charsets.UTF_8)
    }

    /** The Keystore key, generated on first use. */
    private fun secretKey(): SecretKey {
        val keyStore = KeyStore.getInstance(PROVIDER).apply { load(null) }
        (keyStore.getEntry(ALIAS, null) as? KeyStore.SecretKeyEntry)?.let { return it.secretKey }
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, PROVIDER)
        generator.init(
            KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setUserAuthenticationRequired(false)
                .build(),
        )
        return generator.generateKey()
    }

    private companion object {
        val KEY = stringPreferencesKey("proxy_passwords_json")
        const val PROVIDER = "AndroidKeyStore"
        const val ALIAS = "dsh_proxy_passwords"
        const val TRANSFORMATION = "AES/GCM/NoPadding"
        const val TAG_BITS = 128

        /** Not valid base64, so it cannot occur inside either half. */
        const val SEPARATOR = ":"

        /** Keys of the username/password pair inside one encrypted blob. */
        const val USERNAME_KEY = "u"
        const val PASSWORD_KEY = "p"
    }
}
