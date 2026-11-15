package com.labteto.dshmobile.security

import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringPreferencesKey
import com.labteto.dshmobile.core.wire.WireJson
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import kotlinx.serialization.builtins.MapSerializer
import kotlinx.serialization.builtins.serializer
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Passkey registrations, one per host id, in plain DataStore.
 *
 * Plain, deliberately: a registration holds only a credential id and a relying-party id, both
 * public by design — the credential id is sent to the server on every login, and the rpId is a
 * hostname. There is nothing here an attacker could use without the private key, which never
 * leaves the platform authenticator. Encrypting public values would suggest a boundary that
 * is not there, the same reasoning [com.labteto.dshmobile.connection.HarnessSessionStore]
 * gives for the session cookie; the secrets in this feature are the proxy password and the
 * content-encryption key, and those stay Keystore-encrypted in their own stores.
 */
@Singleton
class PasskeyStore @Inject constructor(
    private val dataStore: DataStore<Preferences>,
) {
    /** The registration for [hostId], or null when this phone has none for it. */
    fun registration(hostId: String): Flow<PasskeyRegistration?> =
        dataStore.data.map { prefs ->
            registrations(prefs[KEY]).get(hostId)?.let {
                runCatching { WireJson.decodeFromString(PasskeyRegistration.serializer(), it) }.getOrNull()
            }
        }

    suspend fun registrationOnce(hostId: String): PasskeyRegistration? = registration(hostId).first()

    /** Remember [registration] for [hostId], replacing any previous one. */
    suspend fun save(hostId: String, registration: PasskeyRegistration) {
        val raw = dataStore.data.first()[KEY]
        val next = registrations(raw) + (hostId to WireJson.encodeToString(PasskeyRegistration.serializer(), registration))
        dataStore.edit { it[KEY] = WireJson.encodeToString(serializer, next) }
    }

    /** Forget the registration for [hostId]. Safe to call when there is none. */
    suspend fun remove(hostId: String) {
        val raw = dataStore.data.first()[KEY]
        val current = registrations(raw)
        if (hostId !in current) return
        dataStore.edit { it[KEY] = WireJson.encodeToString(serializer, current - hostId) }
    }

    /** Forget every registration — the Settings "clear data" action, and forgetting every host. */
    suspend fun clear() {
        dataStore.edit { it.remove(KEY) }
    }

    private fun registrations(raw: String?): Map<String, String> {
        if (raw == null) return emptyMap()
        return runCatching { WireJson.decodeFromString(serializer, raw) }.getOrDefault(emptyMap())
    }

    private companion object {
        val KEY = stringPreferencesKey("passkey_registrations_json")
        val serializer = MapSerializer(String.serializer(), String.serializer())
    }
}
