package com.labteto.dshmobile.security

import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.longPreferencesKey
import com.labteto.dshmobile.connection.ConnectionManager
import com.labteto.dshmobile.core.wire.dto.PromptContentPart
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.withContext
import javax.crypto.SecretKey
import javax.inject.Inject
import javax.inject.Singleton

/** What the Settings content-encryption card shows. */
data class ContentEncryptionState(
    /** The user switched encryption on — only possible once the decryptor probe succeeded. */
    val enabled: Boolean = false,
    /** The server decryptor answered the probe. Null while never probed. */
    val decryptorReady: Boolean? = null,
    /** A content key exists on this phone. */
    val keyReady: Boolean = false,
    /** Short fingerprint of the key, for checking two phones hold the same one. Null when no key. */
    val keyFingerprint: String? = null,
    /** Epoch millis the key was first created on this phone. 0 when unknown. */
    val keyCreatedAt: Long = 0L,
)

/** One re-pairing attempt (ask the server for the key it already holds). */
sealed interface RepairOutcome {
    data object Repaired : RepairOutcome
    data object ServerMissing : RepairOutcome
    data object NoHost : RepairOutcome
    data class Failed(val message: String) : RepairOutcome
}

/**
 * Content encryption, as the app's policy layer.
 *
 * The gate is the whole point: encryption is **off by default and cannot be switched on
 * until the server decryptor probe succeeds**. Turning it on without the decryptor would
 * send DSH ciphertext it cannot read, which breaks every task the phone sends — so
 * [setEnabled] refuses, and [encryptPartsIfEnabled] checks the same gate again on every
 * send rather than trusting the stored flag alone. A build of this app against a server
 * without the decryptor component therefore behaves exactly like the build before it:
 * plain text over TLS, behind the proxy password and the DSH cookie.
 *
 * The key is generated at first setup ([ensureKey], called when the Settings card opens and
 * before the first encrypted send) and lives in the Keystore ([ContentKeyStore]). The
 * server holds the *same* key — that is what the decryptor decrypts with — and the two
 * copies are what the backup paths protect: a passphrase-encrypted backup line on the
 * phone ([exportBackup] / [importBackup]), and re-pairing from the server after a
 * dsh-password login ([repairKey]).
 *
 * Key loss is final, and the app says so where the key is managed: lose the phone key, the
 * backup line, *and* the server copy, and the encrypted messages cannot be read by anyone,
 * including their owner. Rotating the key is therefore not offered as a button: a fresh key
 * would orphan every earlier encrypted message, and the design says rotation needs a warning
 * first. If rotation is ever wanted, it is a deliberate, server-side decision, not a toggle.
 */
@Singleton
class ContentEncryptionService @Inject constructor(
    private val dataStore: DataStore<Preferences>,
    private val keyStore: ContentKeyStore,
    private val gateway: PasskeyGateway,
    private val connectionManager: ConnectionManager,
) {
    /** Live state for the Settings card. */
    val state: Flow<ContentEncryptionState> = dataStore.data.map { prefs ->
        val key = runCatching { withContext(Dispatchers.Default) { keyStore.loadExisting() } }.getOrNull()
        ContentEncryptionState(
            enabled = prefs[Keys.ENABLED] ?: false,
            decryptorReady = prefs[Keys.DECRYPTOR_READY],
            keyReady = key != null,
            // A fingerprint must never be able to take the Settings card down with it: if
            // the key ever surprises this call, the line is simply not shown.
            keyFingerprint = key?.let { runCatching { ContentCrypto.fingerprint(it) }.getOrNull() },
            keyCreatedAt = prefs[Keys.KEY_CREATED_AT] ?: 0L,
        )
    }

    /** The content key, generating it on first use and stamping when it was made. */
    suspend fun ensureKey(): SecretKey {
        keyStore.loadExisting()?.let { return it }
        val fresh = withContext(Dispatchers.Default) { keyStore.key() }
        dataStore.edit { prefs ->
            if ((prefs[Keys.KEY_CREATED_AT] ?: 0L) == 0L) prefs[Keys.KEY_CREATED_AT] = System.currentTimeMillis()
        }
        return fresh
    }

    /**
     * Switch encryption on or off. Switching on is refused — returning false — while the
     * decryptor probe has not succeeded, so the toggle can never put the app in a state
     * where DSH cannot read what it sends.
     */
    suspend fun setEnabled(enabled: Boolean): Boolean {
        if (enabled) {
            val ready = dataStore.data.first()[Keys.DECRYPTOR_READY] ?: false
            if (!ready) return false
            ensureKey()
        }
        dataStore.edit { it[Keys.ENABLED] = enabled }
        return true
    }

    /** Ask the server component whether its decryptor is installed, for the active host. Null when not connected. */
    suspend fun probeDecryptor(): Boolean? {
        val host = connectionManager.state.value.host ?: return null
        val ready = when (val r = gateway.probeDecryptor(host.baseUrl, host.id)) {
            is GatewayResult.Ok -> r.value
            else -> false
        }
        dataStore.edit { it[Keys.DECRYPTOR_READY] = ready }
        return ready
    }

    /**
     * The send-path hook: encrypt the text parts of a prompt, and only when the gate is open.
     *
     * Called from `SessionStore.promptContent` for every prompt. When encryption is off, or
     * the decryptor is not ready, or there is no key, the parts pass through untouched — so
     * the normal path costs one flag read and nothing else. Images and file receipts are
     * never touched: the design encrypts message *text*, and a staged file's bytes are a
     * separate concern the server component does not decrypt.
     */
    suspend fun encryptPartsIfEnabled(parts: List<PromptContentPart>): List<PromptContentPart> {
        val prefs = dataStore.data.first()
        if (prefs[Keys.ENABLED] != true) return parts
        if (prefs[Keys.DECRYPTOR_READY] != true) return parts
        val key = runCatching { withContext(Dispatchers.Default) { ensureKey() } }.getOrNull() ?: return parts
        return parts.map { part ->
            if (part is PromptContentPart.Text && part.text.isNotBlank()) {
                PromptContentPart.Text(ContentCrypto.encrypt(key, part.text))
            } else {
                part
            }
        }
    }

    /**
     * Decrypt one line of text if it is an encrypted envelope, else return it unchanged.
     *
     * The hook point for the day the server component re-encrypts DSH's replies: the
     * transcript renders through here, and an envelope the phone cannot open (wrong key,
     * tampered tag) is shown as-is rather than silently dropped, so a decryption failure
     * is visible instead of looking like a missing message. Until the server component
     * exists no envelope ever arrives, so this is a no-op in practice today.
     */
    fun maybeDecrypt(text: String): String {
        if (!ContentCrypto.isEnvelope(text)) return text
        val key = runCatching { keyStore.existingKey() }.getOrNull() ?: return text
        return ContentCrypto.decrypt(key, text) ?: text
    }

    /** A passphrase-encrypted backup line for the current key. Null when there is no key yet. */
    suspend fun exportBackup(passphrase: String): String? {
        val key = withContext(Dispatchers.Default) { keyStore.loadExisting() } ?: return null
        return withContext(Dispatchers.Default) { ContentKeyBackup.exportBackup(key, passphrase) }
    }

    /**
     * Restore a key from a backup line. On success the restored key *replaces* the Keystore
     * key — restoring is a recovery, not an addition — and the stored flag state is left
     * alone: if encryption was on before the loss, it stays on with the recovered key.
     */
    suspend fun importBackup(blob: String, passphrase: String): BackupImportResult {
        val result = withContext(Dispatchers.Default) { ContentKeyBackup.importBackup(blob, passphrase) }
        if (result is BackupImportResult.Restored) {
            withContext(Dispatchers.Default) { keyStore.importRaw(result.key.encoded) }
            dataStore.edit { it[Keys.KEY_CREATED_AT] = System.currentTimeMillis() }
        }
        return result
    }

    /**
     * Re-pair: ask the server for the content key it already holds, after a dsh-password login.
     *
     * The server returns the *same* key, never a fresh one. A fresh key would orphan every
     * earlier encrypted message; the gateway refuses to mint one on this path, and the app
     * would refuse to store one that does not match the fingerprint it already knows — but
     * a phone that lost its key has no fingerprint to check against, so the trust here is
     * the dsh-password login itself, exactly as the design says.
     */
    suspend fun repairKey(): RepairOutcome {
        val host = connectionManager.state.value.host ?: return RepairOutcome.NoHost
        return when (val r = gateway.repairKey(host.baseUrl, host.id)) {
            is GatewayResult.Ok -> {
                withContext(Dispatchers.Default) { keyStore.importRaw(r.value) }
                dataStore.edit { it[Keys.KEY_CREATED_AT] = System.currentTimeMillis() }
                RepairOutcome.Repaired
            }
            is GatewayResult.ServerMissing -> RepairOutcome.ServerMissing
            is GatewayResult.Failed -> RepairOutcome.Failed(r.message)
        }
    }

    private object Keys {
        val ENABLED = booleanPreferencesKey("content_encryption_enabled")
        val DECRYPTOR_READY = booleanPreferencesKey("content_decryptor_ready")
        val KEY_CREATED_AT = longPreferencesKey("content_key_created_at")
    }
}
