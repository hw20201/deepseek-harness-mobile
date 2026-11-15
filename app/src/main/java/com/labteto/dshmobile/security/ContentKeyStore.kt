package com.labteto.dshmobile.security

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyStore
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec
import javax.inject.Inject
import javax.inject.Singleton

/**
 * The content-encryption key, held in the Android Keystore.
 *
 * The key is generated once, at first setup, and never leaves the Keystore in usable form:
 * [key] hands back a handle the cipher uses in place, and the raw bytes are never exposed
 * except through the passphrase-encrypted backup ([ContentKeyBackup]) and the server
 * re-pairing flow, both of which the user explicitly starts. A key whose Keystore entry was
 * invalidated (device credential change, restore onto another phone) reads as absent, and
 * the service treats that as "no key — re-pair or restore from backup".
 *
 * User authentication is deliberately *not* required on the key, for the same reason as the
 * relay and proxy stores: the key must be usable whenever the app sends a message, and a
 * per-message biometric prompt would make the feature unusable in practice. The phone's
 * lock screen is the boundary here; the fingerprint step belongs to the passkey, which
 * gates *access*, while this key gates *readability of the words themselves*.
 */
@Singleton
class ContentKeyStore @Inject constructor() {

    /** The content key, generating it on first use. */
    fun key(): SecretKey {
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

    /** The content key if one exists, without creating one. */
    fun existingKey(): SecretKey? {
        val keyStore = KeyStore.getInstance(PROVIDER).apply { load(null) }
        return (keyStore.getEntry(ALIAS, null) as? KeyStore.SecretKeyEntry)?.secretKey
    }

    /** The raw bytes of the current key, for the passphrase-encrypted backup. Null when there is no key. */
    fun exportRaw(): ByteArray? = existingKey()?.encoded

    /**
     * Replace the stored key with [raw] bytes — the backup-restore and re-pairing paths.
     *
     * This is the one place raw key material is written: a restore the user pasted in, or a
     * re-issue from the server after a dsh-password login. It never generates a fresh key
     * on its own — a fresh key here would orphan every earlier encrypted message.
     */
    fun importRaw(raw: ByteArray) {
        val keyStore = KeyStore.getInstance(PROVIDER).apply { load(null) }
        keyStore.setEntry(ALIAS, KeyStore.SecretKeyEntry(SecretKeySpec(raw, "AES")), null)
    }

    /** Forget the key. The encrypted messages stay encrypted — including from their owner. */
    fun clear() {
        val keyStore = KeyStore.getInstance(PROVIDER).apply { load(null) }
        if (keyStore.containsAlias(ALIAS)) keyStore.deleteEntry(ALIAS)
    }

    private companion object {
        const val PROVIDER = "AndroidKeyStore"
        const val ALIAS = "dsh_content_key"
    }
}
