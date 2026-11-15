package com.labteto.dshmobile.security

import com.labteto.dshmobile.core.wire.WireJson
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import java.security.SecureRandom
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

/** Why a backup import refused to restore a key. */
sealed interface BackupImportResult {
    data class Restored(val key: SecretKey) : BackupImportResult
    /** The blob is not a backup at all, or was damaged. */
    data object NotABackup : BackupImportResult
    /** The blob is a backup, but the passphrase is wrong (or it was made under another key). */
    data object WrongPassphrase : BackupImportResult
}

/**
 * A passphrase-encrypted backup of the content key.
 *
 * The backup is one line of text the user can copy into a password manager or write down:
 *
 *     dsh-key-backup-v1:{"v":1,"kdf":"PBKDF2-HmacSHA256","iter":120000,"salt":"…","iv":"…","ct":"…"}
 *
 * The passphrase never leaves the phone, and the server never sees this blob — it is a
 * phone-local backup for the day the Keystore entry is gone (new phone, credential reset).
 * The KDF cost (120,000 iterations of PBKDF2-HmacSHA256) is the defence against guessing:
 * a short passphrase is still guessable, so the Settings backup dialog says so plainly.
 *
 * This is the *local* backup. The other backup is re-pairing: after a dsh-password login
 * the server re-issues the same key it already holds ([ContentEncryptionService.repairKey]).
 * Either path restores the same key — never a fresh one — because a fresh key would make
 * every earlier encrypted message unreadable. Losing the key *and* the backup *and* the
 * server copy means the encrypted messages are unreadable by anyone, including their owner;
 * the app says that on the backup screen rather than hiding it.
 */
object ContentKeyBackup {
    const val BACKUP_PREFIX = "dsh-key-backup-v1:"
    private const val KDF = "PBKDF2WithHmacSHA256"
    private const val KDF_ITERATIONS = 120_000
    private const val SALT_BYTES = 32
    private const val IV_BYTES = 12
    private const val TAG_BITS = 128
    private const val TRANSFORMATION = "AES/GCM/NoPadding"

    /** Wrap [key]'s raw bytes under [passphrase]; the result is one copyable line. */
    fun exportBackup(key: SecretKey, passphrase: String): String {
        val raw = key.encoded ?: throw IllegalStateException("key has no exportable bytes")
        val salt = ByteArray(SALT_BYTES).also { SecureRandom().nextBytes(it) }
        val iv = ByteArray(IV_BYTES).also { SecureRandom().nextBytes(it) }
        val wrapping = deriveKey(passphrase, salt)
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, wrapping, GCMParameterSpec(TAG_BITS, iv))
        val body = cipher.doFinal(raw)
        val json = WireJson.encodeToString(
            JsonObject.serializer(),
            buildJsonObject {
                put("v", 1)
                put("kdf", "PBKDF2-HmacSHA256")
                put("iter", KDF_ITERATIONS)
                put("salt", salt.toBase64Url())
                put("iv", iv.toBase64Url())
                put("ct", body.toBase64Url())
            },
        )
        return BACKUP_PREFIX + json
    }

    /** Unwrap a backup line made by [exportBackup]. Never throws; the reason is the answer. */
    fun importBackup(blob: String, passphrase: String): BackupImportResult {
        if (!blob.startsWith(BACKUP_PREFIX)) return BackupImportResult.NotABackup
        val root = runCatching {
            WireJson.parseToJsonElement(blob.removePrefix(BACKUP_PREFIX)).jsonObject
        }.getOrNull() ?: return BackupImportResult.NotABackup
        if (root["v"]?.jsonPrimitive?.content != "1") return BackupImportResult.NotABackup
        val salt = runCatching { root["salt"]?.jsonPrimitive?.content?.base64UrlToBytes() }.getOrNull()
            ?: return BackupImportResult.NotABackup
        val iv = runCatching { root["iv"]?.jsonPrimitive?.content?.base64UrlToBytes() }.getOrNull()
            ?: return BackupImportResult.NotABackup
        val body = runCatching { root["ct"]?.jsonPrimitive?.content?.base64UrlToBytes() }.getOrNull()
            ?: return BackupImportResult.NotABackup
        return runCatching {
            val wrapping = deriveKey(passphrase, salt)
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.DECRYPT_MODE, wrapping, GCMParameterSpec(TAG_BITS, iv))
            BackupImportResult.Restored(ContentCrypto.keyFromBytes(cipher.doFinal(body)))
        }.getOrElse { cause ->
            if (cause is AEADBadTagException) BackupImportResult.WrongPassphrase
            else BackupImportResult.NotABackup
        }
    }

    private fun deriveKey(passphrase: String, salt: ByteArray): SecretKey {
        val factory = SecretKeyFactory.getInstance(KDF)
        val spec = PBEKeySpec(passphrase.toCharArray(), salt, KDF_ITERATIONS, 256)
        return SecretKeySpec(factory.generateSecret(spec).encoded, "AES")
    }
}
