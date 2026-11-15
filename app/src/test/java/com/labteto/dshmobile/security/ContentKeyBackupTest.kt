package com.labteto.dshmobile.security

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ContentKeyBackupTest {

    @Test
    fun `export then import restores the same key`() {
        val key = ContentCrypto.generateKey()
        val blob = ContentKeyBackup.exportBackup(key, "correct horse battery staple")
        assertTrue(blob.startsWith(ContentKeyBackup.BACKUP_PREFIX))
        val result = ContentKeyBackup.importBackup(blob, "correct horse battery staple")
        assertTrue(result is BackupImportResult.Restored)
        val restored = (result as BackupImportResult.Restored).key
        assertEquals(key.encoded.toList(), restored.encoded.toList())
        assertEquals(ContentCrypto.fingerprint(key), ContentCrypto.fingerprint(restored))
    }

    @Test
    fun `a wrong passphrase is reported, not silently accepted`() {
        val key = ContentCrypto.generateKey()
        val blob = ContentKeyBackup.exportBackup(key, "correct horse battery staple")
        assertEquals(BackupImportResult.WrongPassphrase, ContentKeyBackup.importBackup(blob, "wrong passphrase"))
    }

    @Test
    fun `garbage is not a backup`() {
        assertEquals(BackupImportResult.NotABackup, ContentKeyBackup.importBackup("hello", "passphrase"))
        assertEquals(BackupImportResult.NotABackup, ContentKeyBackup.importBackup("dsh-key-backup-v1:not json", "passphrase"))
        assertEquals(BackupImportResult.NotABackup, ContentKeyBackup.importBackup("", "passphrase"))
    }

    @Test
    fun `a tampered backup fails the tag check`() {
        val key = ContentCrypto.generateKey()
        val blob = ContentKeyBackup.exportBackup(key, "passphrase")
        val tampered = blob.dropLast(2) + if (blob.last() == 'A') "B" else "A"
        val result = ContentKeyBackup.importBackup(tampered, "passphrase")
        assertTrue(result is BackupImportResult.WrongPassphrase || result is BackupImportResult.NotABackup)
    }
}
