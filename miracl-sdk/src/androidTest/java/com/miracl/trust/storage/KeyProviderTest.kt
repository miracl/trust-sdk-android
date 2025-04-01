package com.miracl.trust.storage

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import com.miracl.trust.storage.security.KeyProtector
import com.miracl.trust.storage.security.KeyProvider
import org.junit.Assert
import org.junit.Before
import org.junit.Test
import java.io.File

class KeyProviderTest {
    companion object {
        private const val STORAGE_KEY_FILE_NAME = "miracl_storage_key.txt"

        private const val STORAGE_PREFERENCES = "storage_preferences"
        private const val STORAGE_KEY_ID = "storage_key"
    }

    private val context: Context = ApplicationProvider.getApplicationContext()
    private val storagePreferences =
        context.getSharedPreferences(STORAGE_PREFERENCES, Context.MODE_PRIVATE)
    private val keyProtector = KeyProtector(context)
    private val keyProvider = KeyProvider(context, storagePreferences, keyProtector)

    @Before
    fun cleanUp() {
        storagePreferences.edit().clear().apply()
        File(context.noBackupFilesDir, STORAGE_KEY_FILE_NAME).delete()
    }

    @Test
    fun testStorageKeyIsWriteAndReadFromNoBackupFilesDirOnApiLevel21AndAbove() {
        // Act
        val storageKey = keyProvider.storageKey

        // Assert
        Assert.assertArrayEquals(storageKey, keyProvider.storageKey)
        Assert.assertTrue(File(context.noBackupFilesDir, STORAGE_KEY_FILE_NAME).exists())
        Assert.assertFalse(storagePreferences.contains(STORAGE_KEY_ID))
    }

    @Test
    fun testMigratingStorageKeyFromPreferencesToNoBackupFilesDirOnApiLevel21AndAbove() {
        // Arrange
        val encryptedStorageKey = keyProtector.createStorageKey()
        storagePreferences.edit()
            .putString(STORAGE_KEY_ID, String(encryptedStorageKey, Charsets.ISO_8859_1))
            .commit()

        // Act
        val storageKey = keyProvider.storageKey

        // Assert
        Assert.assertArrayEquals(keyProtector.decryptStorageKey(encryptedStorageKey), storageKey)
        Assert.assertTrue(File(context.noBackupFilesDir, STORAGE_KEY_FILE_NAME).exists())
        Assert.assertFalse(storagePreferences.contains(STORAGE_KEY_ID))
    }
}