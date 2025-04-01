package com.miracl.trust.storage.security

import android.content.Context
import android.content.SharedPreferences
import android.util.AndroidException
import androidx.annotation.VisibleForTesting
import java.io.File
import java.io.FileInputStream
import java.io.IOException
import java.lang.Exception

internal class KeyProvider(
    private val context: Context,
    private val storagePreferences: SharedPreferences,
    private val keyProtector: KeyProtector
) {
    companion object {
        private const val STORAGE_KEY_FILE_NAME = "miracl_storage_key.txt"
        private const val STORAGE_KEY_ID = "storage_key"

        private const val ERROR_UNABLE_TO_WRITE_KEY = "Unable to save the DB key into the storage."
        private const val ERROR_UNABLE_TO_READ_KEY = "Unable to get the DB key from the storage."
    }

    val storageKey: ByteArray
        get() {
            var storageKey = readStorageKey()

            if (storageKey == null) {
                storageKey = keyProtector.createStorageKey()
                writeStorageKey(storageKey)
            }

            return keyProtector.decryptStorageKey(storageKey)
        }

    @VisibleForTesting
    fun readStorageKey(): ByteArray? {
        if (storagePreferences.contains(STORAGE_KEY_ID)) {
            val storageKey = getKeyFromSharedPreference()
            return try {
                writeStorageKey(storageKey)
                storagePreferences.edit().clear().apply()
                storageKey
            } catch (ex: Exception) {
                storageKey
            }
        }

        val storageKeyFile = File(context.noBackupFilesDir, STORAGE_KEY_FILE_NAME)

        if (!storageKeyFile.exists()) {
            return null
        }

        try {
            FileInputStream(storageKeyFile).use {
                return it.readBytes()
            }
        } catch (ex: IOException) {
            throw AndroidException(ERROR_UNABLE_TO_READ_KEY)
        }
    }

    @VisibleForTesting
    fun writeStorageKey(encryptedStorageKey: ByteArray) {
        val storageKeyFile = File(context.noBackupFilesDir, STORAGE_KEY_FILE_NAME)

        try {
            encryptedStorageKey.inputStream().use { input ->
                storageKeyFile.outputStream().use { output ->
                    input.copyTo(output)
                }
            }
        } catch (exception: IOException) {
            throw AndroidException(ERROR_UNABLE_TO_WRITE_KEY)
        }
    }

    private fun getKeyFromSharedPreference() =
        storagePreferences
            .getString(STORAGE_KEY_ID, null)?.decodeToByteArray()
            ?: throw NoSuchElementException(ERROR_UNABLE_TO_READ_KEY)

    private fun String.decodeToByteArray(): ByteArray {
        return this.toByteArray(Charsets.ISO_8859_1)
    }
}