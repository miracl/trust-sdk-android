package com.miracl.trust.core

import android.content.Context
import com.miracl.trust.util.toHexString
import java.io.File
import java.security.SecureRandom

internal class DeviceTagProvider(private val file: File) {

    fun get(): String {
        cachedTag?.let { return it }

        synchronized(LOCK) {
            cachedTag?.let { return it }

            val tag = try {
                if (file.exists()) {
                    val stored = file.readText(Charsets.UTF_8).trim()

                    if (isValidTag(stored)) {
                        stored
                    } else {
                        createAndPersist(file)
                    }
                } else {
                    createAndPersist(file)
                }
            } catch (_: Exception) {
                createAndPersist(file)
            }

            cachedTag = tag
            return tag
        }
    }

    private fun createAndPersist(file: File): String {
        val tag = generateTag()

        try {
            file.writeText(tag, Charsets.UTF_8)
        } catch (_: Exception) {
            // Ignore persistence failure.
        }

        return tag
    }

    private fun isValidTag(value: String): Boolean {
        return value.length == ID_LENGTH &&
                value.all { it in '0'..'9' || it in 'a'..'f' }
    }

    private fun generateTag(): String {
        val data = ByteArray(16)
        SecureRandom().nextBytes(data)

        return data.toHexString()
    }

    internal companion object {
        private const val FILE_NAME = "miracl_device_tag"
        private const val ID_LENGTH = 32

        private val LOCK = Any()

        @Volatile
        private var cachedTag: String? = null

        fun create(context: Context): DeviceTagProvider {
            val file = File(context.applicationContext.noBackupFilesDir, FILE_NAME)
            return DeviceTagProvider(file)
        }
    }
}