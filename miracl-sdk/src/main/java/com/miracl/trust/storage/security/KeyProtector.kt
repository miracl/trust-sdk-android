package com.miracl.trust.storage.security

import android.content.Context
import android.os.Build
import android.security.KeyPairGeneratorSpec
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import androidx.annotation.RequiresApi
import java.math.BigInteger
import java.nio.ByteBuffer
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.SecureRandom
import java.util.*
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.security.auth.x500.X500Principal

internal class KeyProtector(private val context: Context) {
    companion object {
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val STORAGE_SECURITY_KEY_ALIAS = "storage_security_key"

        private const val AES_ALGORITHM_MODE = "AES/GCM/NoPadding";
        private const val GCM_TAG_LENGTH = 128
        private const val IV_LENGTH = 12

        private const val RSA_ALGORITHM_NAME = "RSA"
        private const val RSA_ALGORITHM_MODE = "RSA/ECB/PKCS1Padding";
    }

    private val randomIV: ByteArray
        get() = ByteArray(IV_LENGTH)
            .apply { SecureRandom().nextBytes(this) }

    fun createStorageKey(): ByteArray {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
            createKeyPair()
            val secureRandom = SecureRandom()
            val storageKey = Base64.encode(secureRandom.generateSeed(64), 0)

            return rsaEncryptStorageKey(storageKey, loadPrivateKeyEntry())
        }

        val secureKey = createSecureKey()
        val storageKey = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES).generateKey()

        return aesEncryptStorageKey(storageKey, secureKey)
    }

    fun decryptStorageKey(encryptedStorageKey: ByteArray): ByteArray {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
            return rsaDecryptStorageKey(encryptedStorageKey)
        }

        return aesDecryptStorageKey(encryptedStorageKey)
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    private fun createSecureKey(): SecretKey {
        val keyGenParameterSpec = KeyGenParameterSpec.Builder(
            STORAGE_SECURITY_KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setRandomizedEncryptionRequired(false)
            .build()

        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
            .apply { init(keyGenParameterSpec) }
            .generateKey()
    }

    @Suppress("DEPRECATION")
    private fun createKeyPair(): KeyPair {
        val startDate = GregorianCalendar()
        val endDate = GregorianCalendar()
        endDate.add(Calendar.YEAR, 25)

        val parameterSpec: KeyPairGeneratorSpec =
            KeyPairGeneratorSpec.Builder(context).run {
                setAlias(STORAGE_SECURITY_KEY_ALIAS)
                setSubject(X500Principal("CN=${STORAGE_SECURITY_KEY_ALIAS}"))
                setSerialNumber(BigInteger.valueOf(777))
                setStartDate(startDate.time)
                setEndDate(endDate.time)
                build()
            }

        val keyPairGenerator: KeyPairGenerator =
            KeyPairGenerator.getInstance(RSA_ALGORITHM_NAME, ANDROID_KEYSTORE)
        keyPairGenerator.initialize(parameterSpec)

        return keyPairGenerator.genKeyPair()
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    private fun aesEncryptStorageKey(storageKey: SecretKey, secureKey: SecretKey): ByteArray {
        val cipher = Cipher.getInstance(AES_ALGORITHM_MODE)
        val iv = randomIV
        val gcmParameterSpec = GCMParameterSpec(GCM_TAG_LENGTH, iv)
        cipher.init(Cipher.ENCRYPT_MODE, secureKey, gcmParameterSpec)
        val encryptedKey = cipher.doFinal(storageKey.encoded)

        return ByteBuffer.allocate(iv.size + encryptedKey.size)
            .put(iv)
            .put(encryptedKey)
            .array()
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    private fun aesDecryptStorageKey(encryptedStorageKey: ByteArray): ByteArray {
        val cipher = Cipher.getInstance(AES_ALGORITHM_MODE)
        val gcmParameterSpec =
            GCMParameterSpec(GCM_TAG_LENGTH, encryptedStorageKey, 0, IV_LENGTH)
        val secureKey = loadSecureKey()

        cipher.init(Cipher.DECRYPT_MODE, secureKey, gcmParameterSpec)

        return cipher.doFinal(
            encryptedStorageKey,
            IV_LENGTH,
            encryptedStorageKey.size - IV_LENGTH
        )
    }

    private fun rsaEncryptStorageKey(
        storageKey: ByteArray,
        privateKeyEntry: KeyStore.PrivateKeyEntry
    ): ByteArray {
        val cipher: Cipher = Cipher.getInstance(RSA_ALGORITHM_MODE)
        cipher.init(Cipher.ENCRYPT_MODE, privateKeyEntry.certificate.publicKey)

        val arr = cipher.doFinal(storageKey)

        return Base64.encode(arr, Base64.DEFAULT)
    }

    private fun rsaDecryptStorageKey(encryptedStorageKey: ByteArray): ByteArray {
        val privateKeyEntry: KeyStore.PrivateKeyEntry = loadPrivateKeyEntry()

        val cipher: Cipher = Cipher.getInstance(RSA_ALGORITHM_MODE)
        cipher.init(Cipher.DECRYPT_MODE, privateKeyEntry.privateKey)

        return cipher.doFinal(Base64.decode(encryptedStorageKey, Base64.DEFAULT))
    }

    private fun loadSecureKey(): SecretKey {
        val keyStore: KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
            .apply {
                load(null)
            }

        val entry = keyStore.getEntry(STORAGE_SECURITY_KEY_ALIAS, null)
                as KeyStore.SecretKeyEntry

        return entry.secretKey
    }

    private fun loadPrivateKeyEntry(): KeyStore.PrivateKeyEntry {
        val keyStore: KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
            .apply {
                load(null)
            }

        return keyStore.getEntry(STORAGE_SECURITY_KEY_ALIAS, null)
                as KeyStore.PrivateKeyEntry
    }
}