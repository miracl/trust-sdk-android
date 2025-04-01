package com.miracl.trust.user_storage

import android.content.Context
import android.content.SharedPreferences
import android.util.AndroidException
import com.miracl.trust.storage.security.KeyProtector
import com.miracl.trust.storage.security.KeyProvider
import io.mockk.clearAllMocks
import io.mockk.every
import io.mockk.just
import io.mockk.mockk
import io.mockk.runs
import io.mockk.spyk
import io.mockk.verify
import org.junit.Assert
import org.junit.Before
import org.junit.Test

class KeyProviderUnitTest {
    companion object {
        private const val stringEncodedKey = "Hello World"
        private val byteArrayDecodedKey =
            byteArrayOf(72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100)

        private const val STORAGE_KEY_ID = "storage_key"
    }

    private val contextMock = mockk<Context>()
    private val storagePreferencesMock = mockk<SharedPreferences>()
    private val keyProtectorMock = mockk<KeyProtector>()

    @Before
    fun setUp() {
        clearAllMocks()
    }

    @Test
    fun `returns decrypted storage key from NoBackupFilesDir when key already exists`() {
        // Arrange
        val keyProviderSpy =
            spyk(KeyProvider(contextMock, storagePreferencesMock, keyProtectorMock))
        every { keyProviderSpy.readStorageKey() } returns byteArrayDecodedKey

        val decryptedKey = byteArrayOf(1, 2, 3)
        every { keyProtectorMock.decryptStorageKey(byteArrayDecodedKey) } returns decryptedKey

        // Act
        val result = keyProviderSpy.storageKey

        // Assert
        verify { keyProtectorMock.decryptStorageKey(byteArrayDecodedKey) }
        Assert.assertArrayEquals(decryptedKey, result)
    }

    @Test
    fun `returns decrypted storage key which is newly generated and save it in NoBackupFilesDir`() {
        // Arrange
        val keyProviderSpy =
            spyk(KeyProvider(contextMock, storagePreferencesMock, keyProtectorMock))

        every { keyProviderSpy.readStorageKey() } returns null
        every { keyProtectorMock.createStorageKey() } returns byteArrayDecodedKey
        every { keyProviderSpy.writeStorageKey(byteArrayDecodedKey) } just runs

        val decryptedKey = byteArrayOf(1, 2, 3)
        every { keyProtectorMock.decryptStorageKey(byteArrayDecodedKey) } returns decryptedKey

        // Act
        val result = keyProviderSpy.storageKey

        // Assert
        verify { keyProtectorMock.createStorageKey() }
        verify { keyProviderSpy.writeStorageKey(byteArrayDecodedKey) }
        verify { keyProtectorMock.decryptStorageKey(byteArrayDecodedKey) }

        Assert.assertArrayEquals(decryptedKey, result)
    }

    @Test
    fun `moves decrypted storage key from shared preferences to NoBackupFilesDir when key already exists`() {
        // Arrange
        val keyProviderSpy =
            spyk(KeyProvider(contextMock, storagePreferencesMock, keyProtectorMock))

        every { storagePreferencesMock.contains(STORAGE_KEY_ID) } returns true
        every {
            storagePreferencesMock.getString(
                STORAGE_KEY_ID,
                any()
            )
        } returns stringEncodedKey

        every { keyProviderSpy.writeStorageKey(byteArrayDecodedKey) } just runs

        val decryptedKey = byteArrayOf(1, 2, 3)
        every { keyProtectorMock.decryptStorageKey(byteArrayDecodedKey) } returns decryptedKey

        // Act
        val result = keyProviderSpy.storageKey

        // Assert
        verify { keyProviderSpy.writeStorageKey(byteArrayDecodedKey) }
        verify { keyProtectorMock.decryptStorageKey(byteArrayDecodedKey) }
        Assert.assertArrayEquals(decryptedKey, result)
    }

    @Test
    fun `returns decrypted storage key from shared preferences when move fails`() {
        // Arrange
        val keyProviderSpy =
            spyk(KeyProvider(contextMock, storagePreferencesMock, keyProtectorMock))

        every { storagePreferencesMock.contains(STORAGE_KEY_ID) } returns true
        every {
            storagePreferencesMock.getString(
                STORAGE_KEY_ID,
                any()
            )
        } returns stringEncodedKey

        every { keyProviderSpy.writeStorageKey(byteArrayDecodedKey) } throws AndroidException(
            "Unable to save the DB key into the storage."
        )

        val decryptedKey = byteArrayOf(1, 2, 3)
        every { keyProtectorMock.decryptStorageKey(byteArrayDecodedKey) } returns decryptedKey

        // Act
        val result = keyProviderSpy.storageKey

        // Assert
        verify { keyProviderSpy.writeStorageKey(byteArrayDecodedKey) }
        verify { keyProtectorMock.decryptStorageKey(byteArrayDecodedKey) }
        Assert.assertArrayEquals(decryptedKey, result)
    }

    @Test(expected = NoSuchElementException::class)
    fun `throws exception if fails to get the key from the shared preferences`() {
        // Arrange
        every { storagePreferencesMock.contains(STORAGE_KEY_ID) } returns true
        every {
            storagePreferencesMock.getString(
                STORAGE_KEY_ID,
                any()
            )
        } returns null

        val keyProvider = KeyProvider(contextMock, storagePreferencesMock, keyProtectorMock)

        // Act
        keyProvider.storageKey
    }
}