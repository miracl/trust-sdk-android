package com.miracl.trust.core

import com.miracl.trust.randomHexString
import org.junit.After
import org.junit.Assert
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File

class DeviceTagProviderUnitTest {

    @get:Rule
    val tempFolder = TemporaryFolder()

    private lateinit var file: File
    private lateinit var provider: DeviceTagProvider

    @Before
    fun setup() {
        file = tempFolder.newFile("miracl_device_tag")

        if (file.exists()) {
            file.delete()
        }

        val cacheField = DeviceTagProvider::class.java.getDeclaredField("cachedTag").apply {
            isAccessible = true
        }
        cacheField.set(null, null)

        provider = DeviceTagProvider(file)
    }

    @After
    fun tearDown() {
        if (file.exists()) {
            file.setWritable(true)
            file.setReadable(true)
        }
    }

    @Test
    fun `get should return existing valid tag without modifying it when tag already exists on disk`() {
        // Arrange
        val expectedTag = "1234567890abcdef1234567890abcdef"
        file.writeText(expectedTag)

        // Act
        val result = provider.get()

        // Assert
        Assert.assertEquals(expectedTag, result)
        Assert.assertEquals(expectedTag, file.readText().trim())
    }

    @Test
    fun `get should generate and persist a new tag when the file does not exist`() {
        // Arrange & Act
        val result = provider.get()

        // Assert
        Assert.assertEquals(32, result.length)
        Assert.assertTrue(result.all { it in '0'..'9' || it in 'a'..'f' })
        Assert.assertTrue(file.exists())
    }

    @Test
    fun `get should return the exact same tag on consecutive invocations`() {
        // Arrange
        val firstCallTag = provider.get()

        // Act
        val secondCallTag = provider.get()

        // Assert
        Assert.assertEquals(firstCallTag, secondCallTag)
    }

    @Test
    fun `get should return the same tag across different provider instances pointing to the same file`() {
        // Arrange
        val expectedTag = provider.get()
        val secondProvider = DeviceTagProvider(file)

        // Act
        val result = secondProvider.get()

        // Assert
        Assert.assertEquals(expectedTag, result)
    }

    @Test
    fun `get should return the tag from the shared process cache without touching the disk when a second instance is initialized`() {
        // Arrange
        val firstProvider = DeviceTagProvider(file)
        val expectedTag = firstProvider.get()
        val secondProvider = DeviceTagProvider(file)

        // Act
        file.delete()
        val result = secondProvider.get()

        // Assert
        Assert.assertEquals(expectedTag, result)
    }

    @Test
    fun `get should regenerate and persist a fresh tag when the existing file is corrupted`() {
        // Arrange
        val corruptedData = "INVALID_DATA"
        file.writeText(corruptedData)

        // Act
        val result = provider.get()

        // Assert
        Assert.assertEquals(32, result.length)
        Assert.assertTrue(result.all { it in '0'..'9' || it in 'a'..'f' })
        Assert.assertNotEquals(corruptedData, result)
        Assert.assertEquals(result, file.readText().trim())
    }

    @Test
    fun `get should regenerate and persist a fresh tag when the existing file is empty`() {
        // Arrange
        file.writeText("")

        // Act
        val result = provider.get()

        // Assert
        Assert.assertEquals(32, result.length)
        Assert.assertTrue(result.all { it in '0'..'9' || it in 'a'..'f' })
        Assert.assertEquals(result, file.readText().trim())
    }

    @Test
    fun `get should fallback to a volatile runtime tag and not crash when the file is not writable`() {
        // Arrange
        file.createNewFile()
        file.setWritable(false)

        // Act
        val result = provider.get()

        // Assert
        Assert.assertEquals(32, result.length)
        Assert.assertTrue(result.all { it in '0'..'9' || it in 'a'..'f' })
    }

    @Test
    fun `get should fallback to a volatile runtime tag and not crash when reading the file fails`() {
        // Arrange
        file.writeText("1234567890abcdef1234567890abcdef")
        randomHexString()
        file.setReadable(false)

        // Act
        val result = provider.get()

        // Assert
        Assert.assertEquals(32, result.length)
        Assert.assertTrue(result.all { it in '0'..'9' || it in 'a'..'f' })
    }
}