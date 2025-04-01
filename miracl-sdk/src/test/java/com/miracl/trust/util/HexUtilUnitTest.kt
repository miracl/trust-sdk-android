package com.miracl.trust.util

import org.junit.Assert
import org.junit.Test

class HexUtilUnitTest {
    private val hexCharactersRegEx = "-?[0-9a-fA-F]{2}".toRegex()

    @Test
    fun `toHexString should convert a byte array to its hex representation`() {
        // Arrange
        val bytes = byteArrayOf(2, 5, 23, 64, 244.toByte())

        // Act
        val result = bytes.toHexString()

        // Assert
        result.chunked(2).forEach {
            Assert.assertTrue(it.matches(hexCharactersRegEx))
        }
    }

    @Test
    fun `hexStringToByteArray should convert a hex string to a byte array representation`() {
        // Arrange
        val hex = "02051740f4"
        val expectedBytes = byteArrayOf(2, 5, 23, 64, 244.toByte())

        // Act
        val result = hex.hexStringToByteArray()

        // Assert
        for (index in 0 until result.count()) {
            Assert.assertEquals(expectedBytes[index], result[index])
        }
    }
}
