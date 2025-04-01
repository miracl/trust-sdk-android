package com.miracl.trust.util

import org.junit.Assert
import org.junit.Test

class HashUtilUnitTest {
    @Test
    fun `toSHA256 should return a SHA-256 hash of a byte array`() {
        // Arrange
        val input = "abc".toByteArray()
        val expectedValue = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

        // Act
        val result = input.toSHA256()

        // Assert
        Assert.assertEquals(expectedValue, result)
    }
}
