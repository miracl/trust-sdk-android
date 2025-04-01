package com.miracl.trust.util

import com.miracl.trust.randomNumericPin
import com.miracl.trust.randomPinLength
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.runTest
import org.junit.Assert
import org.junit.Test

class PinUtilTest {
    @OptIn(ExperimentalCoroutinesApi::class)
    @Test
    fun `acquirePin returns what the pinProvider provides`() =
        runTest {
            // Arrange
            val pin = randomNumericPin(randomPinLength())
            // Act
            val acquiredPin = acquirePin { it.consume(pin) }

            // Assert
            Assert.assertEquals(pin, acquiredPin)
        }
}