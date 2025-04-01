package com.miracl.trust.util.log

import android.util.Log
import io.mockk.every
import io.mockk.mockkStatic
import io.mockk.verify
import org.junit.Before
import org.junit.Test

class DefaultLoggerUnitTest {
    @Before
    fun setUp() {
        mockkStatic(Log::class)
        every { Log.e(any(), any()) } returns 0
        every { Log.w(any(), ofType(String::class)) } returns 0
        every { Log.d(any(), any()) } returns 0
        every { Log.i(any(), any()) } returns 0
    }

    @Test
    fun `logger logs nothing errors when log level value is NONE`() {
        // Arrange
        val defaultLogger = DefaultLogger(Logger.LoggingLevel.NONE)

        // Act
        defaultLogger.error("", "")
        defaultLogger.warning("", "")
        defaultLogger.info("", "")
        defaultLogger.debug("", "")

        // Assert
        verify(exactly = 0) { Log.e(any(), any()) }
        verify(exactly = 0) { Log.w(any(), ofType(String::class)) }
        verify(exactly = 0) { Log.i(any(), any()) }
        verify(exactly = 0) { Log.d(any(), any()) }
    }

    @Test
    fun `logger logs only errors when log level value is ERROR`() {
        // Arrange
        val defaultLogger = DefaultLogger(Logger.LoggingLevel.ERROR)

        // Act
        defaultLogger.error("", "")
        defaultLogger.warning("", "")
        defaultLogger.info("", "")
        defaultLogger.debug("", "")

        // Assert
        verify { Log.e(any(), any()) }
        verify(exactly = 0) { Log.w(any(), ofType(String::class)) }
        verify(exactly = 0) { Log.i(any(), any()) }
        verify(exactly = 0) { Log.d(any(), any()) }
    }

    @Test
    fun `logger logs only errors and warning when log level value is WARNING`() {
        // Arrange
        val defaultLogger = DefaultLogger(Logger.LoggingLevel.WARNING)

        // Act
        defaultLogger.error("", "")
        defaultLogger.warning("", "")
        defaultLogger.info("", "")
        defaultLogger.debug("", "")

        // Assert
        verify { Log.e(any(), any()) }
        verify { Log.w(any(), ofType(String::class)) }
        verify(exactly = 0) { Log.i(any(), any()) }
        verify(exactly = 0) { Log.d(any(), any()) }
    }

    @Test
    fun `logger logs only errors, warning and info when log level value is INFO`() {
        // Arrange
        val defaultLogger = DefaultLogger(Logger.LoggingLevel.INFO)

        // Act
        defaultLogger.error("", "")
        defaultLogger.warning("", "")
        defaultLogger.info("", "")
        defaultLogger.debug("", "")

        // Assert
        verify { Log.e(any(), any()) }
        verify { Log.w(any(), ofType(String::class)) }
        verify { Log.i(any(), any()) }
        verify(exactly = 0) { Log.d(any(), any()) }
    }

    @Test
    fun `logger logs everything when log level value is DEBUG`() {
        // Arrange
        val defaultLogger = DefaultLogger(Logger.LoggingLevel.DEBUG)

        // Act
        defaultLogger.error("", "")
        defaultLogger.warning("", "")
        defaultLogger.info("", "")
        defaultLogger.debug("", "")

        // Assert
        verify { Log.e(any(), any()) }
        verify { Log.w(any(), ofType(String::class)) }
        verify { Log.i(any(), any()) }
        verify { Log.d(any(), any()) }
    }
}