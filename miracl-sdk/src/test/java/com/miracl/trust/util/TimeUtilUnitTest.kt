package com.miracl.trust.util

import org.junit.Assert
import org.junit.Test
import java.util.*
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.DurationUnit
import kotlin.time.ExperimentalTime

class TimeUtilUnitTest {

    @ExperimentalTime
    @Test
    fun testSecondsSince1970ReturnsIntSeconds() {
        val testDate = Date()

        Assert.assertEquals((testDate.time / 1000).toInt(), testDate.secondsSince1970())
        Assert.assertEquals(
            testDate.time.milliseconds.toInt(DurationUnit.SECONDS),
            testDate.secondsSince1970()
        )
    }
}