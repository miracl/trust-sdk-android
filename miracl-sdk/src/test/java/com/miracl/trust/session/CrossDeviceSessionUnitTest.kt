package com.miracl.trust.session

import com.miracl.trust.randomHexString
import com.miracl.trust.randomUuidString
import org.junit.Assert
import org.junit.Test

class CrossDeviceSessionUnitTest {
    @Test
    fun `type should be Authentication when signing hash is empty`() {
        // Arrange
        val session = CrossDeviceSession(
            sessionId = randomUuidString(),
            sessionDescription = randomUuidString(),
            userId = randomUuidString(),
            projectId = randomUuidString(),
            signingHash = ""
        )

        // Assert
        Assert.assertEquals(CrossDeviceSessionType.Authentication, session.type)
    }

    @Test
    fun `type should return Signing when signing hash is not empty`() {
        // Arrange
        val session = CrossDeviceSession(
            sessionId = randomUuidString(),
            sessionDescription = randomUuidString(),
            userId = randomUuidString(),
            projectId = randomUuidString(),
            signingHash = randomHexString()
        )

        // Assert
        Assert.assertEquals(CrossDeviceSessionType.Signing, session.type)
    }
}