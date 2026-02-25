package com.miracl.trust.session

import android.net.Uri
import com.miracl.trust.MIRACLError
import com.miracl.trust.MIRACLSuccess
import com.miracl.trust.randomUuidString
import io.mockk.clearAllMocks
import io.mockk.coEvery
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkClass
import io.mockk.mockkStatic
import kotlinx.coroutines.test.runTest
import org.junit.Assert
import org.junit.Before
import org.junit.Test

class CrossDeviceSessionManagerUnitTest {
    private val sessionId = randomUuidString()
    private val crossDeviceSessionResponse = createCrossDeviceSessionResponse()
    private val crossDeviceSession = createCrossDeviceSession()

    private val sessionApiMock = mockk<CrossDeviceSessionApi>()
    private val sessionManager = CrossDeviceSessionManager(sessionApiMock)

    @Before
    fun setUp() {
        clearAllMocks()
    }

    @Test
    fun `getCrossDeviceSessionFromAppLink should return MIRACLSuccess`() =
        runTest {
            // Arrange
            val appLinkMock = mockkClass(Uri::class)
            every { appLinkMock.fragment } returns sessionId

            coEvery {
                sessionApiMock.executeGetSessionRequest(sessionId)
            } returns MIRACLSuccess(crossDeviceSessionResponse)

            // Act
            val result = sessionManager.getCrossDeviceSessionFromAppLink(appLinkMock)

            // Assert
            Assert.assertTrue(result is MIRACLSuccess)

            Assert.assertEquals(sessionId, (result as MIRACLSuccess).value.sessionId)
            Assert.assertEquals(crossDeviceSessionResponse.description, result.value.sessionDescription)
            Assert.assertEquals(crossDeviceSessionResponse.prerollId, result.value.userId)
            Assert.assertEquals(crossDeviceSessionResponse.projectId, result.value.projectId)
            Assert.assertEquals(crossDeviceSessionResponse.hash, result.value.signingHash)
        }

    @Test
    fun `getCrossDeviceSessionFromAppLink should return MIRACLError when codeStatusRequest fails`() =
        runTest {
            // Arrange
            val appLinkMock = mockkClass(Uri::class)
            every { appLinkMock.fragment } returns sessionId

            val sessionManagementException =
                CrossDeviceSessionException.GetCrossDeviceSessionFail(null)
            coEvery {
                sessionApiMock.executeGetSessionRequest(sessionId)
            } returns MIRACLError(sessionManagementException)

            // Act
            val result = sessionManager.getCrossDeviceSessionFromAppLink(appLinkMock)

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertEquals(sessionManagementException, (result as MIRACLError).value)
        }

    @Test
    fun `getCrossDeviceSessionFromAppLink should return MIRACLError when appLink is invalid`() =
        runTest {
            // Arrange
            val appLinkMock = mockkClass(Uri::class)
            every { appLinkMock.fragment } returns null

            // Act
            val result = sessionManager.getCrossDeviceSessionFromAppLink(appLinkMock)

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertEquals(
                CrossDeviceSessionException.InvalidAppLink,
                (result as MIRACLError).value
            )
        }

    @Test
    fun `getCrossDeviceSessionFromQRCode should return MIRACLSuccess`() =
        runTest {
            // Arrange
            val qrCode = "https://mcl.mpin.io/mobile-login/#$sessionId"
            val uriMock = mockkClass(Uri::class)

            mockkStatic(Uri::class)
            every { Uri.parse(qrCode) } returns uriMock
            every { uriMock.fragment } returns sessionId

            coEvery {
                sessionApiMock.executeGetSessionRequest(sessionId)
            } returns MIRACLSuccess(crossDeviceSessionResponse)

            // Act
            val result = sessionManager.getCrossDeviceSessionFromQRCode(qrCode)

            // Assert
            Assert.assertTrue(result is MIRACLSuccess)
        }

    @Test
    fun `getCrossDeviceSessionFromQRCode should return MIRACLError when codeStatusRequest fails`() =
        runTest {
            // Arrange
            val qrCode = "https://mcl.mpin.io/mobile-login/#$sessionId"
            val uriMock = mockkClass(Uri::class)

            mockkStatic(Uri::class)
            every { Uri.parse(qrCode) } returns uriMock
            every { uriMock.fragment } returns sessionId

            val sessionManagementException =
                CrossDeviceSessionException.GetCrossDeviceSessionFail(null)
            coEvery {
                sessionApiMock.executeGetSessionRequest(sessionId)
            } returns MIRACLError(sessionManagementException)

            // Act
            val result = sessionManager.getCrossDeviceSessionFromQRCode(qrCode)

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertEquals(sessionManagementException, (result as MIRACLError).value)
        }

    @Test
    fun `getCrossDeviceSessionFromQRCode should return MIRACLError when qrCode is invalid`() =
        runTest {
            // Arrange
            val qrCode = "https://mcl.mpin.io/mobile-login"
            val uriMock = mockkClass(Uri::class)

            mockkStatic(Uri::class)
            every { Uri.parse(qrCode) } returns uriMock
            every { uriMock.fragment } returns null

            // Act
            val result = sessionManager.getCrossDeviceSessionFromQRCode(qrCode)

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertEquals(
                CrossDeviceSessionException.InvalidQRCode,
                (result as MIRACLError).value
            )
        }

    @Test
    fun `getCrossDeviceSessionFromNotificationPayload should return MIRACLSuccess`() =
        runTest {
            // Arrange
            val qrUrl = "https://mcl.mpin.io/mobile-login/#$sessionId"
            val payload = mapOf(
                SessionManager.PUSH_NOTIFICATION_QR_URL to qrUrl
            )
            val uriMock = mockkClass(Uri::class)

            mockkStatic(Uri::class)
            every { Uri.parse(qrUrl) } returns uriMock
            every { uriMock.fragment } returns sessionId

            coEvery {
                sessionApiMock.executeGetSessionRequest(sessionId)
            } returns MIRACLSuccess(crossDeviceSessionResponse)

            // Act
            val result = sessionManager.getCrossDeviceSessionFromNotificationPayload(payload)

            // Assert
            Assert.assertTrue(result is MIRACLSuccess)
        }

    @Test
    fun `getCrossDeviceSessionFromNotificationPayload should return MIRACLError when codeStatusRequest fails`() =
        runTest {
            // Arrange
            val qrUrl = "https://mcl.mpin.io/mobile-login/#$sessionId"
            val payload = mapOf(
                SessionManager.PUSH_NOTIFICATION_QR_URL to qrUrl
            )
            val uriMock = mockkClass(Uri::class)

            mockkStatic(Uri::class)
            every { Uri.parse(qrUrl) } returns uriMock
            every { uriMock.fragment } returns sessionId

            val sessionManagementException =
                CrossDeviceSessionException.GetCrossDeviceSessionFail(null)
            coEvery {
                sessionApiMock.executeGetSessionRequest(sessionId)
            } returns MIRACLError(sessionManagementException)

            // Act
            val result = sessionManager.getCrossDeviceSessionFromNotificationPayload(payload)

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertEquals(sessionManagementException, (result as MIRACLError).value)
        }

    @Test
    fun `getCrossDeviceSessionFromNotificationPayload should return MIRACLError when payload doesn't contain qrURL`() =
        runTest {
            // Arrange
            val payload = mapOf<String, String>()

            // Act
            val result = sessionManager.getCrossDeviceSessionFromNotificationPayload(payload)

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertEquals(
                CrossDeviceSessionException.InvalidNotificationPayload,
                (result as MIRACLError).value
            )
        }

    @Test
    fun `getCrossDeviceSessionFromNotificationPayload should return MIRACLError when payload contains invalid qrURL`() =
        runTest {
            // Arrange
            val qrUrl = "https://mcl.mpin.io/mobile-login"
            val payload = mapOf(
                SessionManager.PUSH_NOTIFICATION_QR_URL to qrUrl
            )
            val uriMock = mockkClass(Uri::class)

            mockkStatic(Uri::class)
            every { Uri.parse(qrUrl) } returns uriMock
            every { uriMock.fragment } returns null

            // Act
            val result = sessionManager.getCrossDeviceSessionFromNotificationPayload(payload)

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertEquals(
                CrossDeviceSessionException.InvalidNotificationPayload,
                (result as MIRACLError).value
            )
        }

    @Test
    fun `abortSession should return MIRACLSuccess`() =
        runTest {
            // Arrange
            coEvery {
                sessionApiMock.executeAbortSessionRequest(sessionId)
            } returns MIRACLSuccess(Unit)

            // Act
            val result = sessionManager.abortSession(crossDeviceSession)

            // Assert
            Assert.assertTrue(result is MIRACLSuccess)
        }

    @Test
    fun `abortSession should return MIRACLError when access id in SessionDetails is empty or blank`() =
        runTest {
            // Arrange
            val blankSessionId = "   "
            val sessionDetailsBlankSessionId = createCrossDeviceSession(sessionId = blankSessionId)

            // Act
            val result = sessionManager.abortSession(sessionDetailsBlankSessionId)

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertEquals(
                CrossDeviceSessionException.InvalidCrossDeviceSession,
                (result as MIRACLError).value
            )
        }

    @Test
    fun `abortSession should return MIRACLError when abortSessionRequest fails`() =
        runTest {
            // Arrange
            val exception = CrossDeviceSessionException.AbortCrossDeviceSessionFail(null)
            coEvery {
                sessionApiMock.executeAbortSessionRequest(sessionId)
            } returns MIRACLError(exception)

            // Act
            val result = sessionManager.abortSession(crossDeviceSession)

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertEquals(exception, (result as MIRACLError).value)
        }

    private fun createCrossDeviceSession(
        sessionId: String = this.sessionId,
        description: String = randomUuidString(),
        userId: String = randomUuidString(),
        projectId: String = randomUuidString(),
        hash: String = randomUuidString()
    ): CrossDeviceSession {
        return CrossDeviceSession(
            sessionId = sessionId,
            sessionDescription = description,
            userId = userId,
            projectId = projectId,
            signingHash = hash
        )
    }

    private fun createCrossDeviceSessionResponse() = CrossDeviceSessionResponse(
        prerollId = randomUuidString(),
        description = randomUuidString(),
        projectId = randomUuidString(),
        hash = randomUuidString()
    )
}