package com.miracl.trust.session

import android.net.Uri
import com.miracl.trust.MIRACLError
import com.miracl.trust.MIRACLSuccess
import com.miracl.trust.randomPinLength
import com.miracl.trust.randomUuidString
import io.mockk.*
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.runTest
import org.junit.Assert
import org.junit.Before
import org.junit.Test
import kotlin.random.Random

@ExperimentalCoroutinesApi
class SessionManagerUnitTest {
    private val accessId = randomUuidString()
    private val codeStatusResponse = crateCodeStatusResponse()
    private val sessionDetails = createSessionDetails()

    private val sessionApiMock = mockk<SessionApi>()
    private val sessionManager = SessionManager(sessionApiMock)

    @Before
    fun setUp() {
        clearAllMocks()
    }

    @Test
    fun `getSessionDetailsFromAppLink should return MIRACLSuccess`() =
        runTest {
            // Arrange
            val appLinkMock = mockkClass(Uri::class)

            every { appLinkMock.fragment } returns accessId
            coEvery {
                sessionApiMock.executeCodeStatusRequest(accessId, SessionStatus.WID.value)
            } returns MIRACLSuccess(codeStatusResponse)

            // Act
            val result = sessionManager.getSessionDetailsFromAppLink(appLinkMock)

            // Assert
            Assert.assertTrue(result is MIRACLSuccess)

            Assert.assertEquals(
                codeStatusResponse.prerollId,
                (result as MIRACLSuccess).value.userId
            )
            Assert.assertEquals(codeStatusResponse.projectId, result.value.projectId)
            Assert.assertEquals(codeStatusResponse.projectName, result.value.projectName)
            Assert.assertEquals(codeStatusResponse.projectLogoUrl, result.value.projectLogoUrl)
            Assert.assertEquals(codeStatusResponse.pinLength, result.value.pinLength)
            Assert.assertEquals(accessId, result.value.accessId)
            Assert.assertEquals(
                VerificationMethod.fromString(codeStatusResponse.verificationMethod),
                result.value.verificationMethod
            )
            Assert.assertEquals(codeStatusResponse.verificationUrl, result.value.verificationUrl)
            Assert.assertEquals(
                codeStatusResponse.verificationCustomText,
                result.value.verificationCustomText
            )
            Assert.assertEquals(
                IdentityType.fromString(codeStatusResponse.identityType),
                result.value.identityType
            )
            Assert.assertEquals(
                codeStatusResponse.identityTypeLabel,
                result.value.identityTypeLabel
            )
            Assert.assertEquals(
                codeStatusResponse.quickCodeEnabled,
                result.value.quickCodeEnabled
            )
            Assert.assertEquals(
                codeStatusResponse.limitQuickCodeRegistration,
                result.value.limitQuickCodeRegistration
            )
        }

    @Test
    fun `getSessionDetailsFromAppLink should return MIRACLError when codeStatusRequest fails`() =
        runTest {
            // Arrange
            val appLinkMock = mockkClass(Uri::class)

            every { appLinkMock.fragment } returns accessId

            val sessionManagementException =
                AuthenticationSessionException.GetAuthenticationSessionDetailsFail(null)
            coEvery {
                sessionApiMock.executeCodeStatusRequest(accessId, SessionStatus.WID.value)
            } returns MIRACLError(sessionManagementException)

            // Act
            val result = sessionManager.getSessionDetailsFromAppLink(appLinkMock)

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertEquals(sessionManagementException, (result as MIRACLError).value)
        }

    @Test
    fun `getSessionDetailsFromAppLink should return MIRACLError when appLink is invalid`() =
        runTest {
            // Arrange
            val appLinkMock = mockkClass(Uri::class)
            every { appLinkMock.fragment } returns null

            // Act
            val result = sessionManager.getSessionDetailsFromAppLink(appLinkMock)

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertEquals(
                AuthenticationSessionException.InvalidAppLink,
                (result as MIRACLError).value
            )
        }


    @Test
    fun `getSessionDetailsFromQRCode should return MIRACLSuccess`() =
        runTest {
            // Arrange
            val qrCode = "https://mcl.mpin.io/mobile-login/#$accessId"
            val uriMock = mockkClass(Uri::class)

            mockkStatic(Uri::class)
            every { Uri.parse(qrCode) } returns uriMock
            every { uriMock.fragment } returns accessId

            coEvery {
                sessionApiMock.executeCodeStatusRequest(accessId, SessionStatus.WID.value)
            } returns MIRACLSuccess(codeStatusResponse)

            // Act
            val result = sessionManager.getSessionDetailsFromQRCode(qrCode)

            // Assert
            Assert.assertTrue(result is MIRACLSuccess)
        }

    @Test
    fun `getSessionDetailsFromQRCode should return MIRACLError when codeStatusRequest fails`() =
        runTest {
            // Arrange
            val qrCode = "https://mcl.mpin.io/mobile-login/#$accessId"
            val uriMock = mockkClass(Uri::class)

            mockkStatic(Uri::class)
            every { Uri.parse(qrCode) } returns uriMock
            every { uriMock.fragment } returns accessId

            val sessionManagementException =
                AuthenticationSessionException.GetAuthenticationSessionDetailsFail(null)
            coEvery {
                sessionApiMock.executeCodeStatusRequest(accessId, SessionStatus.WID.value)
            } returns MIRACLError(sessionManagementException)

            // Act
            val result = sessionManager.getSessionDetailsFromQRCode(qrCode)

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertEquals(sessionManagementException, (result as MIRACLError).value)
        }

    @Test
    fun `getSessionDetailsFromQRCode should return MIRACLError when qrCode is invalid`() =
        runTest {
            // Arrange
            val qrCode = "https://mcl.mpin.io/mobile-login"
            val uriMock = mockkClass(Uri::class)

            mockkStatic(Uri::class)
            every { Uri.parse(qrCode) } returns uriMock
            every { uriMock.fragment } returns null

            // Act
            val result = sessionManager.getSessionDetailsFromQRCode(qrCode)

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertEquals(
                AuthenticationSessionException.InvalidQRCode,
                (result as MIRACLError).value
            )
        }

    @Test
    fun `getSessionDetailsFromNotificationPayload should return MIRACLSuccess`() =
        runTest {
            // Arrange
            val qrUrl = "https://mcl.mpin.io/mobile-login/#$accessId"
            val payload = mapOf(
                SessionManager.PUSH_NOTIFICATION_QR_URL to qrUrl
            )
            val uriMock = mockkClass(Uri::class)

            mockkStatic(Uri::class)
            every { Uri.parse(qrUrl) } returns uriMock
            every { uriMock.fragment } returns accessId

            coEvery {
                sessionApiMock.executeCodeStatusRequest(accessId, SessionStatus.WID.value)
            } returns MIRACLSuccess(codeStatusResponse)

            // Act
            val result = sessionManager.getSessionDetailsFromNotificationPayload(payload)

            // Assert
            Assert.assertTrue(result is MIRACLSuccess)
        }

    @Test
    fun `getSessionDetailsFromNotificationPayload should return MIRACLError when codeStatusRequest fails`() =
        runTest {
            // Arrange
            val qrUrl = "https://mcl.mpin.io/mobile-login/#$accessId"
            val payload = mapOf(
                SessionManager.PUSH_NOTIFICATION_QR_URL to qrUrl
            )
            val uriMock = mockkClass(Uri::class)

            mockkStatic(Uri::class)
            every { Uri.parse(qrUrl) } returns uriMock
            every { uriMock.fragment } returns accessId

            val sessionManagementException =
                AuthenticationSessionException.GetAuthenticationSessionDetailsFail(null)
            coEvery {
                sessionApiMock.executeCodeStatusRequest(accessId, SessionStatus.WID.value)
            } returns MIRACLError(sessionManagementException)

            // Act
            val result = sessionManager.getSessionDetailsFromNotificationPayload(payload)

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertEquals(sessionManagementException, (result as MIRACLError).value)
        }

    @Test
    fun `getSessionDetailsFromNotificationPayload should return MIRACLError when payload doesn't contain qrURL`() =
        runTest {
            // Arrange
            val payload = mapOf<String, String>()

            // Act
            val result = sessionManager.getSessionDetailsFromNotificationPayload(payload)

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertEquals(
                AuthenticationSessionException.InvalidNotificationPayload,
                (result as MIRACLError).value
            )
        }

    @Test
    fun `getSessionDetailsFromNotificationPayload should return MIRACLError when payload contains invalid qrURL`() =
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
            val result = sessionManager.getSessionDetailsFromNotificationPayload(payload)

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertEquals(
                AuthenticationSessionException.InvalidNotificationPayload,
                (result as MIRACLError).value
            )
        }

    @Test
    fun `abortSession should return MIRACLSuccess`() =
        runTest {
            // Arrange
            coEvery {
                sessionApiMock.executeAbortSessionRequest(accessId)
            } returns MIRACLSuccess(Unit)

            // Act
            val result = sessionManager.abortSession(sessionDetails)

            // Assert
            Assert.assertTrue(result is MIRACLSuccess)
        }

    @Test
    fun `abortSession should return MIRACLError when access id in SessionDetails is empty or blank`() =
        runTest {
            // Arrange
            val blankAccessId = "   "
            val sessionDetailsBlankAccessId = createSessionDetails(accessId = blankAccessId)

            // Act
            val result = sessionManager.abortSession(sessionDetailsBlankAccessId)

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertEquals(
                AuthenticationSessionException.InvalidSessionDetails,
                (result as MIRACLError).value
            )
        }

    @Test
    fun `abortSession should return MIRACLError when abortSessionRequest fails`() =
        runTest {
            // Arrange
            val exception = AuthenticationSessionException.AbortSessionFail(null)
            coEvery {
                sessionApiMock.executeAbortSessionRequest(accessId)
            } returns MIRACLError(exception)

            // Act
            val result = sessionManager.abortSession(sessionDetails)

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertEquals(exception, (result as MIRACLError).value)
        }

    private fun createSessionDetails(
        accessId: String = this.accessId,
        userId: String = randomUuidString(),
        projectId: String = randomUuidString(),
        projectName: String = randomUuidString(),
        projectLogoUrl: String = randomUuidString(),
        pinLength: Int = randomPinLength(),
        verificationMethod: VerificationMethod = VerificationMethod.FullCustom,
        verificationUrl: String = randomUuidString(),
        verificationCustomText: String = randomUuidString(),
        identityType: IdentityType = IdentityType.Email,
        identityTypeLabel: String = randomUuidString(),
        quickCodeEnabled: Boolean = Random.nextBoolean(),
        limitQuickCodeRegistration: Boolean = Random.nextBoolean()
    ): AuthenticationSessionDetails {
        return AuthenticationSessionDetails(
            accessId = accessId,
            userId = userId,
            projectId = projectId,
            projectName = projectName,
            projectLogoUrl = projectLogoUrl,
            pinLength = pinLength,
            verificationMethod = verificationMethod,
            verificationUrl = verificationUrl,
            verificationCustomText = verificationCustomText,
            identityType = identityType,
            identityTypeLabel = identityTypeLabel,
            quickCodeEnabled = quickCodeEnabled,
            limitQuickCodeRegistration = limitQuickCodeRegistration
        )
    }

    private fun crateCodeStatusResponse() = CodeStatusResponse(
        prerollId = randomUuidString(),
        projectId = randomUuidString(),
        projectName = randomUuidString(),
        projectLogoUrl = randomUuidString(),
        pinLength = randomPinLength(),
        verificationMethod = VerificationMethod.StandardEmail.name,
        verificationUrl = randomUuidString(),
        verificationCustomText = randomUuidString(),
        identityType = IdentityType.Email.name,
        identityTypeLabel = randomUuidString(),
        quickCodeEnabled = Random.nextBoolean(),
        limitQuickCodeRegistration = Random.nextBoolean()
    )
}