package com.miracl.trust.session

import android.net.Uri
import com.miracl.trust.MIRACLError
import com.miracl.trust.MIRACLSuccess
import com.miracl.trust.randomHexString
import com.miracl.trust.randomPinLength
import com.miracl.trust.randomUuidString
import io.mockk.clearAllMocks
import io.mockk.coEvery
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkClass
import io.mockk.mockkStatic
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.runTest
import org.junit.Assert
import org.junit.Before
import org.junit.Test
import java.util.Date
import kotlin.random.Random

@ExperimentalCoroutinesApi
class SigningSessionManagerUnitTest {
    private val sessionId = randomUuidString()
    private val signingSessionDetailsResponse = createSigningSessionDetailsResponse()
    private val signingSessionDetails = createSigningSessionDetails()

    private val signingSessionApiMock = mockk<SigningSessionApi>()
    private val signingSessionManager = SigningSessionManager(signingSessionApiMock)

    @Before
    fun setUp() {
        clearAllMocks()
    }

    @Test
    fun `getSigningSessionDetailsFromAppLink should return MIRACLSuccess`() =
        runTest {
            // Arrange
            val appLinkMock = mockkClass(Uri::class)

            every { appLinkMock.fragment } returns sessionId
            coEvery {
                signingSessionApiMock.executeSigningSessionDetailsRequest(sessionId)
            } returns MIRACLSuccess(signingSessionDetailsResponse)

            // Act
            val result = signingSessionManager.getSigningSessionDetailsFromAppLink(appLinkMock)

            // Assert
            Assert.assertTrue(result is MIRACLSuccess)

            Assert.assertEquals(sessionId, (result as MIRACLSuccess).value.sessionId)
            Assert.assertEquals(signingSessionDetailsResponse.userId, result.value.userId)
            Assert.assertEquals(signingSessionDetailsResponse.hash, result.value.signingHash)
            Assert.assertEquals(
                signingSessionDetailsResponse.description,
                result.value.signingDescription
            )
            Assert.assertEquals(
                SigningSessionStatus.fromString(signingSessionDetailsResponse.status),
                result.value.status
            )
            Assert.assertEquals(signingSessionDetailsResponse.expireTime, result.value.expireTime)
            Assert.assertEquals(signingSessionDetailsResponse.projectId, result.value.projectId)
            Assert.assertEquals(
                signingSessionDetailsResponse.projectLogoUrl,
                result.value.projectLogoUrl
            )
            Assert.assertEquals(
                signingSessionDetailsResponse.projectName,
                result.value.projectName
            )
            Assert.assertEquals(
                VerificationMethod.fromString(signingSessionDetailsResponse.verificationMethod),
                result.value.verificationMethod
            )
            Assert.assertEquals(
                signingSessionDetailsResponse.verificationUrl,
                result.value.verificationUrl
            )
            Assert.assertEquals(
                signingSessionDetailsResponse.verificationCustomText,
                result.value.verificationCustomText
            )
            Assert.assertEquals(
                IdentityType.fromString(signingSessionDetailsResponse.identityType),
                result.value.identityType
            )
            Assert.assertEquals(
                signingSessionDetailsResponse.identityTypeLabel,
                result.value.identityTypeLabel
            )
            Assert.assertEquals(signingSessionDetailsResponse.pinLength, result.value.pinLength)
            Assert.assertEquals(
                signingSessionDetailsResponse.quickCodeEnabled,
                result.value.quickCodeEnabled
            )
            Assert.assertEquals(
                signingSessionDetailsResponse.limitQuickCodeRegistration,
                result.value.limitQuickCodeRegistration
            )
        }

    @Test
    fun `getSessionDetailsFromAppLink should return MIRACLError when executeSigningSessionDetailsRequest fails`() =
        runTest {
            // Arrange
            val appLinkMock = mockkClass(Uri::class)

            every { appLinkMock.fragment } returns sessionId

            val sessionManagementException =
                SigningSessionException.GetSigningSessionDetailsFail(null)
            coEvery {
                signingSessionApiMock.executeSigningSessionDetailsRequest(sessionId)
            } returns MIRACLError(sessionManagementException)

            // Act
            val result = signingSessionManager.getSigningSessionDetailsFromAppLink(appLinkMock)

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertEquals(sessionManagementException, (result as MIRACLError).value)
        }

    @Test
    fun `getSigningSessionDetailsFromAppLink should return MIRACLError when appLink is invalid`() =
        runTest {
            // Arrange
            val appLinkMock = mockkClass(Uri::class)
            every { appLinkMock.fragment } returns null

            // Act
            val result = signingSessionManager.getSigningSessionDetailsFromAppLink(appLinkMock)

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertEquals(
                SigningSessionException.InvalidAppLink,
                (result as MIRACLError).value
            )
        }

    @Test
    fun `getSessionDetailsFromQRCode should return MIRACLSuccess`() =
        runTest {
            // Arrange
            val qrCode = "https://mcl.mpin.io/dvs/#$sessionId"
            val uriMock = mockkClass(Uri::class)

            mockkStatic(Uri::class)
            every { Uri.parse(qrCode) } returns uriMock
            every { uriMock.fragment } returns sessionId

            coEvery {
                signingSessionApiMock.executeSigningSessionDetailsRequest(sessionId)
            } returns MIRACLSuccess(signingSessionDetailsResponse)

            // Act
            val result = signingSessionManager.getSigningSessionDetailsFromQRCode(qrCode)

            // Assert
            Assert.assertTrue(result is MIRACLSuccess)
        }

    @Test
    fun `getSessionDetailsFromQRCode should return MIRACLError when codeStatusRequest fails`() =
        runTest {
            // Arrange
            val qrCode = "https://mcl.mpin.io/dvs/#$sessionId"
            val uriMock = mockkClass(Uri::class)

            mockkStatic(Uri::class)
            every { Uri.parse(qrCode) } returns uriMock
            every { uriMock.fragment } returns sessionId

            val sessionManagementException =
                SigningSessionException.GetSigningSessionDetailsFail(null)
            coEvery {
                signingSessionApiMock.executeSigningSessionDetailsRequest(sessionId)
            } returns MIRACLError(sessionManagementException)

            // Act
            val result = signingSessionManager.getSigningSessionDetailsFromQRCode(qrCode)

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertEquals(sessionManagementException, (result as MIRACLError).value)
        }

    @Test
    fun `getSessionDetailsFromQRCode should return MIRACLError when qrCode is invalid`() =
        runTest {
            // Arrange
            val qrCode = "https://mcl.mpin.io/dvs"
            val uriMock = mockkClass(Uri::class)

            mockkStatic(Uri::class)
            every { Uri.parse(qrCode) } returns uriMock
            every { uriMock.fragment } returns null

            // Act
            val result = signingSessionManager.getSigningSessionDetailsFromQRCode(qrCode)

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertEquals(
                SigningSessionException.InvalidQRCode,
                (result as MIRACLError).value
            )
        }

    @Test
    fun `abortSigningSession should return MIRACLSuccess`() =
        runTest {
            // Arrange
            coEvery {
                signingSessionApiMock.executeSigningSessionAbortRequest(sessionId)
            } returns MIRACLSuccess(Unit)

            // Act
            val result = signingSessionManager.abortSigningSession(signingSessionDetails)

            // Assert
            Assert.assertTrue(result is MIRACLSuccess)
        }

    @Test
    fun `abortSigningSession should return MIRACLError when session id in SigningSessionDetails is empty or blank`() =
        runTest {
            // Arrange
            val blankSessionId = "   "
            val sessionDetailsBlankSessionId =
                createSigningSessionDetails(sessionId = blankSessionId)

            // Act
            val result = signingSessionManager.abortSigningSession(sessionDetailsBlankSessionId)

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertEquals(
                SigningSessionException.InvalidSigningSessionDetails,
                (result as MIRACLError).value
            )
        }

    @Test
    fun `abortSigningSession should return MIRACLError when signingSessionAbortRequest fails`() =
        runTest {
            // Arrange
            val exception = SigningSessionException.AbortSigningSessionFail(null)
            coEvery {
                signingSessionApiMock.executeSigningSessionAbortRequest(sessionId)
            } returns MIRACLError(exception)

            // Act
            val result = signingSessionManager.abortSigningSession(signingSessionDetails)

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertEquals(exception, (result as MIRACLError).value)
        }

    private fun createSigningSessionDetails(
        sessionId: String = this.sessionId,
        hash: String = randomHexString(),
        description: String = randomUuidString(),
        status: SigningSessionStatus = SigningSessionStatus.Active,
        expireTime: Long = Date().time,
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
    ): SigningSessionDetails {
        return SigningSessionDetails(
            sessionId = sessionId,
            signingHash = hash,
            signingDescription = description,
            status = status,
            expireTime = expireTime,
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

    private fun createSigningSessionDetailsResponse() = SigningSessionDetailsResponse(
        userId = randomUuidString(),
        hash = randomHexString(),
        description = randomUuidString(),
        status = SigningSessionStatus.Active.name,
        expireTime = Date().time,
        projectId = randomUuidString(),
        projectName = randomUuidString(),
        projectLogoUrl = randomUuidString(),
        verificationMethod = VerificationMethod.StandardEmail.name,
        verificationUrl = randomUuidString(),
        verificationCustomText = randomUuidString(),
        identityType = IdentityType.Email.name,
        identityTypeLabel = randomUuidString(),
        pinLength = randomPinLength(),
        quickCodeEnabled = Random.nextBoolean(),
        limitQuickCodeRegistration = Random.nextBoolean()
    )
}