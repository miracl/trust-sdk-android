package com.miracl.trust.registration

import android.net.Uri
import com.miracl.trust.MIRACLError
import com.miracl.trust.MIRACLSuccess
import com.miracl.trust.authentication.AuthenticateResponse
import com.miracl.trust.authentication.AuthenticationException
import com.miracl.trust.authentication.AuthenticatorContract
import com.miracl.trust.authentication.AuthenticatorScopes
import com.miracl.trust.delegate.PinProvider
import com.miracl.trust.model.User
import com.miracl.trust.network.ApiException
import com.miracl.trust.network.ClientErrorData
import com.miracl.trust.randomByteArray
import com.miracl.trust.randomPinLength
import com.miracl.trust.randomUuidString
import com.miracl.trust.session.AuthenticationSessionDetails
import com.miracl.trust.storage.UserStorage
import com.miracl.trust.util.toHexString
import io.mockk.*
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.runTest
import org.junit.Assert
import org.junit.Before
import org.junit.Test
import java.util.Date
import kotlin.random.Random
import kotlin.random.nextInt

@ExperimentalCoroutinesApi
class VerificatorUnitTest {
    private val authenticatorMock = mockk<AuthenticatorContract>()
    private val verificationApiMock = mockk<VerificationApi>()
    private val userStorageMock = mockk<UserStorage>()

    private val verificator = Verificator(authenticatorMock, verificationApiMock, userStorageMock)

    @Before
    fun setUp() {
        clearAllMocks()
        every { userStorageMock.getUser(any(), any()) } returns null
    }

    @Test
    fun `sendVerificationEmail should return MIRACLSuccess`() =
        runTest {
            // Arrange
            val userId = randomUuidString()
            val projectId = randomUuidString()
            val deviceName = randomUuidString()
            val backoff: Long = Random.nextLong()
            val method = EmailVerificationMethod.Link

            coEvery {
                verificationApiMock.executeVerificationRequest(
                    VerificationRequestBody(
                        userId = userId,
                        projectId = projectId,
                        deviceName = deviceName,
                        accessId = null,
                        mpinId = null
                    )
                )
            } returns MIRACLSuccess(VerificationRequestResponse(backoff, method.toString()))

            // Act
            val result = verificator.sendVerificationEmail(
                userId,
                projectId,
                deviceName,
                null
            )

            // Assert
            Assert.assertTrue(result is MIRACLSuccess)
            Assert.assertEquals(backoff, (result as MIRACLSuccess).value.backoff)
            Assert.assertEquals(method, result.value.method)
        }

    @Test
    fun `sendVerificationEmail should return MIRACLSuccess when authenticationSessionDetails are passed`() =
        runTest {
            // Arrange
            val userId = randomUuidString()
            val projectId = randomUuidString()
            val deviceName = randomUuidString()
            val accessId = randomUuidString()
            val backoff: Long = Random.nextLong()
            val method = EmailVerificationMethod.Link

            val authenticationSessionDetails = mockkClass(AuthenticationSessionDetails::class)
            every { authenticationSessionDetails.accessId } returns accessId

            coEvery {
                verificationApiMock.executeVerificationRequest(
                    VerificationRequestBody(
                        userId = userId,
                        projectId = projectId,
                        deviceName = deviceName,
                        accessId = accessId,
                        mpinId = null
                    )
                )
            } returns MIRACLSuccess(VerificationRequestResponse(backoff, method.toString()))

            // Act
            val result = verificator.sendVerificationEmail(
                userId = userId,
                projectId = projectId,
                deviceName = deviceName,
                authenticationSessionDetails = authenticationSessionDetails
            )

            // Assert
            Assert.assertTrue(result is MIRACLSuccess)
            Assert.assertEquals(backoff, (result as MIRACLSuccess).value.backoff)
            Assert.assertEquals(method, result.value.method)
        }

    @Test
    fun `sendVerificationEmail should pass the user's mpinId when it exists`() =
        runTest {
            // Arrange
            val userId = randomUuidString()
            val projectId = randomUuidString()
            val deviceName = randomUuidString()
            val backoff: Long = Random.nextLong()
            val method = EmailVerificationMethod.Code

            val mpinId = randomByteArray()
            every { userStorageMock.getUser(userId, projectId) } returns User(
                userId = userId,
                projectId = projectId,
                revoked = Random.nextBoolean(),
                pinLength = randomPinLength(),
                mpinId = mpinId,
                token = randomByteArray(),
                dtas = randomUuidString(),
                publicKey = randomByteArray()
            )

            coEvery {
                verificationApiMock.executeVerificationRequest(
                    VerificationRequestBody(
                        userId = userId,
                        projectId = projectId,
                        deviceName = deviceName,
                        accessId = null,
                        mpinId = mpinId.toHexString()
                    )
                )
            } returns MIRACLSuccess(VerificationRequestResponse(backoff, method.toString()))

            // Act
            val result = verificator.sendVerificationEmail(
                userId,
                projectId,
                deviceName,
                null
            )

            // Assert
            Assert.assertTrue(result is MIRACLSuccess)
            Assert.assertEquals(backoff, (result as MIRACLSuccess).value.backoff)
            Assert.assertEquals(method, result.value.method)
        }

    @Test
    fun `sendVerificationEmail should return MIRACLError when userId is empty`() =
        runTest {
            // Arrange
            val userId = ""
            val projectId = randomUuidString()
            val deviceName = randomUuidString()

            // Act
            val result = verificator.sendVerificationEmail(
                userId,
                projectId,
                deviceName,
                null
            )

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertTrue((result as MIRACLError).value is VerificationException.EmptyUserId)
        }

    @Test
    fun `sendVerificationEmail should return MIRACLError when accessId in authenticationSessionDetails is empty`() =
        runTest {
            // Arrange
            val userId = randomUuidString()
            val projectId = randomUuidString()
            val deviceName = randomUuidString()
            val accessId = ""

            val authenticationSessionDetails = mockkClass(AuthenticationSessionDetails::class)
            every { authenticationSessionDetails.accessId } returns accessId

            // Act
            val result = verificator.sendVerificationEmail(
                userId,
                projectId,
                deviceName,
                authenticationSessionDetails
            )

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertTrue((result as MIRACLError).value is VerificationException.InvalidSessionDetails)
        }

    @Test
    fun `sendVerificationEmail should return MIRACLError when verification request returns an error`() =
        runTest {
            // Arrange
            val userId = randomUuidString()
            val projectId = randomUuidString()
            val deviceName = randomUuidString()

            val verificationException = VerificationException.VerificationFail()
            coEvery {
                verificationApiMock.executeVerificationRequest(
                    any()
                )
            } returns MIRACLError(verificationException)

            // Act
            val result = verificator.sendVerificationEmail(
                userId,
                projectId,
                deviceName,
                null
            )

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertEquals(verificationException, (result as MIRACLError).value)
        }

    @Test
    fun `generateQuickCode should return MIRACLSuccess with QuickCode`() =
        runTest {
            // Arrange
            val user = mockk<User>()
            val pinProviderMock = mockk<PinProvider>()
            val projectId = randomUuidString()
            val deviceName = randomUuidString()
            val jwt = randomUuidString()

            coEvery { user.projectId } returns projectId

            coEvery {
                authenticatorMock.authenticate(
                    user,
                    null,
                    pinProviderMock,
                    arrayOf(AuthenticatorScopes.QUICK_CODE.value),
                    deviceName
                )
            } returns MIRACLSuccess(AuthenticateResponse(200, "OK", null, jwt))


            val capturingSlotQuickCodeVerification =
                CapturingSlot<QuickCodeVerificationRequestBody>()

            val quickCodeVerificationResponse = QuickCodeVerificationResponse(
                code = randomUuidString(),
                expireTime = Date().time,
                ttlSeconds = Random.nextInt(1..9999)
            )
            coEvery {
                verificationApiMock.executeQuickCodeVerificationRequest(
                    capture(capturingSlotQuickCodeVerification)
                )
            } returns MIRACLSuccess(quickCodeVerificationResponse)

            // Act
            val result = verificator.generateQuickCode(
                user,
                pinProviderMock,
                deviceName
            )

            // Assert
            Assert.assertEquals(projectId, capturingSlotQuickCodeVerification.captured.projectId)
            Assert.assertEquals(jwt, capturingSlotQuickCodeVerification.captured.jwt)
            Assert.assertEquals(deviceName, capturingSlotQuickCodeVerification.captured.deviceName)

            Assert.assertTrue(result is MIRACLSuccess)
            Assert.assertEquals(
                quickCodeVerificationResponse.code,
                (result as MIRACLSuccess).value.code
            )
            Assert.assertEquals(quickCodeVerificationResponse.expireTime, result.value.expireTime)
            Assert.assertEquals(quickCodeVerificationResponse.ttlSeconds, result.value.ttlSeconds)
        }

    @Test
    fun `generateQuickCode should return MIRACLError when authentication fails`() =
        runTest {
            // Arrange
            val authenticationException = AuthenticationException.AuthenticationFail(Exception())
            coEvery {
                authenticatorMock.authenticate(any(), any(), any(), any(), any())
            } returns MIRACLError(authenticationException)

            // Act
            val result = verificator.generateQuickCode(
                user = mockk<User>(),
                pinProvider = mockk<PinProvider>(),
                deviceName = randomUuidString()
            )

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertTrue((result as MIRACLError).value is QuickCodeException.GenerationFail)
            Assert.assertEquals(authenticationException, result.value.cause)
        }

    @Test
    fun `generateQuickCode should return correct MIRACLError when authentication fails because of limited QuickCode generation`() =
        runTest {
            // Arrange
            val authenticationException = AuthenticationException.AuthenticationFail(
                ApiException.ClientError(
                    clientErrorData = ClientErrorData(
                        code = "LIMITED_QUICKCODE_GENERATION",
                        info = "Generating QuickCode from this registration is not allowed.",
                        context = null
                    )
                )
            )
            coEvery {
                authenticatorMock.authenticate(any(), any(), any(), any(), any())
            } returns MIRACLError(authenticationException)

            // Act
            val result = verificator.generateQuickCode(
                user = mockk<User>(),
                pinProvider = mockk<PinProvider>(),
                deviceName = randomUuidString()
            )

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertTrue((result as MIRACLError).value is QuickCodeException.LimitedQuickCodeGeneration)
        }

    @Test
    fun `generateQuickCode should return correct MIRACLError when authentication fails because of invalid pin`() =
        runTest {
            // Arrange
            val authenticationException = AuthenticationException.InvalidPin
            coEvery {
                authenticatorMock.authenticate(any(), any(), any(), any(), any())
            } returns MIRACLError(authenticationException)

            // Act
            val result = verificator.generateQuickCode(
                user = mockk<User>(),
                pinProvider = mockk<PinProvider>(),
                deviceName = randomUuidString()
            )

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertTrue((result as MIRACLError).value is QuickCodeException.InvalidPin)
        }

    @Test
    fun `generateQuickCode should return correct MIRACLError when authentication fails because of cancelled pin`() =
        runTest {
            // Arrange
            val authenticationException = AuthenticationException.PinCancelled
            coEvery {
                authenticatorMock.authenticate(any(), any(), any(), any(), any())
            } returns MIRACLError(authenticationException)

            // Act
            val result = verificator.generateQuickCode(
                user = mockk<User>(),
                pinProvider = mockk<PinProvider>(),
                deviceName = randomUuidString()
            )

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertTrue((result as MIRACLError).value is QuickCodeException.PinCancelled)
        }

    @Test
    fun `generateQuickCode should return correct MIRACLError when authentication fails because of unsuccessful authentication`() =
        runTest {
            // Arrange
            val authenticationException = AuthenticationException.UnsuccessfulAuthentication
            coEvery {
                authenticatorMock.authenticate(any(), any(), any(), any(), any())
            } returns MIRACLError(authenticationException)

            // Act
            val result = verificator.generateQuickCode(
                user = mockk<User>(),
                pinProvider = mockk<PinProvider>(),
                deviceName = randomUuidString()
            )

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertTrue((result as MIRACLError).value is QuickCodeException.UnsuccessfulAuthentication)
        }

    @Test
    fun `generateQuickCode should return correct MIRACLError when authentication fails because of revoked user`() =
        runTest {
            // Arrange
            val authenticationException = AuthenticationException.Revoked
            coEvery {
                authenticatorMock.authenticate(any(), any(), any(), any(), any())
            } returns MIRACLError(authenticationException)

            // Act
            val result = verificator.generateQuickCode(
                user = mockk<User>(),
                pinProvider = mockk<PinProvider>(),
                deviceName = randomUuidString()
            )

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertTrue((result as MIRACLError).value is QuickCodeException.Revoked)
        }

    @Test
    fun `generateQuickCode should return MIRACLError when there is no jwt in the authentication response`() =
        runTest {
            // Arrange
            coEvery {
                authenticatorMock.authenticate(any(), any(), any(), any(), any())
            } returns MIRACLSuccess(AuthenticateResponse(200, "OK", null, null))

            // Act
            val result = verificator.generateQuickCode(
                user = mockk<User>(),
                pinProvider = mockk<PinProvider>(),
                deviceName = randomUuidString()
            )

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertTrue((result as MIRACLError).value is QuickCodeException.GenerationFail)
        }

    @Test
    fun `generateQuickCode should return MIRACLError when QuickCode verification fails`() =
        runTest {
            // Arrange
            val user = mockk<User>()
            coEvery { user.projectId } returns randomUuidString()

            coEvery {
                authenticatorMock.authenticate(any(), any(), any(), any(), any())
            } returns MIRACLSuccess(AuthenticateResponse(200, "OK", null, randomUuidString()))

            val quickCodeVerificationException = QuickCodeException.GenerationFail()
            coEvery {
                verificationApiMock.executeQuickCodeVerificationRequest(any())
            } returns MIRACLError(quickCodeVerificationException)

            // Act
            val result = verificator.generateQuickCode(
                user = user,
                pinProvider = mockk<PinProvider>(),
                deviceName = randomUuidString()
            )

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertEquals(quickCodeVerificationException, (result as MIRACLError).value)
        }

    @Test
    fun `getActivationToken with verification URI should return MIRACLSuccess with activationToken, userId and accessId`() =
        runTest {
            // Arrange
            val userId = randomUuidString()
            val code = randomUuidString()

            val uriMock = mockkClass(Uri::class)
            mockkStatic(Uri::class)
            every { uriMock.getQueryParameter("user_id") } returns userId
            every { uriMock.getQueryParameter("code") } returns code

            val capturingSlotConfirmation = CapturingSlot<ConfirmationRequestBody>()

            val confirmationResponse = ConfirmationResponse(
                projectId = randomUuidString(),
                activateToken = randomUuidString(),
                accessId = randomUuidString()
            )
            coEvery {
                verificationApiMock.executeConfirmationRequest(
                    capture(capturingSlotConfirmation)
                )
            } returns MIRACLSuccess(confirmationResponse)

            // Act
            val result = verificator.getActivationToken(
                uriMock
            )

            // Assert
            Assert.assertEquals(userId, capturingSlotConfirmation.captured.userId)
            Assert.assertEquals(code, capturingSlotConfirmation.captured.code)

            Assert.assertTrue(result is MIRACLSuccess)
            Assert.assertEquals(
                confirmationResponse.activateToken,
                (result as MIRACLSuccess).value.activationToken
            )
            Assert.assertEquals(userId, result.value.userId)
            Assert.assertEquals(confirmationResponse.accessId, result.value.accessId)
            Assert.assertEquals(confirmationResponse.projectId, result.value.projectId)
        }

    @Test
    fun `getActivationToken with verification URI should return MIRACLError when confirmation fails`() =
        runTest {
            // Arrange
            val userId = randomUuidString()
            val code = randomUuidString()

            val uriMock = mockkClass(Uri::class)
            mockkStatic(Uri::class)
            every { uriMock.getQueryParameter("user_id") } returns userId
            every { uriMock.getQueryParameter("code") } returns code


            val verificationException = ActivationTokenException.GetActivationTokenFail()
            coEvery {
                verificationApiMock.executeConfirmationRequest(any())
            } returns MIRACLError(verificationException)

            // Act
            val result = verificator.getActivationToken(
                uriMock
            )

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertEquals(verificationException, (result as MIRACLError).value)
        }

    @Test
    fun `getActivationToken should return MIRACLSuccess with activationToken, userId and accessId`() =
        runTest {
            // Arrange
            val userId = randomUuidString()
            val code = randomUuidString()

            val capturingSlotConfirmation = CapturingSlot<ConfirmationRequestBody>()

            val confirmationResponse = ConfirmationResponse(
                projectId = randomUuidString(),
                activateToken = randomUuidString(),
                accessId = randomUuidString()
            )
            coEvery {
                verificationApiMock.executeConfirmationRequest(
                    capture(capturingSlotConfirmation)
                )
            } returns MIRACLSuccess(confirmationResponse)

            // Act
            val result = verificator.getActivationToken(
                userId, code
            )

            // Assert
            Assert.assertEquals(userId, capturingSlotConfirmation.captured.userId)
            Assert.assertEquals(code, capturingSlotConfirmation.captured.code)

            Assert.assertTrue(result is MIRACLSuccess)
            Assert.assertEquals(
                confirmationResponse.activateToken,
                (result as MIRACLSuccess).value.activationToken
            )
            Assert.assertEquals(userId, result.value.userId)
            Assert.assertEquals(confirmationResponse.accessId, result.value.accessId)
            Assert.assertEquals(confirmationResponse.projectId, result.value.projectId)
        }

    @Test
    fun `getActivationToken should return MIRACLError when userId is blank`() =
        runTest {
            // Arrange
            val userId = ""
            val code = randomUuidString()

            // Act
            val result = verificator.getActivationToken(
                userId, code
            )

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertEquals(ActivationTokenException.EmptyUserId, (result as MIRACLError).value)
        }

    @Test
    fun `getActivationToken should return MIRACLError when code is blank`() =
        runTest {
            // Arrange
            val userId = randomUuidString()
            val code = ""

            // Act
            val result = verificator.getActivationToken(
                userId, code
            )

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertEquals(
                ActivationTokenException.EmptyVerificationCode,
                (result as MIRACLError).value
            )
        }

    @Test
    fun `getActivationToken should return MIRACLError when confirmation request returns an error`() =
        runTest {
            // Arrange
            val userId = randomUuidString()
            val code = randomUuidString()

            val verificationException = ActivationTokenException.GetActivationTokenFail()
            coEvery {
                verificationApiMock.executeConfirmationRequest(any())
            } returns MIRACLError(verificationException)

            // Act
            val result = verificator.getActivationToken(
                userId, code
            )

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertEquals(verificationException, (result as MIRACLError).value)
        }

    @Test
    fun `getActivationToken should return MIRACLError when confirmation request returns response with empty projectId`() =
        runTest {
            // Arrange
            val userId = randomUuidString()
            val code = randomUuidString()

            val confirmationResponse = ConfirmationResponse(
                projectId = " ",
                activateToken = randomUuidString(),
                accessId = randomUuidString()
            )
            coEvery {
                verificationApiMock.executeConfirmationRequest(any())
            } returns MIRACLSuccess(confirmationResponse)

            // Act
            val result = verificator.getActivationToken(
                userId, code
            )

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertTrue((result as MIRACLError).value is ActivationTokenException.GetActivationTokenFail)
        }

    @Test
    fun `getActivationToken should return MIRACLError when confirmation request returns response with empty activateToken`() =
        runTest {
            // Arrange
            val userId = randomUuidString()
            val code = randomUuidString()

            val confirmationResponse = ConfirmationResponse(
                projectId = randomUuidString(),
                activateToken = " ",
                accessId = randomUuidString()
            )
            coEvery {
                verificationApiMock.executeConfirmationRequest(any())
            } returns MIRACLSuccess(confirmationResponse)

            // Act
            val result = verificator.getActivationToken(
                userId, code
            )

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertTrue((result as MIRACLError).value is ActivationTokenException.GetActivationTokenFail)
        }
}