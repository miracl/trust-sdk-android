package com.miracl.trust.registration

import com.miracl.trust.MIRACLError
import com.miracl.trust.MIRACLSuccess
import com.miracl.trust.network.*
import com.miracl.trust.randomHexString
import com.miracl.trust.randomUuidString
import com.miracl.trust.util.json.KotlinxSerializationJsonUtil
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
class VerificationApiUnitTest {
    private val httpRequestExecutorMock = mockk<ApiRequestExecutor>()
    private val apiSettings = ApiSettings(randomUuidString())

    private val apiManager =
        VerificationApiManager(
            KotlinxSerializationJsonUtil,
            httpRequestExecutorMock,
            apiSettings
        )

    @Before
    fun setUp() {
        clearAllMocks()
    }

    @Test
    fun `executeVerification returns MIRACLSuccess`() =
        runTest {
            // Arrange
            val verificationRequestBody = VerificationRequestBody(
                projectId = randomUuidString(),
                userId = randomUuidString(),
                deviceName = randomUuidString(),
                accessId = randomUuidString(),
                mpinId = randomHexString()
            )

            val verificationRequestBodyAsJson =
                KotlinxSerializationJsonUtil.toJsonString(verificationRequestBody)

            val apiRequest = ApiRequest(
                method = HttpMethod.POST,
                headers = null,
                body = verificationRequestBodyAsJson,
                params = null,
                url = apiSettings.verificationUrl
            )

            val verificationRequestResponse = VerificationRequestResponse(
                backoff = Random.nextLong(),
                method = EmailVerificationMethod.Link.toString()
            )
            val verificationRequestResponseAsJson =
                KotlinxSerializationJsonUtil.toJsonString(verificationRequestResponse)

            coEvery { httpRequestExecutorMock.execute(apiRequest) } returns MIRACLSuccess(
                verificationRequestResponseAsJson
            )

            // Act
            val result = apiManager.executeVerificationRequest(verificationRequestBody)

            // Assert
            Assert.assertTrue(result is MIRACLSuccess)
            Assert.assertEquals(verificationRequestResponse, (result as MIRACLSuccess).value)
        }

    @Test
    fun `executeVerification returns MIRACLError when networkRequest returns an error`() =
        runTest {
            // Arrange
            val httpRequestExecutorException = ApiException.ExecutionError()
            coEvery {
                httpRequestExecutorMock.execute(any())
            } returns MIRACLError(httpRequestExecutorException)

            // Act
            val result = apiManager.executeVerificationRequest(
                VerificationRequestBody(
                    projectId = randomUuidString(),
                    userId = randomUuidString(),
                    deviceName = randomUuidString(),
                    accessId = null,
                    mpinId = null
                )
            )

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertTrue((result as MIRACLError).value is VerificationException.VerificationFail)
            Assert.assertEquals(httpRequestExecutorException, result.value.cause)
        }

    @Test
    fun `executeVerification returns correct MIRACLError when request executor result is BACKOFF_ERROR client error`() =
        runTest {
            // Arrange
            val backoff = Random.nextLong()
            val apiException = ApiException.ClientError(
                clientErrorData = ClientErrorData(
                    code = "BACKOFF_ERROR",
                    info = "Too many verification requests. Wait for the backoff period.",
                    context = mapOf("backoff" to "$backoff")
                ),
                cause = HttpRequestExecutorException.HttpError(400, "")
            )

            coEvery { httpRequestExecutorMock.execute(any()) } returns MIRACLError(apiException)

            // Act
            val result = apiManager.executeVerificationRequest(
                VerificationRequestBody(
                    projectId = randomUuidString(),
                    userId = randomUuidString(),
                    deviceName = randomUuidString(),
                    accessId = null,
                    mpinId = null
                )
            )

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertTrue((result as MIRACLError).value is VerificationException.RequestBackoff)
            val exception = result.value as VerificationException.RequestBackoff
            Assert.assertEquals(backoff, exception.backoff)
        }

    @Test
    fun `executeVerification returns correct MIRACLError when request executor result is BACKOFF_ERROR client error and there isn't backoff in the context`() =
        runTest {
            // Arrange
            val apiException = ApiException.ClientError(
                clientErrorData = ClientErrorData(
                    code = "BACKOFF_ERROR",
                    info = "Too many verification requests. Wait for the backoff period.",
                    context = null
                ),
                cause = HttpRequestExecutorException.HttpError(400, "")
            )

            coEvery { httpRequestExecutorMock.execute(any()) } returns MIRACLError(apiException)

            // Act
            val result = apiManager.executeVerificationRequest(
                VerificationRequestBody(
                    projectId = randomUuidString(),
                    userId = randomUuidString(),
                    deviceName = randomUuidString(),
                    accessId = null,
                    mpinId = null
                )
            )

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertTrue((result as MIRACLError).value is VerificationException.VerificationFail)
        }

    @Test
    fun `executeVerification returns correct MIRACLError when request executor result is REQUEST_BACKOFF client error`() =
        runTest {
            // Arrange
            val backoff = Random.nextLong()

            val apiException = ApiException.ClientError(
                clientErrorData = ClientErrorData(
                    code = "REQUEST_BACKOFF",
                    info = "Too many verification requests. Wait for the backoff period.",
                    context = mapOf("backoff" to "$backoff")
                ),
                cause = HttpRequestExecutorException.HttpError(400, "")
            )

            coEvery { httpRequestExecutorMock.execute(any()) } returns MIRACLError(apiException)

            // Act
            val result = apiManager.executeVerificationRequest(
                VerificationRequestBody(
                    projectId = randomUuidString(),
                    userId = randomUuidString(),
                    deviceName = randomUuidString(),
                    accessId = null,
                    mpinId = null
                )
            )

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertTrue((result as MIRACLError).value is VerificationException.RequestBackoff)
            val exception = result.value as VerificationException.RequestBackoff
            Assert.assertEquals(backoff, exception.backoff)
        }

    @Test
    fun `executeVerification returns correct MIRACLError when request executor result is REQUEST_BACKOFF client error and there isn't backoff in the context`() =
        runTest {
            // Arrange
            val apiException = ApiException.ClientError(
                clientErrorData = ClientErrorData(
                    code = "REQUEST_BACKOFF",
                    info = "Too many verification requests. Wait for the backoff period.",
                    context = null
                ),
                cause = HttpRequestExecutorException.HttpError(400, "")
            )

            coEvery { httpRequestExecutorMock.execute(any()) } returns MIRACLError(apiException)

            // Act
            val result = apiManager.executeVerificationRequest(
                VerificationRequestBody(
                    projectId = randomUuidString(),
                    userId = randomUuidString(),
                    deviceName = randomUuidString(),
                    accessId = null,
                    mpinId = null
                )
            )

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertTrue((result as MIRACLError).value is VerificationException.VerificationFail)
        }

    @Test
    fun `executeVerification returns MIRACLError when exception is thrown`() =
        runTest {
            // Arrange
            val exception = Exception()
            coEvery { httpRequestExecutorMock.execute(any()) } throws exception

            // Act
            val result = apiManager.executeVerificationRequest(
                VerificationRequestBody(
                    projectId = randomUuidString(),
                    userId = randomUuidString(),
                    deviceName = randomUuidString(),
                    accessId = null,
                    mpinId = null
                )
            )

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertTrue((result as MIRACLError).value is VerificationException.VerificationFail)
            Assert.assertEquals(exception, result.value.cause)
        }

    @Test
    fun `executeQuickCodeVerificationRequest returns MIRACLSuccess`() =
        runTest {
            // Arrange
            val quickCodeVerificationRequestBody = QuickCodeVerificationRequestBody(
                projectId = randomUuidString(),
                jwt = randomUuidString(),
                deviceName = randomUuidString()
            )

            val quickCodeVerificationRequestBodyAsJson =
                KotlinxSerializationJsonUtil.toJsonString(quickCodeVerificationRequestBody)

            val apiRequest = ApiRequest(
                method = HttpMethod.POST,
                headers = null,
                body = quickCodeVerificationRequestBodyAsJson,
                params = null,
                url = apiSettings.quickCodeVerificationUrl
            )

            val quickCodeVerificationResponse = QuickCodeVerificationResponse(
                code = randomUuidString(),
                expireTime = Date().time,
                ttlSeconds = Random.nextInt(1..9999)
            )

            val quickCodeVerificationResponseAsJson =
                KotlinxSerializationJsonUtil.toJsonString(quickCodeVerificationResponse)

            coEvery { httpRequestExecutorMock.execute(apiRequest) } returns MIRACLSuccess(
                quickCodeVerificationResponseAsJson
            )

            // Act
            val result =
                apiManager.executeQuickCodeVerificationRequest(quickCodeVerificationRequestBody)

            // Assert
            Assert.assertTrue(result is MIRACLSuccess)
            Assert.assertEquals(quickCodeVerificationResponse, (result as MIRACLSuccess).value)
        }

    @Test
    fun `executeQuickCodeVerificationRequest returns MIRACLError when networkRequest returns an error`() =
        runTest {
            // Arrange
            val httpRequestExecutorException = ApiException.ExecutionError()
            coEvery {
                httpRequestExecutorMock.execute(any())
            } returns MIRACLError(httpRequestExecutorException)

            // Act
            val result = apiManager.executeQuickCodeVerificationRequest(
                QuickCodeVerificationRequestBody(
                    projectId = randomUuidString(),
                    jwt = randomUuidString(),
                    deviceName = randomUuidString()
                )
            )

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertTrue((result as MIRACLError).value is QuickCodeException.GenerationFail)
            Assert.assertEquals(httpRequestExecutorException, result.value.cause)
        }

    @Test
    fun `executeQuickCodeVerificationRequest returns MIRACLError when exception is thrown`() =
        runTest {
            // Arrange
            val exception = Exception()
            coEvery { httpRequestExecutorMock.execute(any()) } throws exception

            // Act
            val result = apiManager.executeQuickCodeVerificationRequest(
                QuickCodeVerificationRequestBody(
                    projectId = randomUuidString(),
                    jwt = randomUuidString(),
                    deviceName = randomUuidString()
                )
            )

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertTrue((result as MIRACLError).value is QuickCodeException.GenerationFail)
            Assert.assertEquals(exception, result.value.cause)
        }

    @Test
    fun `executeConfirmation returns MIRACLSuccess`() =
        runTest {
            // Arrange
            val confirmationRequestBody = ConfirmationRequestBody(
                userId = randomUuidString(),
                code = randomUuidString()
            )

            val confirmationRequestBodyAsJson =
                KotlinxSerializationJsonUtil.toJsonString(confirmationRequestBody)

            val apiRequest = ApiRequest(
                method = HttpMethod.POST,
                headers = null,
                body = confirmationRequestBodyAsJson,
                params = null,
                url = apiSettings.verificationConfirmationUrl
            )

            val confirmationResponse = ConfirmationResponse(
                projectId = randomUuidString(),
                activateToken = randomUuidString(),
                accessId = randomUuidString()
            )

            val confirmationResponseAsJson =
                KotlinxSerializationJsonUtil.toJsonString(confirmationResponse)

            coEvery { httpRequestExecutorMock.execute(apiRequest) } returns MIRACLSuccess(
                confirmationResponseAsJson
            )

            // Act
            val result = apiManager.executeConfirmationRequest(confirmationRequestBody)

            // Assert
            Assert.assertTrue(result is MIRACLSuccess)
            Assert.assertEquals(confirmationResponse, (result as MIRACLSuccess).value)
        }

    @Test
    fun `executeConfirmation returns MIRACLError when networkRequest returns an error`() =
        runTest {
            // Arrange
            val httpRequestExecutorException = ApiException.ExecutionError()
            coEvery {
                httpRequestExecutorMock.execute(any())
            } returns MIRACLError(httpRequestExecutorException)

            // Act
            val result = apiManager.executeConfirmationRequest(
                ConfirmationRequestBody(
                    userId = randomUuidString(),
                    code = randomUuidString()
                )
            )

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertTrue((result as MIRACLError).value is ActivationTokenException.GetActivationTokenFail)
            Assert.assertEquals(httpRequestExecutorException, result.value.cause)
        }

    @Test
    fun `executeConfirmation returns correct MIRACLError when request executor result is INVALID_VERIFICATION_CODE client error`() =
        runTest {
            // Arrange
            val userId = randomUuidString()
            val accessId = randomUuidString()
            val projectId = randomUuidString()

            val apiException = ApiException.ClientError(
                clientErrorData = ClientErrorData(
                    code = "INVALID_VERIFICATION_CODE",
                    info = "Invalid or expired activation code.",
                    context = mapOf("projectId" to projectId, "accessId" to accessId)
                ),
                cause = HttpRequestExecutorException.HttpError(400, "")
            )

            coEvery { httpRequestExecutorMock.execute(any()) } returns MIRACLError(apiException)

            // Act
            val result = apiManager.executeConfirmationRequest(
                ConfirmationRequestBody(
                    userId = userId,
                    code = randomUuidString()
                )
            )

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertTrue((result as MIRACLError).value is ActivationTokenException.UnsuccessfulVerification)
            val exception = result.value as ActivationTokenException.UnsuccessfulVerification

            Assert.assertEquals(projectId, exception.activationTokenErrorResponse?.projectId)
            Assert.assertEquals(userId, exception.activationTokenErrorResponse?.userId)
            Assert.assertEquals(accessId, exception.activationTokenErrorResponse?.accessId)
        }

    @Test
    fun `executeConfirmation returns correct MIRACLError when request executor result is INVALID_VERIFICATION_CODE client error and there isn't projectId in the context`() =
        runTest {
            // Arrange
            val apiException = ApiException.ClientError(
                clientErrorData = ClientErrorData(
                    code = "INVALID_VERIFICATION_CODE",
                    info = "Invalid or expired activation code.",
                    context = null
                ),
                cause = HttpRequestExecutorException.HttpError(400, "")
            )

            coEvery { httpRequestExecutorMock.execute(any()) } returns MIRACLError(apiException)

            // Act
            val result = apiManager.executeConfirmationRequest(
                ConfirmationRequestBody(
                    userId = randomUuidString(),
                    code = randomUuidString()
                )
            )

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertTrue((result as MIRACLError).value is ActivationTokenException.UnsuccessfulVerification)
            val exception = result.value as ActivationTokenException.UnsuccessfulVerification
            Assert.assertNull(exception.activationTokenErrorResponse)
        }

    @Test
    fun `executeConfirmation returns correct MIRACLError when request executor result is UNSUCCESSFUL_VERIFICATION client error`() =
        runTest {
            // Arrange
            val userId = randomUuidString()
            val accessId = randomUuidString()
            val projectId = randomUuidString()

            val apiException = ApiException.ClientError(
                clientErrorData = ClientErrorData(
                    code = "UNSUCCESSFUL_VERIFICATION",
                    info = "Invalid or expired activation code.",
                    context = mapOf("projectId" to projectId, "accessId" to accessId)
                ),
                cause = HttpRequestExecutorException.HttpError(400, "")
            )

            coEvery { httpRequestExecutorMock.execute(any()) } returns MIRACLError(apiException)

            // Act
            val result = apiManager.executeConfirmationRequest(
                ConfirmationRequestBody(
                    userId = userId,
                    code = randomUuidString()
                )
            )

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertTrue((result as MIRACLError).value is ActivationTokenException.UnsuccessfulVerification)
            val exception = result.value as ActivationTokenException.UnsuccessfulVerification

            Assert.assertEquals(projectId, exception.activationTokenErrorResponse?.projectId)
            Assert.assertEquals(userId, exception.activationTokenErrorResponse?.userId)
            Assert.assertEquals(accessId, exception.activationTokenErrorResponse?.accessId)
        }

    @Test
    fun `executeConfirmation returns correct MIRACLError when request executor result is UNSUCCESSFUL_VERIFICATION client error and there isn't projectId in the context`() =
        runTest {
            // Arrange
            val apiException = ApiException.ClientError(
                clientErrorData = ClientErrorData(
                    code = "UNSUCCESSFUL_VERIFICATION",
                    info = "Invalid or expired activation code.",
                    context = null
                ),
                cause = HttpRequestExecutorException.HttpError(400, "")
            )

            coEvery { httpRequestExecutorMock.execute(any()) } returns MIRACLError(apiException)

            // Act
            val result = apiManager.executeConfirmationRequest(
                ConfirmationRequestBody(
                    userId = randomUuidString(),
                    code = randomUuidString()
                )
            )

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertTrue((result as MIRACLError).value is ActivationTokenException.UnsuccessfulVerification)
            val exception = result.value as ActivationTokenException.UnsuccessfulVerification
            Assert.assertNull(exception.activationTokenErrorResponse)
        }

    @Test
    fun `executeConfirmation returns MIRACLError when exception is thrown`() =
        runTest {
            // Arrange
            val exception = Exception()
            coEvery { httpRequestExecutorMock.execute(any()) } throws exception

            // Act
            val result = apiManager.executeConfirmationRequest(
                ConfirmationRequestBody(
                    userId = randomUuidString(),
                    code = randomUuidString()
                )
            )

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertTrue((result as MIRACLError).value is ActivationTokenException.GetActivationTokenFail)
            Assert.assertEquals(exception, result.value.cause)
        }
}