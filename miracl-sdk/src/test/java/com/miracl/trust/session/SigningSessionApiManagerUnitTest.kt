package com.miracl.trust.session

import com.miracl.trust.MIRACLError
import com.miracl.trust.MIRACLSuccess
import com.miracl.trust.network.ApiException
import com.miracl.trust.network.ApiRequest
import com.miracl.trust.network.ApiRequestExecutor
import com.miracl.trust.network.ApiSettings
import com.miracl.trust.network.ClientErrorData
import com.miracl.trust.network.HttpMethod
import com.miracl.trust.randomHexString
import com.miracl.trust.randomPinLength
import com.miracl.trust.randomUuidString
import com.miracl.trust.signing.Signature
import com.miracl.trust.util.json.KotlinxSerializationJsonUtil
import com.miracl.trust.util.secondsSince1970
import io.mockk.clearAllMocks
import io.mockk.coEvery
import io.mockk.mockk
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.SerializationException
import org.junit.Assert
import org.junit.Before
import org.junit.Test
import java.util.Date
import kotlin.random.Random

@ExperimentalCoroutinesApi
class SigningSessionApiManagerUnitTest {
    private val httpRequestExecutorMock = mockk<ApiRequestExecutor>()
    private val apiSettings = ApiSettings(randomUuidString())

    private val apiManager = SigningSessionApiManager(
        apiRequestExecutor = httpRequestExecutorMock,
        jsonUtil = KotlinxSerializationJsonUtil,
        apiSettings = apiSettings
    )

    private val sessionId = randomUuidString()
    private val timestamp = Date().secondsSince1970()
    private val signature = Signature(
        mpinId = randomHexString(),
        U = randomHexString(),
        V = randomHexString(),
        publicKey = randomHexString(),
        dtas = randomUuidString(),
        hash = randomHexString(),
        timestamp = timestamp
    )

    @Before
    fun setUp() {
        clearAllMocks()
    }

    @Test
    fun `executeSigningSessionDetailsRequest should return MIRACLSuccess when passed data is valid`() =
        runTest {
            // Arrange
            val signingSessionDetailsRequestBody = SigningSessionDetailsRequestBody(sessionId)
            val signingSessionDetailsRequestBodyAsJson =
                KotlinxSerializationJsonUtil.toJsonString(signingSessionDetailsRequestBody)

            val apiRequest = ApiRequest(
                method = HttpMethod.POST,
                headers = null,
                body = signingSessionDetailsRequestBodyAsJson,
                params = null,
                url = apiSettings.signingSessionDetailsUrl
            )

            val signingSessionDetailsResponse = createSigningSessionDetailsResponse()
            val signingSessionDetailsResponseAsJson =
                KotlinxSerializationJsonUtil.toJsonString(signingSessionDetailsResponse)

            coEvery { httpRequestExecutorMock.execute(apiRequest) } returns MIRACLSuccess(
                signingSessionDetailsResponseAsJson
            )

            // Act
            val result = apiManager.executeSigningSessionDetailsRequest(sessionId)

            // Assert
            Assert.assertTrue(result is MIRACLSuccess)
            Assert.assertEquals(signingSessionDetailsResponse, (result as MIRACLSuccess).value)
        }

    @Test
    fun `executeSigningSessionDetailsRequest returns MIRACLError when networkRequest returns an error`() =
        runTest {
            // Arrange
            val apiException = ApiException.ExecutionError()
            coEvery { httpRequestExecutorMock.execute(any()) } returns MIRACLError(apiException)

            // Act
            val result =
                apiManager.executeSigningSessionDetailsRequest(sessionId)

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertTrue((result as MIRACLError).value is SigningSessionException.GetSigningSessionDetailsFail)
            Assert.assertEquals(apiException, result.value.cause)
        }

    @Test
    fun `executeSigningSessionDetailsRequest should return correct MIRACLError when networkRequest result is INVALID_REQUEST_PARAMETERS client error`() =
        runTest {
            // Arrange
            val apiException =
                ApiException.ClientError(
                    clientErrorData = ClientErrorData(
                        code = "INVALID_REQUEST_PARAMETERS",
                        info = "Missing or invalid parameters from the request.",
                        context = mapOf("params" to "id")
                    )
                )

            coEvery { httpRequestExecutorMock.execute(any()) } returns MIRACLError(apiException)

            // Act
            val result =
                apiManager.executeSigningSessionDetailsRequest(sessionId)

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertTrue((result as MIRACLError).value is SigningSessionException.InvalidSigningSession)
        }

    @Test
    fun `executeSigningSessionDetailsRequest returns MIRACLError because of JSONException`() =
        runTest {
            // Arrange
            coEvery { httpRequestExecutorMock.execute(any()) } returns MIRACLSuccess("invalidJson")

            // Act
            val result = apiManager.executeSigningSessionDetailsRequest(sessionId)

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertTrue((result as MIRACLError).value is SigningSessionException.GetSigningSessionDetailsFail)
            Assert.assertTrue(result.value.cause is SerializationException)
        }

    @Test
    fun `executeSigningSessionDetailsRequest returns MIRACLError when exception is thrown`() =
        runTest {
            // Arrange
            val exception = Exception()
            coEvery { httpRequestExecutorMock.execute(any()) } throws exception

            // Act
            val result = apiManager.executeSigningSessionDetailsRequest(sessionId)

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertTrue((result as MIRACLError).value is SigningSessionException.GetSigningSessionDetailsFail)
            Assert.assertEquals(exception, result.value.cause)
        }

    @Test
    fun `executeSigningSessionUpdateRequest should return MIRACLSuccess when passed data is valid`() =
        runTest {
            // Arrange
            val signingSessionUpdateRequestBody =
                SigningSessionUpdateRequestBody(sessionId, signature, timestamp)

            val signingSessionUpdateRequestBodyAsJson =
                KotlinxSerializationJsonUtil.toJsonString(signingSessionUpdateRequestBody)

            val apiRequest = ApiRequest(
                method = HttpMethod.PUT,
                headers = null,
                body = signingSessionUpdateRequestBodyAsJson,
                params = null,
                url = apiSettings.signingSessionUrl
            )

            val signingSessionUpdateResponse =
                SigningSessionUpdateResponse(SigningSessionStatus.Active.name)

            val signingSessionUpdateResponseAsJson =
                KotlinxSerializationJsonUtil.toJsonString(signingSessionUpdateResponse)

            val executeApiRequestResult =
                MIRACLSuccess<String, ApiException>(signingSessionUpdateResponseAsJson)

            coEvery { httpRequestExecutorMock.execute(apiRequest) } returns executeApiRequestResult

            // Act
            val result =
                apiManager.executeSigningSessionUpdateRequest(sessionId, signature, timestamp)

            // Assert
            Assert.assertTrue(result is MIRACLSuccess)
            Assert.assertEquals(signingSessionUpdateResponse, (result as MIRACLSuccess).value)
        }

    @Test
    fun `executeSigningSessionUpdateRequest returns MIRACLError when networkRequest returns an error`() =
        runTest {
            // Arrange
            val apiException = ApiException.ExecutionError()
            coEvery { httpRequestExecutorMock.execute(any()) } returns MIRACLError(apiException)

            // Act
            val result = apiManager.executeSigningSessionUpdateRequest(
                sessionId,
                signature,
                timestamp
            )

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertTrue((result as MIRACLError).value is SigningSessionException.CompleteSigningSessionFail)
            Assert.assertEquals(apiException, result.value.cause)
        }

    @Test
    fun `executeSigningSessionUpdateRequest should return correct MIRACLError when networkRequest result is INVALID_REQUEST_PARAMETERS client error`() =
        runTest {
            // Arrange
            val apiException =
                ApiException.ClientError(
                    clientErrorData = ClientErrorData(
                        code = "INVALID_REQUEST_PARAMETERS",
                        info = "Missing or invalid parameters from the request.",
                        context = mapOf("params" to "id")
                    )
                )

            coEvery { httpRequestExecutorMock.execute(any()) } returns MIRACLError(apiException)

            // Act
            val result = apiManager.executeSigningSessionUpdateRequest(
                sessionId,
                signature,
                timestamp
            )

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertTrue((result as MIRACLError).value is SigningSessionException.InvalidSigningSession)
        }

    @Test
    fun `executeSigningSessionUpdateRequest returns MIRACLError because of serialization exception`() =
        runTest {
            // Arrange
            coEvery { httpRequestExecutorMock.execute(any()) } returns MIRACLSuccess("invalidJson")

            // Act
            val result = apiManager.executeSigningSessionUpdateRequest(
                sessionId,
                signature,
                timestamp
            )

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertTrue((result as MIRACLError).value is SigningSessionException.CompleteSigningSessionFail)
            Assert.assertTrue(result.value.cause is SerializationException)
        }

    @Test
    fun `executeSigningSessionUpdateRequest returns MIRACLError when exception is thrown`() =
        runTest {
            // Arrange
            val exception = Exception()
            coEvery { httpRequestExecutorMock.execute(any()) } throws exception

            // Act
            val result = apiManager.executeSigningSessionUpdateRequest(
                sessionId,
                signature,
                timestamp
            )

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertTrue((result as MIRACLError).value is SigningSessionException.CompleteSigningSessionFail)
            Assert.assertEquals(exception, result.value.cause)
        }

    @Test
    fun `executeSigningSessionAbortRequest should return MIRACLSuccess when passed data is valid`() =
        runTest {
            // Arrange
            val signingSessionAbortRequestBody = SigningSessionAbortRequestBody(sessionId)
            val signingSessionAbortRequestBodyAsJson =
                KotlinxSerializationJsonUtil.toJsonString(signingSessionAbortRequestBody)

            val apiRequest = ApiRequest(
                method = HttpMethod.DELETE,
                headers = null,
                body = signingSessionAbortRequestBodyAsJson,
                params = null,
                url = apiSettings.signingSessionUrl
            )

            val executeApiRequestResult = MIRACLSuccess<String, ApiException>("")
            coEvery { httpRequestExecutorMock.execute(apiRequest) } returns executeApiRequestResult

            // Act
            val result = apiManager.executeSigningSessionAbortRequest(sessionId)

            // Assert
            Assert.assertTrue(result is MIRACLSuccess)
        }

    @Test
    fun `executeSigningSessionAbortRequest returns MIRACLError when networkRequest returns an error`() =
        runTest {
            // Arrange
            val apiException = ApiException.ExecutionError()
            coEvery { httpRequestExecutorMock.execute(any()) } returns MIRACLError(apiException)

            // Act
            val result = apiManager.executeSigningSessionAbortRequest(sessionId)

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertTrue((result as MIRACLError).value is SigningSessionException.AbortSigningSessionFail)
            Assert.assertEquals(apiException, result.value.cause)
        }

    @Test
    fun `executeSigningSessionAbortRequest should return correct MIRACLError when networkRequest result is INVALID_REQUEST_PARAMETERS client error`() =
        runTest {
            // Arrange
            val apiException =
                ApiException.ClientError(
                    clientErrorData = ClientErrorData(
                        code = "INVALID_REQUEST_PARAMETERS",
                        info = "Missing or invalid parameters from the request.",
                        context = mapOf("params" to "id")
                    )
                )

            coEvery { httpRequestExecutorMock.execute(any()) } returns MIRACLError(apiException)

            // Act
            val result = apiManager.executeSigningSessionAbortRequest(sessionId)

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertTrue((result as MIRACLError).value is SigningSessionException.InvalidSigningSession)
        }

    @Test
    fun `executeSigningSessionAbortRequest returns MIRACLError when exception is thrown`() =
        runTest {
            // Arrange
            val exception = Exception()
            coEvery { httpRequestExecutorMock.execute(any()) } throws exception

            // Act
            val result = apiManager.executeSigningSessionAbortRequest(sessionId)

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertTrue((result as MIRACLError).value is SigningSessionException.AbortSigningSessionFail)
            Assert.assertEquals(exception, result.value.cause)
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
        verificationMethod = VerificationMethod.FullCustom.name,
        verificationUrl = randomUuidString(),
        verificationCustomText = randomUuidString(),
        identityType = IdentityType.Email.name,
        identityTypeLabel = randomUuidString(),
        pinLength = randomPinLength(),
        quickCodeEnabled = Random.nextBoolean()
    )
}