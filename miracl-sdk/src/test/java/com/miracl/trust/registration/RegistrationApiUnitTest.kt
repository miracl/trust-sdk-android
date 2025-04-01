package com.miracl.trust.registration

import com.miracl.trust.BuildConfig
import com.miracl.trust.MIRACLError
import com.miracl.trust.MIRACLSuccess
import com.miracl.trust.crypto.SupportedEllipticCurves
import com.miracl.trust.network.ApiException
import com.miracl.trust.network.ApiRequest
import com.miracl.trust.network.ApiRequestExecutor
import com.miracl.trust.network.ApiSettings
import com.miracl.trust.network.ClientErrorData
import com.miracl.trust.randomHexString
import com.miracl.trust.randomUuidString
import com.miracl.trust.util.json.KotlinxSerializationJsonUtil
import io.mockk.CapturingSlot
import io.mockk.clearAllMocks
import io.mockk.coEvery
import io.mockk.mockk
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.SerializationException
import org.junit.Assert
import org.junit.Before
import org.junit.Test

@ExperimentalCoroutinesApi
class RegistrationApiUnitTest {
    private val httpRequestExecutorMock = mockk<ApiRequestExecutor>()
    private val jsonUtil = KotlinxSerializationJsonUtil
    private val apiSettings = ApiSettings(BuildConfig.BASE_URL)

    private val registrationApi =
        RegistrationApiManager(httpRequestExecutorMock, jsonUtil, apiSettings)

    @Before
    fun resetMocks() {
        clearAllMocks()
    }

    @Test
    fun `executeRegisterRequest should return MIRACLSuccess with RegisterResponse when passed registerRequest is valid`() =
        runTest {
            // Arrange
            val projectId = randomUuidString()

            val registerRequestBody = RegisterRequestBody(
                userId = randomUuidString(),
                deviceName = randomUuidString(),
                activationToken = randomUuidString()
            )
            val capturingSlot = CapturingSlot<ApiRequest>()
            val registerResponse =
                RegisterResponse(randomUuidString(), projectId, randomUuidString())
            val registerResponseAsJson = jsonUtil.toJsonString(registerResponse)
            coEvery {
                httpRequestExecutorMock.execute(capture(capturingSlot))
            } returns MIRACLSuccess(registerResponseAsJson)

            // Act
            val result = registrationApi.executeRegisterRequest(registerRequestBody, projectId)

            // Assert
            Assert.assertTrue(result is MIRACLSuccess)
            Assert.assertEquals(registerResponse, (result as MIRACLSuccess).value)

            val pass1RequestBodyAsJson = jsonUtil.toJsonString(registerRequestBody)
            Assert.assertEquals(pass1RequestBodyAsJson, capturingSlot.captured.body)
        }

    @Test
    fun `executeRegisterRequest should return MIRACLError when request is valid but the response body from server is not a valid json`() =
        runTest {
            // Arrange
            val projectId = randomUuidString()

            val registerRequestBody = RegisterRequestBody(
                userId = randomUuidString(),
                deviceName = randomUuidString(),
                activationToken = randomUuidString()
            )
            val jsonString = "invalid json"
            val executorResult = MIRACLSuccess<String, ApiException>(
                value = jsonString
            )
            coEvery {
                httpRequestExecutorMock.execute(any())
            } returns executorResult

            // Act
            val result = registrationApi.executeRegisterRequest(registerRequestBody, projectId)

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertTrue((result as MIRACLError).value is RegistrationException.RegistrationFail)
            Assert.assertTrue(result.value.cause is SerializationException)
        }

    @Test
    fun `executeRegisterRequest should return MIRACLError when http request executor returns an error`() =
        runTest {
            // Arrange
            val projectId = randomUuidString()
            val registerRequestBody = RegisterRequestBody(
                userId = randomUuidString(),
                deviceName = randomUuidString(),
                activationToken = randomUuidString()
            )
            val httpRequestExecutorException = ApiException.ExecutionError()
            val executorResult = MIRACLError<String, ApiException>(
                value = httpRequestExecutorException
            )

            coEvery {
                httpRequestExecutorMock.execute(any())
            } returns executorResult
            // Act
            val result = registrationApi.executeRegisterRequest(registerRequestBody, projectId)

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertTrue((result as MIRACLError).value is RegistrationException.RegistrationFail)
            Assert.assertEquals(httpRequestExecutorException, result.value.cause)
        }

    @Test
    fun `executeRegisterRequest should return correct MIRACLError when ApiException contains INVALID_ACTIVATION_TOKEN client error`() =
        runTest {
            // Arrange
            val projectId = randomUuidString()
            val registerRequestBody = RegisterRequestBody(
                userId = randomUuidString(),
                deviceName = randomUuidString(),
                activationToken = randomUuidString()
            )

            val apiException =
                ApiException.ClientError(
                    clientErrorData = ClientErrorData(
                        code = "INVALID_ACTIVATION_TOKEN",
                        info = "The provided user ID or activation token are invalid.",
                        context = null
                    )
                )
            coEvery {
                httpRequestExecutorMock.execute(any())
            } returns MIRACLError(value = apiException)

            // Act
            val result = registrationApi.executeRegisterRequest(registerRequestBody, projectId)

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertTrue((result as MIRACLError).value is RegistrationException.InvalidActivationToken)
        }

    @Test
    fun `executeRegisterRequest should return MIRACLError when http request executor throws exception`() =
        runTest {
            // Arrange
            val projectId = randomUuidString()
            val registerRequestBody = RegisterRequestBody(
                userId = randomUuidString(),
                deviceName = randomUuidString(),
                activationToken = randomUuidString()
            )
            val exceptionMessage = "Unexpected exception"
            val exception = Exception(exceptionMessage)
            coEvery {
                httpRequestExecutorMock.execute(any())
            } throws exception

            // Act
            val result = registrationApi.executeRegisterRequest(registerRequestBody, projectId)

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertTrue((result as MIRACLError).value is RegistrationException.RegistrationFail)
            Assert.assertEquals(exception, result.value.cause)
        }

    @Test
    fun `executeSignatureRequest should return MIRACLSuccess with SignatureResponse when passed registerResponse is valid`() =
        runTest {
            // Arrange
            val mpinId = randomHexString()
            val regOTT = randomUuidString()
            val publicKey = randomHexString()

            val capturingSlot = CapturingSlot<ApiRequest>()
            val signatureResponse = SignatureResponse(
                dvsClientSecretShare = randomHexString(),
                clientSecret2Url = randomUuidString(),
                dtas = randomUuidString(),
                curve = SupportedEllipticCurves.BN254CX.name
            )
            val signatureResponseAsJson = jsonUtil.toJsonString(signatureResponse)
            coEvery {
                httpRequestExecutorMock.execute(capture(capturingSlot))
            } returns MIRACLSuccess(signatureResponseAsJson)

            // Act
            val result = registrationApi.executeSignatureRequest(mpinId, regOTT, publicKey)

            // Assert
            Assert.assertTrue(result is MIRACLSuccess)
            Assert.assertEquals(signatureResponse, (result as MIRACLSuccess).value)

            Assert.assertEquals(regOTT, capturingSlot.captured.params?.get("regOTT"))
            Assert.assertEquals(publicKey, capturingSlot.captured.params?.get("publicKey"))

            val signatureUrl = "${apiSettings.signatureUrl}/$mpinId"
            Assert.assertEquals(signatureUrl, capturingSlot.captured.url)
        }

    @Test
    fun `executeSignatureRequest should return MIRACLError when httpRequestExecutor throws exception`() =
        runTest {
            // Arrange
            val exceptionMessage = randomUuidString()
            val exception = Exception(exceptionMessage)
            coEvery {
                httpRequestExecutorMock.execute(any())
            } throws exception

            // Act
            val result = registrationApi.executeSignatureRequest(
                mpinId = randomHexString(),
                regOTT = randomUuidString(),
                publicKey = randomHexString()
            )

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertTrue((result as MIRACLError).value is RegistrationException.RegistrationFail)
            Assert.assertEquals(exception, result.value.cause)
        }

    @Test
    fun `executeSignatureRequest should return MIRACLError when http executor returns error`() =
        runTest {
            // Arrange
            val httpRequestExecutorException = ApiException.ExecutionError()
            val executorResult = MIRACLError<String, ApiException>(httpRequestExecutorException)
            coEvery {
                httpRequestExecutorMock.execute(any())
            } returns executorResult

            // Act
            val result = registrationApi.executeSignatureRequest(
                mpinId = randomHexString(),
                regOTT = randomUuidString(),
                publicKey = randomHexString()
            )

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertTrue((result as MIRACLError).value is RegistrationException.RegistrationFail)
            Assert.assertEquals(httpRequestExecutorException, result.value.cause)
        }

    @Test
    fun `executeSignatureRequest should return MIRACLError when response from server is not a valid json`() =
        runTest {
            // Arrange
            val jsonString = "invalid json"
            val executorResult = MIRACLSuccess<String, ApiException>(
                value = jsonString
            )
            coEvery {
                httpRequestExecutorMock.execute(any())
            } returns executorResult

            // Act
            val result = registrationApi.executeSignatureRequest(
                mpinId = randomHexString(),
                regOTT = randomUuidString(),
                publicKey = randomHexString()
            )

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertTrue((result as MIRACLError).value is RegistrationException.RegistrationFail)
            Assert.assertTrue(result.value.cause is SerializationException)
        }

    @Test
    fun `executeClientSecretRequest should return MIRACLSuccess with ClientSecretShare2Response when passed cs2Url is valid`() =
        runTest {
            // Arrange
            val clientSecret2Url = randomUuidString()
            val projectId = randomUuidString()

            val capturingSlot = CapturingSlot<ApiRequest>()
            val dvsClientSecret2Response =
                DVSClientSecret2Response(dvsClientSecret = randomHexString())
            val dvsClientSecret2ResponseAsJson = jsonUtil.toJsonString(dvsClientSecret2Response)
            coEvery {
                httpRequestExecutorMock.execute(capture(capturingSlot))
            } returns MIRACLSuccess(dvsClientSecret2ResponseAsJson)

            // Act
            val result = registrationApi.executeDVSClientSecret2Request(clientSecret2Url, projectId)

            // Assert
            Assert.assertTrue(result is MIRACLSuccess)
            Assert.assertTrue((result as MIRACLSuccess).value.dvsClientSecret.isNotBlank())

            Assert.assertEquals(clientSecret2Url, capturingSlot.captured.url)
        }

    @Test
    fun `executeClientSecretRequest should return MIRACLError when http executor returns an error`() =
        runTest {
            // Arrange
            val clientSecret2Url = randomUuidString()
            val projectId = randomUuidString()
            val httpRequestExecutorException = ApiException.ExecutionError()
            val executorResult = MIRACLError<String, ApiException>(
                value = httpRequestExecutorException
            )
            coEvery {
                httpRequestExecutorMock.execute(any())
            } returns executorResult

            // Act
            val result = registrationApi.executeDVSClientSecret2Request(clientSecret2Url, projectId)

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertTrue((result as MIRACLError).value is RegistrationException.RegistrationFail)
            Assert.assertEquals(httpRequestExecutorException, result.value.cause)
        }

    @Test
    fun `executeClientSecretRequest should return MIRACLError when exception is thrown during execution`() =
        runTest {
            // Arrange
            val clientSecret2Url = randomUuidString()
            val projectId = randomUuidString()
            val exception = Exception(randomUuidString())
            coEvery {
                httpRequestExecutorMock.execute(any())
            } throws exception

            // Act
            val result = registrationApi.executeDVSClientSecret2Request(clientSecret2Url, projectId)

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertTrue((result as MIRACLError).value is RegistrationException.RegistrationFail)
            Assert.assertEquals(exception, result.value.cause)
        }

    @Test
    fun `executeClientSecretRequest should return MIRACLError when json received from server is not valid`() =
        runTest {
            // Arrange
            val clientSecret2Url = randomUuidString()
            val projectId = randomUuidString()
            val jsonString = "invalid json string"
            val executorResult = MIRACLSuccess<String, ApiException>(
                value = jsonString
            )
            coEvery {
                httpRequestExecutorMock.execute(any())
            } returns executorResult

            // Act
            val result = registrationApi.executeDVSClientSecret2Request(clientSecret2Url, projectId)

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertTrue((result as MIRACLError).value is RegistrationException.RegistrationFail)
            Assert.assertTrue(result.value.cause is SerializationException)
        }
}
