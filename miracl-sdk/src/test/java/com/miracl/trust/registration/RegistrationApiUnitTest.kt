package com.miracl.trust.registration

import com.miracl.trust.MIRACLError
import com.miracl.trust.MIRACLSuccess
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
    private val apiSettings = ApiSettings(randomUuidString())

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
                activationToken = randomUuidString(),
                publicKey = randomHexString(),
                deviceTag = randomHexString()
            )
            val capturingSlot = CapturingSlot<ApiRequest>()
            val registerResponse = RegisterResponse(
                mpinId = randomUuidString(),
                projectId = projectId,
                designatedTAs = listOf(
                    DesignatedTA(randomUuidString(), randomUuidString()),
                    DesignatedTA(randomUuidString(), randomUuidString())
                )
            )
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
                activationToken = randomUuidString(),
                publicKey = randomHexString(),
                deviceTag = randomHexString()
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
                activationToken = randomUuidString(),
                publicKey = randomHexString(),
                deviceTag = randomHexString()
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
                activationToken = randomUuidString(),
                publicKey = randomHexString(),
                deviceTag = randomHexString()
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
                activationToken = randomUuidString(),
                publicKey = randomHexString(),
                deviceTag = randomHexString()
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
    fun `executeTAShareRequest should return MIRACLSuccess with DVSClientSecretResponse when passed data is valid`() =
        runTest {
            // Arrange
            val designatedTA = DesignatedTA(randomUuidString(), randomUuidString())
            val taShareRequestBody = TAShareRequestBody(randomHexString(), randomHexString())

            val capturingSlot = CapturingSlot<ApiRequest>()
            val taShareResponse =
                TAShareResponse(node = randomUuidString(), share = randomHexString())
            val taShareResponseAsJson = jsonUtil.toJsonString(taShareResponse)
            coEvery {
                httpRequestExecutorMock.execute(capture(capturingSlot))
            } returns MIRACLSuccess(taShareResponseAsJson)

            // Act
            val result = registrationApi.executeTAShareRequest(designatedTA, taShareRequestBody)

            // Assert
            Assert.assertTrue(result is MIRACLSuccess)
            Assert.assertEquals(taShareResponse.node, (result as MIRACLSuccess).value.node)
            Assert.assertEquals(taShareResponse.share, result.value.share)

            Assert.assertEquals(designatedTA.url, capturingSlot.captured.url)
            Assert.assertEquals(
                "Bearer ${designatedTA.token}",
                capturingSlot.captured.headers?.get("Authorization")
            )
        }

    @Test
    fun `executeTAShareRequest should return MIRACLError when http executor returns an error`() =
        runTest {
            // Arrange
            val designatedTA = DesignatedTA(randomUuidString(), randomUuidString())
            val taShareRequestBody = TAShareRequestBody(randomHexString(), randomHexString())

            val httpRequestExecutorException = ApiException.ClientError()
            val executorResult = MIRACLError<String, ApiException>(
                value = httpRequestExecutorException
            )
            coEvery {
                httpRequestExecutorMock.execute(any())
            } returns executorResult

            // Act
            val result = registrationApi.executeTAShareRequest(designatedTA, taShareRequestBody)

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertTrue((result as MIRACLError).value is RegistrationException.RegistrationFail)
            Assert.assertEquals(httpRequestExecutorException, result.value.cause)
        }

    @Test
    fun `executeTAShareRequest should return MIRACLError when exception is thrown during execution`() =
        runTest {
            // Arrange
            val designatedTA = DesignatedTA(randomUuidString(), randomUuidString())
            val taShareRequestBody = TAShareRequestBody(randomHexString(), randomHexString())

            val exception = Exception(randomUuidString())
            coEvery {
                httpRequestExecutorMock.execute(any())
            } throws exception

            // Act
            val result = registrationApi.executeTAShareRequest(designatedTA, taShareRequestBody)

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertTrue((result as MIRACLError).value is RegistrationException.RegistrationFail)
            Assert.assertEquals(exception, result.value.cause)
        }

    @Test
    fun `executeTAShareRequest should return MIRACLError when json received from server is not valid`() =
        runTest {
            // Arrange
            val designatedTA = DesignatedTA(randomUuidString(), randomUuidString())
            val taShareRequestBody = TAShareRequestBody(randomHexString(), randomHexString())

            val jsonString = "invalid json string"
            val executorResult = MIRACLSuccess<String, ApiException>(
                value = jsonString
            )
            coEvery {
                httpRequestExecutorMock.execute(any())
            } returns executorResult

            // Act
            val result = registrationApi.executeTAShareRequest(designatedTA, taShareRequestBody)

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertTrue((result as MIRACLError).value is RegistrationException.RegistrationFail)
            Assert.assertTrue(result.value.cause is SerializationException)
        }
}
