package com.miracl.trust.session

import com.miracl.trust.MIRACLError
import com.miracl.trust.MIRACLSuccess
import com.miracl.trust.network.ApiException
import com.miracl.trust.network.ApiRequest
import com.miracl.trust.network.ApiRequestExecutor
import com.miracl.trust.network.ApiSettings
import com.miracl.trust.network.HttpMethod
import com.miracl.trust.randomPinLength
import com.miracl.trust.randomUuidString
import com.miracl.trust.util.json.KotlinxSerializationJsonUtil
import io.mockk.clearAllMocks
import io.mockk.coEvery
import io.mockk.mockk
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.SerializationException
import org.junit.Assert
import org.junit.Before
import org.junit.Test
import kotlin.random.Random

@ExperimentalCoroutinesApi
class SessionApiManagerUnitTest {
    private val httpRequestExecutorMock = mockk<ApiRequestExecutor>()
    private val apiSettings = ApiSettings(randomUuidString())

    private val apiManager = SessionApiManager(
        apiRequestExecutor = httpRequestExecutorMock,
        jsonUtil = KotlinxSerializationJsonUtil,
        apiSettings = apiSettings
    )

    @Before
    fun setUp() {
        clearAllMocks()
    }

    @Test
    fun `executeCodeStatusRequest should return MIRACLSuccess when passed data is valid`() =
        runTest {
            // Arrange
            val accessId = randomUuidString()
            val userId = randomUuidString()
            val status = SessionStatus.WID.value

            val codeStatusRequestBody = CodeStatusRequestBody(accessId, status, userId)
            val codeStatusRequestBodyAsJson =
                KotlinxSerializationJsonUtil.toJsonString(codeStatusRequestBody)

            val apiRequest = ApiRequest(
                method = HttpMethod.POST,
                headers = null,
                body = codeStatusRequestBodyAsJson,
                params = null,
                url = apiSettings.codeStatusUrl
            )

            val codeStatusResponse = createCodeStatusResponse()
            val codeStatusResponseAsJson =
                KotlinxSerializationJsonUtil.toJsonString(codeStatusResponse)

            coEvery { httpRequestExecutorMock.execute(apiRequest) } returns MIRACLSuccess(
                codeStatusResponseAsJson
            )

            // Act
            val result = apiManager.executeCodeStatusRequest(accessId, status, userId)

            // Assert
            Assert.assertTrue(result is MIRACLSuccess)
            Assert.assertEquals(codeStatusResponse, (result as MIRACLSuccess).value)
        }

    @Test
    fun `executeCodeStatusRequest returns MIRACLError when networkRequest returns an error`() =
        runTest {
            // Arrange
            val apiException = ApiException.ExecutionError()
            coEvery { httpRequestExecutorMock.execute(any()) } returns MIRACLError(apiException)

            // Act
            val result = apiManager.executeCodeStatusRequest(
                accessId = randomUuidString(),
                status = SessionStatus.WID.value,
                userId = randomUuidString()
            )

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertTrue((result as MIRACLError).value is AuthenticationSessionException.GetAuthenticationSessionDetailsFail)
            Assert.assertEquals(apiException, result.value.cause)
        }

    @Test
    fun `executeCodeStatusRequest returns MIRACLError because of serialization exception`() =
        runTest {
            // Arrange
            coEvery { httpRequestExecutorMock.execute(any()) } returns MIRACLSuccess("invalidJson")

            // Act
            val result = apiManager.executeCodeStatusRequest(
                accessId = randomUuidString(),
                status = SessionStatus.WID.value
            )

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertTrue((result as MIRACLError).value is AuthenticationSessionException.GetAuthenticationSessionDetailsFail)
            Assert.assertTrue(result.value.cause is SerializationException)
        }

    @Test
    fun `executeCodeStatusRequest returns MIRACLError when exception is thrown`() =
        runTest {
            // Arrange
            val exception = Exception()
            coEvery { httpRequestExecutorMock.execute(any()) } throws exception

            // Act
            val result = apiManager.executeCodeStatusRequest(
                accessId = randomUuidString(),
                status = SessionStatus.WID.value
            )

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertTrue((result as MIRACLError).value is AuthenticationSessionException.GetAuthenticationSessionDetailsFail)
            Assert.assertEquals(exception, result.value.cause)
        }

    @Test
    fun `executeAbortSessionRequest should return MIRACLSuccess when passed data is valid`() =
        runTest {
            // Arrange
            val accessId = randomUuidString()
            val status = SessionStatus.ABORT.value

            val codeStatusRequestBody = CodeStatusRequestBody(accessId, status)
            val codeStatusRequestBodyAsJson =
                KotlinxSerializationJsonUtil.toJsonString(codeStatusRequestBody)

            val apiRequest = ApiRequest(
                method = HttpMethod.POST,
                headers = null,
                body = codeStatusRequestBodyAsJson,
                params = null,
                url = apiSettings.codeStatusUrl
            )
            coEvery { httpRequestExecutorMock.execute(apiRequest) } returns MIRACLSuccess("")

            // Act
            val result = apiManager.executeAbortSessionRequest(accessId)

            // Assert
            Assert.assertTrue(result is MIRACLSuccess)
        }

    @Test
    fun `executeAbortSessionRequest returns MIRACLError when networkRequest returns an error`() =
        runTest {
            // Arrange
            val apiException = ApiException.ExecutionError()
            coEvery { httpRequestExecutorMock.execute(any()) } returns MIRACLError(apiException)

            // Act
            val result = apiManager.executeAbortSessionRequest(randomUuidString())

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertTrue((result as MIRACLError).value is AuthenticationSessionException.AbortSessionFail)
            Assert.assertEquals(apiException, result.value.cause)
        }

    @Test
    fun `executeAbortSessionRequest returns MIRACLError when exception is thrown`() =
        runTest {
            // Arrange
            val exception = Exception()
            coEvery { httpRequestExecutorMock.execute(any()) } throws exception

            // Act
            val result = apiManager.executeAbortSessionRequest(randomUuidString())

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertTrue((result as MIRACLError).value is AuthenticationSessionException.AbortSessionFail)
            Assert.assertEquals(exception, result.value.cause)
        }

    @Test
    fun `executeUpdateSessionRequest should return MIRACLSuccess when passed data is valid`() =
        runTest {
            // Arrange
            val accessId = randomUuidString()
            val userId = randomUuidString()
            val status = SessionStatus.USER.value

            val codeStatusRequestBody = CodeStatusRequestBody(accessId, status, userId)
            val codeStatusRequestBodyAsJson =
                KotlinxSerializationJsonUtil.toJsonString(codeStatusRequestBody)

            val apiRequest = ApiRequest(
                method = HttpMethod.POST,
                headers = null,
                body = codeStatusRequestBodyAsJson,
                params = null,
                url = apiSettings.codeStatusUrl
            )
            coEvery { httpRequestExecutorMock.execute(apiRequest) } returns MIRACLSuccess("")

            // Act
            val result = apiManager.executeUpdateSessionRequest(accessId, userId)

            // Assert
            Assert.assertTrue(result is MIRACLSuccess)
        }

    @Test
    fun `executeUpdateSessionRequest returns MIRACLError when networkRequest returns an error`() =
        runTest {
            // Arrange
            val apiException = ApiException.ExecutionError()
            coEvery { httpRequestExecutorMock.execute(any()) } returns MIRACLError(apiException)

            // Act
            val result =
                apiManager.executeUpdateSessionRequest(randomUuidString(), randomUuidString())

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertEquals(apiException, (result as MIRACLError).value)
        }

    @Test
    fun `executeUpdateSessionRequest returns MIRACLError when exception is thrown`() =
        runTest {
            // Arrange
            val exception = Exception()
            coEvery { httpRequestExecutorMock.execute(any()) } throws exception

            // Act
            val result =
                apiManager.executeUpdateSessionRequest(randomUuidString(), randomUuidString())

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertEquals(exception, (result as MIRACLError).value)
        }

    private fun createCodeStatusResponse() = CodeStatusResponse(
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