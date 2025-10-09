package com.miracl.trust.session

import android.util.Base64
import com.miracl.trust.MIRACLError
import com.miracl.trust.MIRACLSuccess
import com.miracl.trust.network.ApiException
import com.miracl.trust.network.ApiRequest
import com.miracl.trust.network.ApiRequestExecutor
import com.miracl.trust.network.ApiSettings
import com.miracl.trust.network.HttpMethod
import com.miracl.trust.randomHexString
import com.miracl.trust.randomPinLength
import com.miracl.trust.randomUuidString
import com.miracl.trust.signing.Signature
import com.miracl.trust.util.json.KotlinxSerializationJsonUtil
import com.miracl.trust.util.secondsSince1970
import io.mockk.clearAllMocks
import io.mockk.coEvery
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkStatic
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.SerializationException
import org.junit.Assert
import org.junit.Before
import org.junit.Test
import java.util.Date
import kotlin.random.Random

class CrossDeviceSessionApiManagerUnitTest {
    private val httpRequestExecutorMock = mockk<ApiRequestExecutor>()
    private val apiSettings = ApiSettings(randomUuidString())

    private val apiManager = CrossDeviceSessionApiManager(
        apiRequestExecutor = httpRequestExecutorMock,
        jsonUtil = KotlinxSerializationJsonUtil,
        apiSettings = apiSettings
    )

    @Before
    fun setUp() {
        clearAllMocks()
    }

    @Test
    fun `executeGetSessionRequest should return MIRACLSuccess when passed data is valid`() =
        runTest {
            // Arrange
            val sessionId = randomUuidString()
            val status = CrossDeviceSessionStatus.WID.value

            val crossDeviceSessionRequestBody = CrossDeviceSessionRequestBody(sessionId, status)
            val crossDeviceSessionRequestBodyAsJson =
                KotlinxSerializationJsonUtil.toJsonString(crossDeviceSessionRequestBody)

            val apiRequest = ApiRequest(
                method = HttpMethod.POST,
                headers = null,
                body = crossDeviceSessionRequestBodyAsJson,
                params = null,
                url = apiSettings.codeStatusUrl
            )

            val crossDeviceSessionResponse = createCrossDeviceSessionResponse()
            val crossDeviceSessionResponseAsJson =
                KotlinxSerializationJsonUtil.toJsonString(crossDeviceSessionResponse)

            coEvery { httpRequestExecutorMock.execute(apiRequest) } returns MIRACLSuccess(
                crossDeviceSessionResponseAsJson
            )

            // Act
            val result = apiManager.executeGetSessionRequest(sessionId)

            // Assert
            Assert.assertTrue(result is MIRACLSuccess)
            Assert.assertEquals(crossDeviceSessionResponse, (result as MIRACLSuccess).value)
        }

    @Test
    fun `executeGetSessionRequest returns MIRACLError when networkRequest returns an error`() =
        runTest {
            // Arrange
            val apiException = ApiException.ExecutionError()
            coEvery { httpRequestExecutorMock.execute(any()) } returns MIRACLError(apiException)

            // Act
            val result = apiManager.executeGetSessionRequest(sessionId = randomUuidString())

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertTrue((result as MIRACLError).value is CrossDeviceSessionException.GetCrossDeviceSessionFail)
            Assert.assertEquals(apiException, result.value.cause)
        }

    @Test
    fun `executeGetSessionRequest returns MIRACLError because of serialization exception`() =
        runTest {
            // Arrange
            coEvery { httpRequestExecutorMock.execute(any()) } returns MIRACLSuccess("invalidJson")

            // Act
            val result = apiManager.executeGetSessionRequest(sessionId = randomUuidString())

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertTrue((result as MIRACLError).value is CrossDeviceSessionException.GetCrossDeviceSessionFail)
            Assert.assertTrue(result.value.cause is SerializationException)
        }

    @Test
    fun `executeGetSessionRequest returns MIRACLError when exception is thrown`() =
        runTest {
            // Arrange
            val exception = Exception()
            coEvery { httpRequestExecutorMock.execute(any()) } throws exception

            // Act
            val result = apiManager.executeGetSessionRequest(sessionId = randomUuidString())

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertTrue((result as MIRACLError).value is CrossDeviceSessionException.GetCrossDeviceSessionFail)
            Assert.assertEquals(exception, result.value.cause)
        }

    @Test
    fun `executeUpdateCrossDeviceSessionForSigningRequest should return MIRACLSuccess when passed data is valid`() =
        runTest {
            // Arrange
            val sessionId = randomUuidString()
            val signature = createSignature()
            val signatureJson = KotlinxSerializationJsonUtil.toJsonString(signature)
            mockkStatic(Base64::class)
            every {
                Base64.encodeToString(
                    signatureJson.toByteArray(),
                    Base64.NO_WRAP
                )
            } returns "encodedSignature"
            val encodedSignature =
                Base64.encodeToString(signatureJson.toByteArray(), Base64.NO_WRAP)

            val crossDeviceSessionRequestBody = CrossDeviceSessionRequestBody(
                wid = sessionId,
                status = CrossDeviceSessionStatus.SIGNED.value,
                signature = encodedSignature
            )
            val crossDeviceSessionRequestBodyAsJson =
                KotlinxSerializationJsonUtil.toJsonString(crossDeviceSessionRequestBody)

            val apiRequest = ApiRequest(
                method = HttpMethod.POST,
                headers = null,
                body = crossDeviceSessionRequestBodyAsJson,
                params = null,
                url = apiSettings.codeStatusUrl
            )
            coEvery { httpRequestExecutorMock.execute(apiRequest) } returns MIRACLSuccess("")

            // Act
            val result =
                apiManager.executeUpdateCrossDeviceSessionForSigningRequest(sessionId, signature)

            // Assert
            Assert.assertTrue(result is MIRACLSuccess)
        }

    @Test
    fun `executeUpdateCrossDeviceSessionForSigningRequest returns MIRACLError when networkRequest returns an error`() =
        runTest {
            // Arrange
            val apiException = ApiException.ExecutionError()
            coEvery { httpRequestExecutorMock.execute(any()) } returns MIRACLError(apiException)

            // Act
            val result = apiManager.executeUpdateCrossDeviceSessionForSigningRequest(
                sessionId = randomUuidString(),
                signature = createSignature()
            )

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertEquals(apiException, (result as MIRACLError).value)
        }

    @Test
    fun `executeUpdateCrossDeviceSessionForSigningRequest returns MIRACLError when exception is thrown`() =
        runTest {
            // Arrange
            val exception = Exception()
            coEvery { httpRequestExecutorMock.execute(any()) } throws exception

            // Act
            val result = apiManager.executeUpdateCrossDeviceSessionForSigningRequest(
                sessionId = randomUuidString(),
                signature = createSignature()
            )

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertEquals(exception, (result as MIRACLError).value)
        }

    @Test
    fun `executeAbortSessionRequest should return MIRACLSuccess when passed data is valid`() =
        runTest {
            // Arrange
            val sessionId = randomUuidString()
            val status = CrossDeviceSessionStatus.ABORT.value

            val crossDeviceSessionRequestBody = CrossDeviceSessionRequestBody(sessionId, status)
            val crossDeviceSessionRequestBodyAsJson =
                KotlinxSerializationJsonUtil.toJsonString(crossDeviceSessionRequestBody)

            val apiRequest = ApiRequest(
                method = HttpMethod.POST,
                headers = null,
                body = crossDeviceSessionRequestBodyAsJson,
                params = null,
                url = apiSettings.codeStatusUrl
            )
            coEvery { httpRequestExecutorMock.execute(apiRequest) } returns MIRACLSuccess("")

            // Act
            val result = apiManager.executeAbortSessionRequest(sessionId)

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
            Assert.assertTrue((result as MIRACLError).value is CrossDeviceSessionException.AbortCrossDeviceSessionFail)
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
            Assert.assertTrue((result as MIRACLError).value is CrossDeviceSessionException.AbortCrossDeviceSessionFail)
            Assert.assertEquals(exception, result.value.cause)
        }

    private fun createCrossDeviceSessionResponse() = CrossDeviceSessionResponse(
        prerollId = randomUuidString(),
        description = randomUuidString(),
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
        hash = randomUuidString()
    )

    private fun createSignature() = Signature(
        mpinId = randomHexString(),
        U = randomHexString(),
        V = randomHexString(),
        publicKey = randomHexString(),
        dtas = randomUuidString(),
        hash = randomUuidString(),
        timestamp = Date().secondsSince1970()
    )
}