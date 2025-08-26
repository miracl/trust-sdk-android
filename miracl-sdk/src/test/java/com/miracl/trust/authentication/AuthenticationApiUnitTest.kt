package com.miracl.trust.authentication

import com.miracl.trust.MIRACLError
import com.miracl.trust.MIRACLSuccess
import com.miracl.trust.network.ApiException
import com.miracl.trust.network.ApiRequest
import com.miracl.trust.network.ApiRequestExecutor
import com.miracl.trust.network.ApiSettings
import com.miracl.trust.network.ClientErrorData
import com.miracl.trust.randomUuidString
import com.miracl.trust.util.json.KotlinxSerializationJsonUtil
import io.mockk.CapturingSlot
import io.mockk.clearAllMocks
import io.mockk.coEvery
import io.mockk.mockk
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.runTest
import org.junit.Assert
import org.junit.Before
import org.junit.Test

@ExperimentalCoroutinesApi
class AuthenticationApiUnitTest {
    private val httpRequestExecutorMock = mockk<ApiRequestExecutor>()

    private val authenticationApiManager = AuthenticationApiManager(
        apiRequestExecutor = httpRequestExecutorMock,
        jsonUtil = KotlinxSerializationJsonUtil,
        apiSettings = ApiSettings(randomUuidString())
    )

    @Before
    fun resetMocks() {
        clearAllMocks()
    }

    @Test
    fun `executePass1Request should return MIRACLSuccess when passed data is valid`() {
        runTest {
            val projectId = randomUuidString()
            val pass1RequestBody = Pass1RequestBody(
                mpinId = randomUuidString(),
                U = randomUuidString(),
                dtas = randomUuidString(),
                scope = arrayOf(AuthenticatorScopes.OIDC.value),
                publicKey = randomUuidString()
            )
            val capturingSlot = CapturingSlot<ApiRequest>()
            val pass1Response = Pass1Response(randomUuidString())
            val pass1ResponseAsJson = KotlinxSerializationJsonUtil.toJsonString(pass1Response)
            coEvery {
                httpRequestExecutorMock.execute(capture(capturingSlot))
            } returns MIRACLSuccess(pass1ResponseAsJson)

            // Act
            val result = authenticationApiManager.executePass1Request(pass1RequestBody, projectId)

            // Assert
            Assert.assertTrue(result is MIRACLSuccess)
            Assert.assertEquals(pass1Response, (result as MIRACLSuccess).value)

            val pass1RequestBodyAsJson = KotlinxSerializationJsonUtil.toJsonString(pass1RequestBody)
            Assert.assertEquals(pass1RequestBodyAsJson, capturingSlot.captured.body)
        }
    }

    @Test
    fun `executePass1Request should return MIRACLError when request executor returns error`() {
        runTest {
            val projectId = randomUuidString()
            val pass1RequestBody = Pass1RequestBody(
                mpinId = randomUuidString(),
                U = randomUuidString(),
                dtas = randomUuidString(),
                scope = arrayOf(AuthenticatorScopes.OIDC.value),
                publicKey = randomUuidString()
            )
            val httpRequestExecutorException = ApiException.ExecutionError()
            coEvery { httpRequestExecutorMock.execute(any()) } returns MIRACLError(
                httpRequestExecutorException
            )

            // Act
            val result = authenticationApiManager.executePass1Request(pass1RequestBody, projectId)

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertTrue((result as MIRACLError).value is AuthenticationException.AuthenticationFail)
            Assert.assertEquals(httpRequestExecutorException, result.value.cause)
        }
    }

    @Test
    fun `executePass1Request should return correct MIRACLError when request executor result is MPINID_EXPIRED client error`() {
        runTest {
            // Arrange
            val projectId = randomUuidString()
            val pass1RequestBody = Pass1RequestBody(
                mpinId = randomUuidString(),
                U = randomUuidString(),
                dtas = randomUuidString(),
                scope = arrayOf(AuthenticatorScopes.OIDC.value),
                publicKey = randomUuidString()
            )
            val apiException =
                ApiException.ClientError(
                    clientErrorData = ClientErrorData(
                        code = "MPINID_EXPIRED",
                        info = "The MPin ID has expired and the device needs to be re-registered.",
                        context = null
                    )
                )
            coEvery { httpRequestExecutorMock.execute(any()) } returns MIRACLError(
                apiException
            )

            // Act
            val result = authenticationApiManager.executePass1Request(pass1RequestBody, projectId)

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertEquals(
                AuthenticationException.Revoked,
                (result as MIRACLError).value
            )
        }
    }

    @Test
    fun `executePass1Request should return correct MIRACLError when request executor result is EXPIRED_MPINID client error`() {
        runTest {
            // Arrange
            val projectId = randomUuidString()
            val pass1RequestBody = Pass1RequestBody(
                mpinId = randomUuidString(),
                U = randomUuidString(),
                dtas = randomUuidString(),
                scope = arrayOf(AuthenticatorScopes.OIDC.value),
                publicKey = randomUuidString()
            )
            val apiException =
                ApiException.ClientError(
                    clientErrorData = ClientErrorData(
                        code = "EXPIRED_MPINID",
                        info = "The MPin ID has expired and the device needs to be re-registered.",
                        context = null
                    )
                )
            coEvery { httpRequestExecutorMock.execute(any()) } returns MIRACLError(
                apiException
            )

            // Act
            val result = authenticationApiManager.executePass1Request(pass1RequestBody, projectId)

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertEquals(
                AuthenticationException.Revoked,
                (result as MIRACLError).value
            )
        }
    }

    @Test
    fun `executePass1Request should return MIRACLError when request executor throws exception`() {
        runTest {
            val projectId = randomUuidString()
            val pass1RequestBody = Pass1RequestBody(
                mpinId = randomUuidString(),
                U = randomUuidString(),
                dtas = randomUuidString(),
                scope = arrayOf(AuthenticatorScopes.OIDC.value),
                publicKey = randomUuidString()
            )
            val exception = Exception()
            coEvery { httpRequestExecutorMock.execute(any()) } throws exception

            // Act
            val result = authenticationApiManager.executePass1Request(pass1RequestBody, projectId)

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertTrue((result as MIRACLError).value is AuthenticationException.AuthenticationFail)
            Assert.assertEquals(exception, result.value.cause)
        }
    }

    @Test
    fun `executePass2Request should return MIRACLSuccess when passed data is valid`() {
        runTest {
            val projectId = randomUuidString()
            val mpinId = randomUuidString()
            val accessId = randomUuidString()
            val sec = randomUuidString()
            val pass2RequestBody = Pass2RequestBody(
                mpinId = mpinId,
                V = sec,
                accessId = accessId
            )
            val capturingSlot = CapturingSlot<ApiRequest>()
            val pass2Response = Pass2Response(randomUuidString())
            val pass2ResponseAsJson = KotlinxSerializationJsonUtil.toJsonString(pass2Response)
            coEvery { httpRequestExecutorMock.execute(capture(capturingSlot)) } returns MIRACLSuccess(
                pass2ResponseAsJson
            )

            // Act
            val result = authenticationApiManager.executePass2Request(pass2RequestBody, projectId)

            // Assert
            Assert.assertTrue(result is MIRACLSuccess)
            Assert.assertEquals(pass2Response, (result as MIRACLSuccess).value)

            val pass2RequestBodyAsJson = KotlinxSerializationJsonUtil.toJsonString(pass2RequestBody)
            Assert.assertEquals(pass2RequestBodyAsJson, capturingSlot.captured.body)
        }
    }

    @Test
    fun `executePass2Request should return MIRACLError when request executor returns error`() {
        runTest {
            val projectId = randomUuidString()
            val pass2RequestBody = Pass2RequestBody(
                mpinId = randomUuidString(),
                V = randomUuidString(),
                accessId = randomUuidString()
            )
            val httpRequestExecutorException = ApiException.ExecutionError()
            coEvery { httpRequestExecutorMock.execute(any()) } returns MIRACLError(
                httpRequestExecutorException
            )

            // Act
            val result = authenticationApiManager.executePass2Request(pass2RequestBody, projectId)

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertTrue((result as MIRACLError).value is AuthenticationException.AuthenticationFail)
            Assert.assertEquals(httpRequestExecutorException, result.value.cause)
        }
    }

    @Test
    fun `executePass2Request should return MIRACLError with exception when request executor throws exception`() {
        runTest {
            val projectId = randomUuidString()
            val pass2RequestBody = Pass2RequestBody(
                mpinId = randomUuidString(),
                V = randomUuidString(),
                accessId = randomUuidString()
            )
            val exception = Exception()
            coEvery { httpRequestExecutorMock.execute(any()) } throws exception

            // Act
            val result = authenticationApiManager.executePass2Request(pass2RequestBody, projectId)

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertTrue((result as MIRACLError).value is AuthenticationException.AuthenticationFail)
            Assert.assertEquals(exception, result.value.cause)
        }
    }

    @Test
    fun `executeAuthenticateRequest should return MIRACLSuccess when passed data is valid`() {
        runTest {
            val projectId = randomUuidString()
            val authenticateRequest = AuthenticateRequestBody(randomUuidString())
            val capturingSlot = CapturingSlot<ApiRequest>()
            val authenticateResponse =
                AuthenticateResponse(
                    status = 200,
                    message = "OK",
                    renewSecretResponse = RenewSecretResponse(
                        token = randomUuidString(),
                        curve = randomUuidString()
                    ),
                    jwt = randomUuidString()
                )
            val authenticateResponseAsJson =
                KotlinxSerializationJsonUtil.toJsonString(authenticateResponse)
            coEvery {
                httpRequestExecutorMock.execute(capture(capturingSlot))
            } returns MIRACLSuccess(authenticateResponseAsJson)

            // Act
            val result =
                authenticationApiManager.executeAuthenticateRequest(authenticateRequest, projectId)

            // Assert
            Assert.assertTrue(result is MIRACLSuccess)
            Assert.assertEquals(authenticateResponse, (result as MIRACLSuccess).value)

            val authenticateRequestBodyAsJson =
                KotlinxSerializationJsonUtil.toJsonString(authenticateRequest)
            Assert.assertEquals(authenticateRequestBodyAsJson, capturingSlot.captured.body)
        }
    }

    @Test
    fun `executeAuthenticateRequest should return MIRACLError when request executor returns error`() {
        runTest {
            val projectId = randomUuidString()
            val authenticateRequest = AuthenticateRequestBody(randomUuidString())
            val httpRequestExecutorException = ApiException.ExecutionError()
            coEvery { httpRequestExecutorMock.execute(any()) } returns MIRACLError(
                httpRequestExecutorException
            )

            // Act
            val result =
                authenticationApiManager.executeAuthenticateRequest(authenticateRequest, projectId)

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertTrue((result as MIRACLError).value is AuthenticationException.AuthenticationFail)
            Assert.assertEquals(httpRequestExecutorException, result.value.cause)
        }
    }

    @Test
    fun `executeAuthenticateRequest should return correct MIRACLError when request executor returns INVALID_AUTH_SESSION error`() {
        runTest {
            // Arrange
            val projectId = randomUuidString()
            val authenticateRequest = AuthenticateRequestBody(randomUuidString())

            val apiException = ApiException.ClientError(
                clientErrorData = ClientErrorData(
                    code = "INVALID_AUTH_SESSION",
                    info = "Invalid or expired authentication session.",
                    context = null
                )
            )
            coEvery { httpRequestExecutorMock.execute(any()) } returns MIRACLError(
                apiException
            )

            // Act
            val result =
                authenticationApiManager.executeAuthenticateRequest(authenticateRequest, projectId)

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertEquals(
                AuthenticationException.InvalidAuthenticationSession,
                (result as MIRACLError).value
            )
        }
    }

    @Test
    fun `executeAuthenticateRequest should return correct MIRACLError when request executor returns INVALID_AUTHENTICATION_SESSION error`() {
        runTest {
            // Arrange
            val projectId = randomUuidString()
            val authenticateRequest = AuthenticateRequestBody(randomUuidString())

            val apiException = ApiException.ClientError(
                clientErrorData = ClientErrorData(
                    code = "INVALID_AUTHENTICATION_SESSION",
                    info = "Invalid or expired authentication session.",
                    context = null
                )
            )
            coEvery { httpRequestExecutorMock.execute(any()) } returns MIRACLError(
                apiException
            )

            // Act
            val result =
                authenticationApiManager.executeAuthenticateRequest(authenticateRequest, projectId)

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertEquals(
                AuthenticationException.InvalidAuthenticationSession,
                (result as MIRACLError).value
            )
        }
    }

    @Test
    fun `executeAuthenticateRequest should return correct MIRACLError when request executor returns INVALID_AUTH client error`() {
        runTest {
            // Arrange
            val projectId = randomUuidString()
            val authenticateRequest = AuthenticateRequestBody(randomUuidString())

            val apiException = ApiException.ClientError(
                clientErrorData = ClientErrorData(
                    code = "INVALID_AUTH",
                    info = "The authentication was not successful.",
                    context = null
                )
            )
            coEvery { httpRequestExecutorMock.execute(any()) } returns MIRACLError(
                apiException
            )

            // Act
            val result =
                authenticationApiManager.executeAuthenticateRequest(authenticateRequest, projectId)

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertEquals(
                AuthenticationException.UnsuccessfulAuthentication,
                (result as MIRACLError).value
            )
        }
    }

    @Test
    fun `executeAuthenticateRequest should return correct MIRACLError when request executor returns UNSUCCESSFUL_AUTHENTICATION client error`() {
        runTest {
            // Arrange
            val projectId = randomUuidString()
            val authenticateRequest = AuthenticateRequestBody(randomUuidString())

            val apiException = ApiException.ClientError(
                clientErrorData = ClientErrorData(
                    code = "UNSUCCESSFUL_AUTHENTICATION",
                    info = "The authentication was not successful.",
                    context = null
                )
            )
            coEvery { httpRequestExecutorMock.execute(any()) } returns MIRACLError(
                apiException
            )

            // Act
            val result =
                authenticationApiManager.executeAuthenticateRequest(authenticateRequest, projectId)

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertEquals(
                AuthenticationException.UnsuccessfulAuthentication,
                (result as MIRACLError).value
            )
        }
    }

    @Test
    fun `executeAuthenticateRequest should return correct MIRACLError when request executor returns MPINID_REVOKED client error`() {
        runTest {
            // Arrange
            val projectId = randomUuidString()
            val authenticateRequest = AuthenticateRequestBody(randomUuidString())

            val apiException = ApiException.ClientError(
                clientErrorData = ClientErrorData(
                    code = "MPINID_REVOKED",
                    info = "The MPin ID has been revoked due to multiple invalid login attempts.",
                    context = null
                )
            )
            coEvery { httpRequestExecutorMock.execute(any()) } returns MIRACLError(
                apiException
            )

            // Act
            val result =
                authenticationApiManager.executeAuthenticateRequest(authenticateRequest, projectId)

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertEquals(
                AuthenticationException.Revoked,
                (result as MIRACLError).value
            )
        }
    }

    @Test
    fun `executeAuthenticateRequest should return correct MIRACLError when request executor returns REVOKED_MPINID client error`() {
        runTest {
            // Arrange
            val projectId = randomUuidString()
            val authenticateRequest = AuthenticateRequestBody(randomUuidString())

            val apiException = ApiException.ClientError(
                clientErrorData = ClientErrorData(
                    code = "REVOKED_MPINID",
                    info = "The MPin ID has been revoked due to multiple invalid login attempts.",
                    context = null
                )
            )
            coEvery { httpRequestExecutorMock.execute(any()) } returns MIRACLError(
                apiException
            )

            // Act
            val result =
                authenticationApiManager.executeAuthenticateRequest(authenticateRequest, projectId)

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertEquals(
                AuthenticationException.Revoked,
                (result as MIRACLError).value
            )
        }
    }

    @Test
    fun `executeAuthenticateRequest should return MIRACLError when request executor throws exception`() {
        runTest {
            val projectId = randomUuidString()
            val authenticateRequest = AuthenticateRequestBody(randomUuidString())

            val exception = Exception()
            coEvery { httpRequestExecutorMock.execute(any()) } throws exception

            // Act
            val result =
                authenticationApiManager.executeAuthenticateRequest(authenticateRequest, projectId)

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertTrue((result as MIRACLError).value is AuthenticationException.AuthenticationFail)
            Assert.assertEquals(exception, result.value.cause)
        }
    }
}
