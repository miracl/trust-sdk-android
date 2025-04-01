package com.miracl.trust.network

import com.miracl.trust.BuildConfig
import com.miracl.trust.MIRACLError
import com.miracl.trust.MIRACLSuccess
import com.miracl.trust.util.json.KotlinxSerializationJsonUtil
import io.mockk.CapturingSlot
import io.mockk.clearAllMocks
import io.mockk.coEvery
import io.mockk.mockk
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.runTest
import org.json.JSONException
import org.junit.Assert
import org.junit.Before
import org.junit.Test
import java.io.IOException

@ExperimentalCoroutinesApi
class ApiRequestExecutorUnitTest {
    private val httpRequestExecutorMock = mockk<HttpRequestExecutor>()
    private val jsonUtilMock = mockk<KotlinxSerializationJsonUtil>()
    private val apiRequest = ApiRequest(
        method = HttpMethod.GET,
        params = null,
        body = null,
        headers = null,
        url = "https"
    )

    private lateinit var apiManager: ApiRequestExecutor

    @Before
    fun setUp() {
        clearAllMocks()
        apiManager = ApiRequestExecutor(httpRequestExecutorMock, jsonUtilMock)
    }

    @Test
    fun `execute should add X-MIRACL-CLIENT header in the request with library info`() =
        runTest {
            // Arrange
            val requestHeader = "requestHeaderKey" to "requestHeaderValue"
            val apiRequest = apiRequest.copy(headers = mapOf(requestHeader))
            val libraryInfo = "MIRACL Android SDK/${BuildConfig.VERSION_NAME}"

            val capturingSlot = CapturingSlot<ApiRequest>()
            coEvery { httpRequestExecutorMock.execute(capture(capturingSlot)) } returns MIRACLSuccess(
                ""
            )

            // Act
            apiManager.execute(apiRequest)

            // Assert
            Assert.assertTrue(capturingSlot.captured.headers?.get(requestHeader.first) == requestHeader.second)
            Assert.assertTrue(capturingSlot.captured.headers?.get("X-MIRACL-CLIENT") == libraryInfo)
        }

    @Test
    fun `execute should add X-MIRACL-CLIENT header in the request with library and application info`() =
        runTest {
            // Arrange
            val libraryInfo = "MIRACL Android SDK/${BuildConfig.VERSION_NAME}"
            val applicationInfo = "com.miracl.android.trustmfa/3.0.0"
            val apiManager =
                ApiRequestExecutor(httpRequestExecutorMock, jsonUtilMock, applicationInfo)
            val expectedHeader = "$libraryInfo $applicationInfo"

            val capturingSlot = CapturingSlot<ApiRequest>()
            coEvery { httpRequestExecutorMock.execute(capture(capturingSlot)) } returns MIRACLSuccess(
                ""
            )

            // Act
            apiManager.execute(apiRequest)

            // Assert
            Assert.assertTrue(capturingSlot.captured.headers?.get("X-MIRACL-CLIENT") == expectedHeader)
        }

    @Test
    fun `execute should return MIRACLSuccess when the passed request is valid and response code is 200`() =
        runTest {
            // Arrange
            val libraryInfo = "MIRACL Android SDK/${BuildConfig.VERSION_NAME}"
            val expectedApiRequest =
                apiRequest.copy(headers = mapOf("X-MIRACL-CLIENT" to libraryInfo))
            val responseBody =
                "{\"signatureURL\":\"https://api.mpin.io/rps/v2/signature\",\"registerURL\":\"https://api.mpin.io/rps/v2/user\"}"

            coEvery { httpRequestExecutorMock.execute(expectedApiRequest) } returns MIRACLSuccess(
                responseBody
            )

            // Act
            val result = apiManager.execute(apiRequest)

            // Assert
            Assert.assertTrue(result is MIRACLSuccess)
            Assert.assertEquals(responseBody, (result as MIRACLSuccess).value)
        }

    @Test
    fun `execute should return MIRACLError when execution returns client error with API error response`() =
        runTest {
            // Arrange
            val requestId = "l53pbvlmsjsqug2l"
            val clientErrorCode = "BACKOFF_ERROR"
            val clientErrorInfo = "Too many verification requests. Wait for the backoff period."
            val clientErrorContext = mapOf("backoff" to "1682319640")

            val errorResponse = """
                {
                    \"requestID\":\"$requestId\",
                    \"error\":{
                        \"code\":\"$clientErrorCode\",
                        \"info\":\"$clientErrorInfo\",
                        \"context\":$clientErrorContext
                    }
                }
                """.trimMargin()
            val httpRequestExecutorException = HttpRequestExecutorException.HttpError(
                responseCode = 400,
                responseBody = errorResponse
            )
            coEvery { httpRequestExecutorMock.execute(any()) } returns MIRACLError(
                httpRequestExecutorException
            )

            coEvery {
                jsonUtilMock.fromJsonString<ClientErrorMessage>(errorResponse)
            } returns ClientErrorMessage(
                requestId,
                ApiErrorResponse(clientErrorCode, clientErrorInfo, clientErrorContext)
            )

            // Act
            val result = apiManager.execute(apiRequest)

            // Assert
            Assert.assertTrue(result is MIRACLError)
            val exception = (result as MIRACLError).value
            Assert.assertTrue(exception is ApiException.ClientError)
            Assert.assertEquals(httpRequestExecutorException, exception.cause)
            Assert.assertEquals(apiRequest.url, exception.url)
            val clientErrorData = (exception as ApiException.ClientError).clientErrorData
            Assert.assertNotNull(clientErrorData)
            Assert.assertEquals(clientErrorCode, clientErrorData!!.code)
            Assert.assertEquals(clientErrorInfo, clientErrorData.info)
            Assert.assertEquals(clientErrorContext, clientErrorData.context)
        }


    @Test
    fun `execute should return MIRACLError when execution returns client error with the new API error response`() =
        runTest {
            // Arrange
            val requestId = "l53pbvlmsjsqug2l"
            val clientErrorCode = "BACKOFF_ERROR"
            val clientErrorInfo = "Too many verification requests. Wait for the backoff period."
            val clientErrorContext = mapOf("requestID" to requestId, "backoff" to "1682319640")

            val errorResponse = """
                {
                    \"error\":\"$clientErrorCode\",
                    \"info\":\"$clientErrorInfo\",
                    \"context\":$clientErrorContext
                }
                """.trimMargin()
            val httpRequestExecutorException = HttpRequestExecutorException.HttpError(
                responseCode = 400,
                responseBody = errorResponse
            )
            coEvery { httpRequestExecutorMock.execute(any()) } returns MIRACLError(
                httpRequestExecutorException
            )

            coEvery {
                jsonUtilMock.fromJsonString<NewApiErrorResponse>(errorResponse)
            } returns NewApiErrorResponse(
                error = clientErrorCode,
                info = clientErrorInfo,
                context = clientErrorContext
            )

            // Act
            val result = apiManager.execute(apiRequest)

            // Assert
            Assert.assertTrue(result is MIRACLError)
            val exception = (result as MIRACLError).value
            Assert.assertTrue(exception is ApiException.ClientError)
            Assert.assertEquals(httpRequestExecutorException, exception.cause)
            Assert.assertEquals(apiRequest.url, exception.url)
            val clientErrorData = (exception as ApiException.ClientError).clientErrorData
            Assert.assertNotNull(clientErrorData)
            Assert.assertEquals(clientErrorCode, clientErrorData!!.code)
            Assert.assertEquals(clientErrorInfo, clientErrorData.info)
            Assert.assertEquals(clientErrorContext, clientErrorData.context)
        }

    @Test
    fun `execute should return MIRACLError when execution returns client error with no API error response`() =
        runTest {
            // Arrange
            val errorResponse = "{}"
            val httpRequestExecutorException = HttpRequestExecutorException.HttpError(
                responseCode = 401,
                responseBody = errorResponse
            )
            coEvery {
                jsonUtilMock.fromJsonString<NewApiErrorResponse>(errorResponse)
            } throws JSONException("IllegalStateException")
            coEvery {
                jsonUtilMock.fromJsonString<ClientErrorMessage>(errorResponse)
            } throws JSONException("IllegalStateException")
            coEvery { httpRequestExecutorMock.execute(any()) } returns MIRACLError(
                httpRequestExecutorException
            )

            // Act
            val result = apiManager.execute(apiRequest)

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertTrue((result as MIRACLError).value is ApiException.ClientError)
            Assert.assertEquals(httpRequestExecutorException, result.value.cause)
            Assert.assertEquals(apiRequest.url, result.value.url)
        }

    @Test
    fun `execute should return MIRACLError when execution returns client error without response`() =
        runTest {
            // Arrange
            val httpRequestExecutorException = HttpRequestExecutorException.HttpError(
                responseCode = 401,
                responseBody = ""
            )
            coEvery { httpRequestExecutorMock.execute(any()) } returns MIRACLError(
                httpRequestExecutorException
            )

            // Act
            val result = apiManager.execute(apiRequest)

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertTrue((result as MIRACLError).value is ApiException.ClientError)
            Assert.assertEquals(httpRequestExecutorException, result.value.cause)
            Assert.assertEquals(apiRequest.url, result.value.url)
        }

    @Test
    fun `execute should return MIRACLError when execution returns server error`() =
        runTest {
            // Arrange
            val httpRequestExecutorException = HttpRequestExecutorException.HttpError(
                responseCode = 500,
                responseBody = ""
            )
            coEvery { httpRequestExecutorMock.execute(any()) } returns MIRACLError(
                httpRequestExecutorException
            )

            // Act
            val result = apiManager.execute(apiRequest)

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertTrue((result as MIRACLError).value is ApiException.ServerError)
            Assert.assertEquals(httpRequestExecutorException, result.value.cause)
        }

    @Test
    fun `execute should return MIRACLError when the execution fails with EXECUTION_ERROR`() =
        runTest {
            // Arrange
            val executionException =
                HttpRequestExecutorException.ExecutionError(cause = IOException())
            coEvery { httpRequestExecutorMock.execute(any()) } returns MIRACLError(
                executionException
            )

            // Act
            val result = apiManager.execute(apiRequest)

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertTrue((result as MIRACLError).value is ApiException.ExecutionError)
            Assert.assertEquals(executionException, result.value.cause)
            Assert.assertEquals(apiRequest.url, result.value.url)
        }

    @Test
    fun `execute should return MIRACLError when exception is thrown`() =
        runTest {
            // Arrange
            val ioException = IOException()
            coEvery { httpRequestExecutorMock.execute(any()) } throws ioException

            // Act
            val result = apiManager.execute(apiRequest)

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertTrue((result as MIRACLError).value is ApiException.ExecutionError)
            Assert.assertEquals(ioException, result.value.cause)
            Assert.assertEquals(apiRequest.url, result.value.url)
        }
}