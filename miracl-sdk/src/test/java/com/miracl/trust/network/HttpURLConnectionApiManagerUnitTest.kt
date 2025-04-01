package com.miracl.trust.network

import com.miracl.trust.MIRACLError
import com.miracl.trust.MIRACLSuccess
import com.miracl.trust.randomUuidString
import com.miracl.trust.test_helpers.MockHttpURLConnectionBuilder
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.runTest
import org.junit.Assert
import org.junit.Before
import org.junit.Test
import java.io.IOException
import java.net.MalformedURLException

@ExperimentalCoroutinesApi
class HttpURLConnectionApiManagerUnitTest {
    private val clientSettingsUrl = "https://api.mpin.io/rps/v2/clientSettings"

    private lateinit var apiManager: HttpsURLConnectionRequestExecutor

    @Before
    fun setUp() {
        apiManager = HttpsURLConnectionRequestExecutor(10, 10)
    }

    @Test
    fun `execute should return MIRACLSuccess when the passed request is valid and response code is 200`() =
        runTest {
            // Arrange
            val apiRequest = ApiRequest(
                method = HttpMethod.GET,
                params = null,
                body = null,
                headers = null,
                url = clientSettingsUrl
            )
            val responseBody =
                "{\"signatureURL\":\"https://api.mpin.io/rps/v2/signature\",\"registerURL\":\"https://api.mpin.io/rps/v2/user\"}"
            apiManager.httpURLConnectionBuilder = MockHttpURLConnectionBuilder(
                statusCode = 200,
                inputStreamProvider = { responseBody.byteInputStream() }
            )

            // Act
            val result = apiManager.execute(apiRequest)

            // Assert
            Assert.assertTrue(result is MIRACLSuccess)
            Assert.assertEquals(responseBody, (result as MIRACLSuccess).value)
        }

    @Test
    fun `execute should return MIRACLError when the execution fails with IOException`() =
        runTest {
            // Arrange
            val headers = mutableMapOf(
                "X-MIRACL-CID" to "companyId"
            )
            val apiRequest = ApiRequest(
                method = HttpMethod.GET,
                params = null,
                body = null,
                headers = headers,
                url = clientSettingsUrl
            )
            val ioException = IOException()
            apiManager.httpURLConnectionBuilder = MockHttpURLConnectionBuilder { throw ioException }

            // Act
            val result = apiManager.execute(apiRequest)

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertTrue((result as MIRACLError).value is HttpRequestExecutorException.ExecutionError)
            Assert.assertEquals(ioException, result.value.cause)
        }

    @Test
    fun `execute should return MIRACLError when the passed request url is not a valid url`() =
        runTest {
            // Arrange
            val headers = mutableMapOf(
                "X-MIRACL-CID" to "companyId"
            )
            val apiRequest = ApiRequest(
                method = HttpMethod.GET,
                params = null,
                body = null,
                headers = headers,
                url = "https"
            )
            val responseBody =
                "{\"signatureURL\":\"https://api.mpin.io/rps/v2/signature\",\"registerURL\":\"https://api.mpin.io/rps/v2/user\"}"
            apiManager.httpURLConnectionBuilder = MockHttpURLConnectionBuilder(
                statusCode = 200,
                inputStreamProvider = { responseBody.byteInputStream() }
            )

            // Act
            val result = apiManager.execute(apiRequest)

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertTrue((result as MIRACLError).value is HttpRequestExecutorException.ExecutionError)
            Assert.assertTrue(result.value.cause is MalformedURLException)
        }

    @Test
    fun `execute should return MIRACLError when the passed request is not valid and response code is 400`() =
        runTest {
            // Arrange
            val apiRequest = ApiRequest(
                method = HttpMethod.GET,
                params = null,
                body = null,
                headers = null,
                url = clientSettingsUrl
            )
            val responseCode = 400
            val responseBody = """
                {
                    \"requestID\":\"l53pbvlmsjsqug2l\",
                    \"error\":{
                        \"code\":\"BACKOFF_ERROR\",
                        \"info\":\"Too many verification requests. Wait for the backoff period.\",
                        \"context\":{\"backoff\":\"1682319640\"}
                    }
                }
                """.trimMargin()
            apiManager.httpURLConnectionBuilder = MockHttpURLConnectionBuilder(
                statusCode = responseCode,
                errorStreamProvider = { responseBody.byteInputStream() }
            )

            // Act
            val result = apiManager.execute(apiRequest)

            // Assert
            Assert.assertTrue(result is MIRACLError)
            val exception = (result as MIRACLError).value
            Assert.assertTrue(exception is HttpRequestExecutorException.HttpError)
            Assert.assertEquals(
                responseCode,
                (exception as HttpRequestExecutorException.HttpError).responseCode
            )
            Assert.assertEquals(responseBody, exception.responseBody)
        }

    @Test
    fun `execute should return MIRACLError when the passed request is valid and response code is 500`() =
        runTest {
            // Arrange
            val params = mutableMapOf("d" to "mcl")
            val apiRequest = ApiRequest(
                method = HttpMethod.GET,
                params = params,
                body = null,
                headers = null,
                url = clientSettingsUrl
            )

            val responseCode = 500
            val responseBody = "Server error"
            apiManager.httpURLConnectionBuilder = MockHttpURLConnectionBuilder(
                statusCode = responseCode,
                errorStreamProvider = { responseBody.byteInputStream() }
            )

            // Act
            val result = apiManager.execute(apiRequest)

            // Assert
            Assert.assertTrue(result is MIRACLError)
            val exception = (result as MIRACLError).value
            Assert.assertTrue(exception is HttpRequestExecutorException.HttpError)
            Assert.assertEquals(
                responseCode,
                (exception as HttpRequestExecutorException.HttpError).responseCode
            )
            Assert.assertEquals(responseBody, exception.responseBody)
        }

    @Test
    fun `execute should attach a valid request body when method is PUT`() =
        runTest {
            // Arrange
            val jsonString = """
                {
                  "userId": "${randomUuidString()}",
                  "deviceName": "${randomUuidString()}",
                  "regOTT": "${randomUuidString()}",
                  "wid": "${randomUuidString()}",
                  "activateCode": "${randomUuidString()}"
                }
            """.trimIndent()
            val apiRequest = ApiRequest(
                method = HttpMethod.PUT,
                params = null,
                body = jsonString,
                headers = null,
                url = clientSettingsUrl
            )
            val responseBody =
                "{\"signatureURL\":\"https://api.mpin.io/rps/v2/signature\",\"registerURL\":\"https://api.mpin.io/rps/v2/user\"}"
            apiManager.httpURLConnectionBuilder = MockHttpURLConnectionBuilder(
                statusCode = 200,
                inputStreamProvider = { responseBody.byteInputStream() }
            )

            // Act
            val result = apiManager.execute(apiRequest)

            // Assert
            Assert.assertTrue(result is MIRACLSuccess)
            Assert.assertEquals(responseBody, (result as MIRACLSuccess).value)
        }
}
