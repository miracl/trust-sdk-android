package com.miracl.trust.network

import com.miracl.trust.MIRACLError
import com.miracl.trust.MIRACLResult
import com.miracl.trust.MIRACLSuccess
import com.miracl.trust.util.log.Loggable
import com.miracl.trust.util.log.LoggerConstants
import com.miracl.trust.util.log.LoggerConstants.NETWORK_TAG
import java.io.*
import java.net.HttpURLConnection
import java.net.URL
import java.util.concurrent.TimeUnit

internal interface HttpURLConnectionBuilder {
    fun build(url: URL): HttpURLConnection
}

internal class DefaultHttpConnectionBuilder : HttpURLConnectionBuilder {
    override fun build(url: URL): HttpURLConnection {
        return url.openConnection() as HttpURLConnection
    }
}

/**
 * Provides implementation of the HttpRequestExecutor that uses [HttpURLConnection].
 */
internal class HttpsURLConnectionRequestExecutor(
    connectTimeout: Int,
    readTimeout: Int
) : HttpRequestExecutor, Loggable {
    companion object {
        private const val ENCODING = "UTF-8"
        private const val MEDIA_TYPE = "application/json; charset=utf-8"
        private const val HTTP_METHOD_NOT_EXPECTED_TO_HAVE_A_BODY_LOG =
            "This HttpMethod is not expected to have a body."
    }

    private val connectTimeout: Int = getTimeout(connectTimeout)
    private val readTimeout: Int = getTimeout(readTimeout)

    var httpURLConnectionBuilder: HttpURLConnectionBuilder = DefaultHttpConnectionBuilder()

    /**
     * Implementation of the [HttpRequestExecutor.execute].
     * @param apiRequest is a MIRACLTrust class that provides the needed data for
     * a http request to be executed.
     * @return MIRACLResult<String, HttpRequestExecutorException>
     * - If the result is success execute returns MIRACLSuccess with a string value of the
     * received response.
     * - If the result is error execute returns the error with a message.
     * If an exception is thrown, the error passes the exception as an object.
     */
    override suspend fun execute(apiRequest: ApiRequest): MIRACLResult<String, HttpRequestExecutorException> {
        var urlConnection: HttpURLConnection? = null
        try {
            urlConnection = buildURLConnection(apiRequest)

            logger?.debug(
                NETWORK_TAG,
                LoggerConstants.NETWORK_REQUEST.format(
                    urlConnection.requestMethod,
                    urlConnection.url
                )
            )

            val responseCode = urlConnection.responseCode
            val responseBody = readStream(
                if (responseCode in 200..299) {
                    BufferedInputStream(urlConnection.inputStream)
                } else {
                    BufferedInputStream(urlConnection.errorStream)
                }
            )

            logger?.debug(
                NETWORK_TAG,
                LoggerConstants.NETWORK_RESPONSE.format(
                    urlConnection.requestMethod,
                    urlConnection.url,
                    responseCode,
                    responseBody
                )
            )

            return when (responseCode) {
                in 200..299 -> MIRACLSuccess(responseBody)
                else -> MIRACLError(
                    HttpRequestExecutorException.HttpError(
                        responseCode,
                        responseBody
                    )
                )
            }
        } catch (ex: Exception) {
            if (ex is IOException) {
                logger?.error(NETWORK_TAG, ex.toString())
            }

            return MIRACLError(HttpRequestExecutorException.ExecutionError(cause = ex))
        } finally {
            urlConnection?.disconnect()
        }
    }

    private fun buildURLConnection(apiRequest: ApiRequest): HttpURLConnection {
        val url = buildURL(apiRequest)
        val urlConnection = httpURLConnectionBuilder.build(url)
        urlConnection.requestMethod = apiRequest.method.method

        apiRequest.headers?.forEach {
            urlConnection.addRequestProperty(it.key, it.value)
        }

        urlConnection.connectTimeout = connectTimeout
        urlConnection.readTimeout = readTimeout

        apiRequest.body?.also {
            if (apiRequest.method == HttpMethod.GET) {
                logger?.info(NETWORK_TAG, HTTP_METHOD_NOT_EXPECTED_TO_HAVE_A_BODY_LOG)
            }

            urlConnection.setRequestProperty(
                "Content-Type",
                MEDIA_TYPE
            )

            val contentLength = it.toByteArray().size
            urlConnection.doOutput = true
            urlConnection.setFixedLengthStreamingMode(contentLength)
            val out: OutputStream = BufferedOutputStream(urlConnection.outputStream, contentLength)
            val writer = BufferedWriter(OutputStreamWriter(out, ENCODING), contentLength)
            writer.write(it)
            writer.flush()
        }

        return urlConnection
    }

    private fun buildURL(apiRequest: ApiRequest): URL {
        val url = if (!apiRequest.params.isNullOrEmpty()) {
            val urlBuilder = StringBuilder(apiRequest.url)
            urlBuilder.append("?")

            apiRequest.params.onEachIndexed { index, param ->
                if (index > 0) urlBuilder.append('&')
                urlBuilder.append("${param.key}=${param.value}")
            }

            urlBuilder.toString()
        } else {
            apiRequest.url
        }

        return URL(url)
    }

    private fun readStream(inputStream: InputStream): String {
        val reader = BufferedReader(InputStreamReader(inputStream, ENCODING))
        return reader.readText()
    }

    private fun getTimeout(duration: Int): Int {
        require(duration >= 0) { "timeout <= 0" }
        val millis = TimeUnit.SECONDS.toMillis(duration.toLong())
        require(millis <= Int.MAX_VALUE) { "timeout too large." }
        return millis.toInt()
    }
}