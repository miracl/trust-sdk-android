package com.miracl.trust.network

import com.miracl.trust.BuildConfig
import com.miracl.trust.MIRACLError
import com.miracl.trust.MIRACLResult
import com.miracl.trust.MIRACLSuccess
import com.miracl.trust.util.json.KotlinxSerializationJsonUtil
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
internal data class ClientErrorMessage(
    @SerialName("requestID") val requestId: String,
    @SerialName("error") val error: ApiErrorResponse
)

@Serializable
internal data class ApiErrorResponse(
    @SerialName("code") val code: String,
    @SerialName("info") val info: String,
    @SerialName("context") val context: Map<String, String>?
)

@Serializable
internal data class NewApiErrorResponse(
    @SerialName("error") val error: String,
    @SerialName("info") val info: String,
    @SerialName("context") val context: Map<String, String>?
)

internal class ApiRequestExecutor(
    private val httpRequestExecutor: HttpRequestExecutor,
    private val jsonUtil: KotlinxSerializationJsonUtil,
    applicationInfo: String? = null
) {
    private val xMiraclClientHeader =
        "X-MIRACL-CLIENT" to "MIRACL Android SDK/${BuildConfig.VERSION_NAME}${
            if (!applicationInfo.isNullOrBlank()) {
                " $applicationInfo"
            } else ""
        }"

    suspend fun execute(apiRequest: ApiRequest): MIRACLResult<String, ApiException> {
        try {
            val headers = if (apiRequest.headers != null) {
                apiRequest.headers + xMiraclClientHeader
            } else {
                mapOf(xMiraclClientHeader)
            }

            val result = httpRequestExecutor.execute(apiRequest.copy(headers = headers))
            if (result is MIRACLError) {
                val exception = result.value
                if (exception is HttpRequestExecutorException.HttpError) {
                    return MIRACLError(
                        when (exception.responseCode) {
                            in 400..499 -> {
                                handleClientError(apiRequest.url, exception)
                            }

                            else -> {
                                ApiException.ServerError(url = apiRequest.url, cause = exception)
                            }
                        }
                    )
                }
                return MIRACLError(ApiException.ExecutionError(apiRequest.url, cause = exception))
            }

            return MIRACLSuccess((result as MIRACLSuccess).value)
        } catch (ex: Exception) {
            return MIRACLError(ApiException.ExecutionError(apiRequest.url, cause = ex))
        }
    }

    private fun handleClientError(
        url: String,
        exception: HttpRequestExecutorException.HttpError
    ): ApiException {
        val responseBody = exception.responseBody

        var clientErrorData: ClientErrorData? = null

        if (responseBody.isNotBlank()) {
            clientErrorData = try {
                val errorResponse = jsonUtil.fromJsonString<NewApiErrorResponse>(responseBody)
                ClientErrorData(
                    code = errorResponse.error,
                    info = errorResponse.info,
                    context = errorResponse.context
                )
            } catch (_: Exception) {
                null
            }

            if (clientErrorData == null) {
                clientErrorData = try {
                    val errorResponse = jsonUtil.fromJsonString<ClientErrorMessage>(responseBody)
                    ClientErrorData(
                        code = errorResponse.error.code,
                        info = errorResponse.error.info,
                        context = errorResponse.error.context
                    )
                } catch (_: Exception) {
                    null
                }
            }
        }

        return ApiException.ClientError(
            url = url,
            clientErrorData = clientErrorData,
            cause = exception
        )
    }
}