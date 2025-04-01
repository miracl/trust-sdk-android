package com.miracl.trust.registration

import com.miracl.trust.MIRACLError
import com.miracl.trust.MIRACLResult
import com.miracl.trust.MIRACLSuccess
import com.miracl.trust.network.ApiException
import com.miracl.trust.network.ApiRequest
import com.miracl.trust.network.ApiRequestExecutor
import com.miracl.trust.network.ApiSettings
import com.miracl.trust.network.HttpMethod
import com.miracl.trust.util.json.KotlinxSerializationJsonUtil
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
internal data class VerificationRequestBody(
    val projectId: String,
    val userId: String,
    val deviceName: String,
    val accessId: String?,
    val mpinId: String?
)

@Serializable
internal data class VerificationRequestResponse(
    val backoff: Long,
    val method: String
)

@Serializable
internal data class QuickCodeVerificationRequestBody(
    val projectId: String,
    val jwt: String,
    val deviceName: String
)

@Serializable
internal data class QuickCodeVerificationResponse(
    val code: String,
    val expireTime: Long,
    val ttlSeconds: Int
)

@Serializable
internal data class ConfirmationRequestBody(
    val userId: String,
    val code: String
)

@Serializable
internal data class ConfirmationResponse(
    @SerialName("projectId") val projectId: String,
    @SerialName("actToken") val activateToken: String,
    @SerialName("accessId") val accessId: String?
)

internal interface VerificationApi {
    suspend fun executeVerificationRequest(
        verificationRequestBody: VerificationRequestBody
    ): MIRACLResult<VerificationRequestResponse, VerificationException>

    suspend fun executeQuickCodeVerificationRequest(
        quickCodeVerificationRequestBody: QuickCodeVerificationRequestBody
    ): MIRACLResult<QuickCodeVerificationResponse, QuickCodeException>

    suspend fun executeConfirmationRequest(
        confirmationRequestBody: ConfirmationRequestBody
    ): MIRACLResult<ConfirmationResponse, ActivationTokenException>
}

internal class VerificationApiManager(
    private val jsonUtil: KotlinxSerializationJsonUtil,
    private val apiRequestExecutor: ApiRequestExecutor,
    private val apiSettings: ApiSettings
) : VerificationApi {
    companion object {
        const val BACKOFF_ERROR = "BACKOFF_ERROR"
        const val REQUEST_BACKOFF = "REQUEST_BACKOFF"
        const val INVALID_VERIFICATION_CODE = "INVALID_VERIFICATION_CODE"
        const val UNSUCCESSFUL_VERIFICATION = "UNSUCCESSFUL_VERIFICATION"
    }

    override suspend fun executeVerificationRequest(
        verificationRequestBody: VerificationRequestBody
    ): MIRACLResult<VerificationRequestResponse, VerificationException> {
        try {
            val requestBodyJson = jsonUtil.toJsonString(verificationRequestBody)
            val apiRequest = ApiRequest(
                method = HttpMethod.POST,
                headers = null,
                body = requestBodyJson,
                params = null,
                url = apiSettings.verificationUrl
            )

            val result = apiRequestExecutor.execute(apiRequest)
            if (result is MIRACLError) {
                val exception = result.value
                if (exception is ApiException.ClientError &&
                    (exception.clientErrorData?.code == BACKOFF_ERROR ||
                            exception.clientErrorData?.code == REQUEST_BACKOFF)
                ) {
                    val backoff = exception.clientErrorData.context?.get("backoff")?.toLongOrNull()
                    if (backoff != null) {
                        return MIRACLError(VerificationException.RequestBackoff(backoff))
                    }
                }

                return MIRACLError(VerificationException.VerificationFail(result.value))
            }

            val verificationRequestResponse =
                jsonUtil.fromJsonString<VerificationRequestResponse>((result as MIRACLSuccess).value)

            return MIRACLSuccess(verificationRequestResponse)
        } catch (ex: Exception) {
            return MIRACLError(VerificationException.VerificationFail(cause = ex))
        }
    }

    override suspend fun executeQuickCodeVerificationRequest(
        quickCodeVerificationRequestBody: QuickCodeVerificationRequestBody
    ): MIRACLResult<QuickCodeVerificationResponse, QuickCodeException> {
        try {
            val requestBodyJson = jsonUtil.toJsonString(quickCodeVerificationRequestBody)
            val apiRequest = ApiRequest(
                method = HttpMethod.POST,
                headers = null,
                body = requestBodyJson,
                params = null,
                url = apiSettings.quickCodeVerificationUrl
            )

            val result = apiRequestExecutor.execute(apiRequest)
            if (result is MIRACLError) {
                return MIRACLError(QuickCodeException.GenerationFail(result.value))
            }

            val verificationRequestResponse =
                jsonUtil.fromJsonString<QuickCodeVerificationResponse>((result as MIRACLSuccess).value)

            return MIRACLSuccess(verificationRequestResponse)
        } catch (ex: Exception) {
            return MIRACLError(QuickCodeException.GenerationFail(ex))
        }
    }

    override suspend fun executeConfirmationRequest(
        confirmationRequestBody: ConfirmationRequestBody
    ): MIRACLResult<ConfirmationResponse, ActivationTokenException> {
        try {
            val requestBodyJson = jsonUtil.toJsonString(confirmationRequestBody)
            val apiRequest = ApiRequest(
                method = HttpMethod.POST,
                headers = null,
                body = requestBodyJson,
                params = null,
                url = apiSettings.verificationConfirmationUrl
            )

            val result = apiRequestExecutor.execute(apiRequest)
            if (result is MIRACLError) {
                val exception = result.value
                if (exception is ApiException.ClientError &&
                    (exception.clientErrorData?.code == INVALID_VERIFICATION_CODE ||
                            exception.clientErrorData?.code == UNSUCCESSFUL_VERIFICATION)
                ) {
                    val projectId = exception.clientErrorData.context?.get("projectId")
                    val accessId = exception.clientErrorData.context?.get("accessId")
                    return if (projectId != null) {
                        MIRACLError(
                            ActivationTokenException.UnsuccessfulVerification(
                                ActivationTokenErrorResponse(
                                    projectId,
                                    confirmationRequestBody.userId,
                                    accessId
                                )
                            )
                        )
                    } else {
                        MIRACLError(ActivationTokenException.UnsuccessfulVerification(null))
                    }
                }

                return MIRACLError(ActivationTokenException.GetActivationTokenFail(exception))
            }

            val confirmationResponse =
                jsonUtil.fromJsonString<ConfirmationResponse>((result as MIRACLSuccess).value)
            return MIRACLSuccess(confirmationResponse)
        } catch (ex: Exception) {
            return MIRACLError(ActivationTokenException.GetActivationTokenFail(ex))
        }
    }
}