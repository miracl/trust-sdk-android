package com.miracl.trust.session

import com.miracl.trust.MIRACLError
import com.miracl.trust.MIRACLResult
import com.miracl.trust.MIRACLSuccess
import com.miracl.trust.network.ApiException
import com.miracl.trust.network.ApiRequest
import com.miracl.trust.network.ApiRequestExecutor
import com.miracl.trust.network.ApiSettings
import com.miracl.trust.network.HttpMethod
import com.miracl.trust.signing.Signature
import com.miracl.trust.util.json.KotlinxSerializationJsonUtil
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
internal data class SigningSessionDetailsRequestBody(
    @SerialName("id") val id: String
)

@Serializable
internal data class SigningSessionDetailsResponse(
    @SerialName("userID") val userId: String,
    @SerialName("hash") val hash: String,
    @SerialName("description") val description: String,
    @SerialName("status") val status: String,
    @SerialName("expireTime") val expireTime: Long,
    @SerialName("projectId") val projectId: String,
    @SerialName("projectName") val projectName: String,
    @SerialName("projectLogoURL") val projectLogoUrl: String,
    @SerialName("verificationMethod") val verificationMethod: String,
    @SerialName("verificationURL") val verificationUrl: String,
    @SerialName("verificationCustomText") val verificationCustomText: String,
    @SerialName("identityType") val identityType: String,
    @SerialName("identityTypeLabel") val identityTypeLabel: String,
    @SerialName("pinLength") val pinLength: Int,
    @SerialName("enableRegistrationCode") val quickCodeEnabled: Boolean
)

@Serializable
internal data class SigningSessionUpdateRequestBody(
    @SerialName("id") val id: String,
    @SerialName("signature") val signature: Signature,
    @SerialName("timestamp") val timestamp: Int
)

@Serializable
internal data class SigningSessionUpdateResponse(
    @SerialName("status") val status: String
)

@Serializable
internal data class SigningSessionAbortRequestBody(
    @SerialName("id") val id: String
)

internal interface SigningSessionApi {
    suspend fun executeSigningSessionDetailsRequest(
        sessionId: String
    ): MIRACLResult<SigningSessionDetailsResponse, SigningSessionException>

    suspend fun executeSigningSessionUpdateRequest(
        id: String,
        signature: Signature,
        timestamp: Int
    ): MIRACLResult<SigningSessionUpdateResponse, SigningSessionException>

    suspend fun executeSigningSessionAbortRequest(
        sessionId: String
    ): MIRACLResult<Unit, SigningSessionException>
}

internal class SigningSessionApiManager(
    private val apiRequestExecutor: ApiRequestExecutor,
    private val jsonUtil: KotlinxSerializationJsonUtil,
    private val apiSettings: ApiSettings,
) : SigningSessionApi {
    companion object {
        const val INVALID_REQUEST_PARAMETERS = "INVALID_REQUEST_PARAMETERS"
    }

    override suspend fun executeSigningSessionDetailsRequest(sessionId: String): MIRACLResult<SigningSessionDetailsResponse, SigningSessionException> {
        val requestBody = SigningSessionDetailsRequestBody(sessionId)

        try {
            val sessionDetailsRequestAsJson = jsonUtil.toJsonString(requestBody)
            val apiRequest = ApiRequest(
                method = HttpMethod.POST,
                headers = null,
                body = sessionDetailsRequestAsJson,
                params = null,
                url = apiSettings.signingSessionDetailsUrl
            )

            val result = apiRequestExecutor.execute(apiRequest)
            if (result is MIRACLError) {
                return MIRACLError(
                    if (result.value is ApiException.ClientError &&
                        result.value.clientErrorData?.code == INVALID_REQUEST_PARAMETERS &&
                        result.value.clientErrorData.context?.get("params") == "id"
                    ) {
                        SigningSessionException.InvalidSigningSession
                    } else {
                        SigningSessionException.GetSigningSessionDetailsFail(result.value)
                    }
                )
            }

            val sessionDetailsResponse =
                jsonUtil.fromJsonString<SigningSessionDetailsResponse>((result as MIRACLSuccess).value)

            return MIRACLSuccess(sessionDetailsResponse)
        } catch (ex: Exception) {
            return MIRACLError(SigningSessionException.GetSigningSessionDetailsFail(ex))
        }
    }

    override suspend fun executeSigningSessionUpdateRequest(
        id: String,
        signature: Signature,
        timestamp: Int
    ): MIRACLResult<SigningSessionUpdateResponse, SigningSessionException> {
        val requestBody = SigningSessionUpdateRequestBody(id, signature, timestamp)

        try {
            val sessionUpdateRequestAsJson = jsonUtil.toJsonString(requestBody)
            val apiRequest = ApiRequest(
                method = HttpMethod.PUT,
                headers = null,
                body = sessionUpdateRequestAsJson,
                params = null,
                url = apiSettings.signingSessionUrl
            )

            val result = apiRequestExecutor.execute(apiRequest)
            if (result is MIRACLError) {
                return MIRACLError(
                    if (result.value is ApiException.ClientError &&
                        result.value.clientErrorData?.code == INVALID_REQUEST_PARAMETERS &&
                        result.value.clientErrorData.context?.get("params") == "id"
                    ) {
                        SigningSessionException.InvalidSigningSession
                    } else {
                        SigningSessionException.CompleteSigningSessionFail(result.value)
                    }
                )
            }

            val sessionUpdateResponse =
                jsonUtil.fromJsonString<SigningSessionUpdateResponse>((result as MIRACLSuccess).value)

            return MIRACLSuccess(sessionUpdateResponse)
        } catch (ex: Exception) {
            return MIRACLError(SigningSessionException.CompleteSigningSessionFail(ex))
        }
    }

    override suspend fun executeSigningSessionAbortRequest(sessionId: String): MIRACLResult<Unit, SigningSessionException> {
        val requestBody = SigningSessionAbortRequestBody(sessionId)

        try {
            val sessionRequestAsJson = jsonUtil.toJsonString(requestBody)
            val apiRequest = ApiRequest(
                method = HttpMethod.DELETE,
                headers = null,
                body = sessionRequestAsJson,
                params = null,
                url = apiSettings.signingSessionUrl
            )

            val result = apiRequestExecutor.execute(apiRequest)
            if (result is MIRACLError) {
                return MIRACLError(
                    if (result.value is ApiException.ClientError &&
                        result.value.clientErrorData?.code == INVALID_REQUEST_PARAMETERS &&
                        result.value.clientErrorData.context?.get("params") == "id"
                    ) {
                        SigningSessionException.InvalidSigningSession
                    } else {
                        SigningSessionException.AbortSigningSessionFail(result.value)
                    }
                )
            }

            return MIRACLSuccess(Unit)
        } catch (ex: Exception) {
            return MIRACLError(SigningSessionException.AbortSigningSessionFail(ex))
        }
    }
}