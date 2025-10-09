package com.miracl.trust.session

import androidx.annotation.Keep
import com.miracl.trust.MIRACLError
import com.miracl.trust.MIRACLResult
import com.miracl.trust.MIRACLSuccess
import com.miracl.trust.network.ApiRequest
import com.miracl.trust.network.ApiRequestExecutor
import com.miracl.trust.network.ApiSettings
import com.miracl.trust.network.HttpMethod
import com.miracl.trust.util.json.KotlinxSerializationJsonUtil
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
internal data class CodeStatusRequestBody(
    @SerialName("wid") val wid: String,
    @SerialName("status") val status: String,
    @SerialName("userId") val userId: String? = null
)

@Serializable
internal data class CodeStatusResponse(
    @SerialName("prerollId") val prerollId: String,
    @SerialName("projectId") val projectId: String,
    @SerialName("projectName") val projectName: String,
    @SerialName("projectLogoURL") val projectLogoUrl: String,
    @SerialName("pinLength") val pinLength: Int,
    @SerialName("verificationMethod") val verificationMethod: String,
    @SerialName("verificationURL") val verificationUrl: String,
    @SerialName("verificationCustomText") val verificationCustomText: String,
    @SerialName("identityType") val identityType: String,
    @SerialName("identityTypeLabel") val identityTypeLabel: String,
    @SerialName("enableRegistrationCode") val quickCodeEnabled: Boolean
)

@Keep
internal interface SessionApi {
    suspend fun executeCodeStatusRequest(
        accessId: String,
        status: String,
        userId: String? = null
    ): MIRACLResult<CodeStatusResponse, AuthenticationSessionException>

    suspend fun executeAbortSessionRequest(
        accessId: String
    ): MIRACLResult<Unit, AuthenticationSessionException>

    suspend fun executeUpdateSessionRequest(
        accessId: String,
        userId: String
    ): MIRACLResult<Unit, Exception>
}

internal class SessionApiManager(
    private val apiRequestExecutor: ApiRequestExecutor,
    private val jsonUtil: KotlinxSerializationJsonUtil,
    private val apiSettings: ApiSettings,
) : SessionApi {
    override suspend fun executeCodeStatusRequest(
        accessId: String,
        status: String,
        userId: String?
    ): MIRACLResult<CodeStatusResponse, AuthenticationSessionException> {
        val requestBody = CodeStatusRequestBody(accessId, status, userId)

        try {
            val codeStatusRequestAsJson = jsonUtil.toJsonString(requestBody)
            val apiRequest = ApiRequest(
                method = HttpMethod.POST,
                headers = null,
                body = codeStatusRequestAsJson,
                params = null,
                url = apiSettings.codeStatusUrl
            )

            val result = apiRequestExecutor.execute(apiRequest)
            if (result is MIRACLError) {
                return MIRACLError(
                    AuthenticationSessionException.GetAuthenticationSessionDetailsFail(
                        result.value
                    )
                )
            }

            val codeStatusResponse =
                jsonUtil.fromJsonString<CodeStatusResponse>((result as MIRACLSuccess).value)

            return MIRACLSuccess(codeStatusResponse)
        } catch (ex: Exception) {
            return MIRACLError(AuthenticationSessionException.GetAuthenticationSessionDetailsFail(ex))
        }
    }

    override suspend fun executeAbortSessionRequest(accessId: String): MIRACLResult<Unit, AuthenticationSessionException> {
        val requestBody = CodeStatusRequestBody(accessId, SessionStatus.ABORT.value)

        try {
            val codeStatusRequestAsJson = jsonUtil.toJsonString(requestBody)
            val apiRequest = ApiRequest(
                method = HttpMethod.POST,
                headers = null,
                body = codeStatusRequestAsJson,
                params = null,
                url = apiSettings.codeStatusUrl
            )

            val result = apiRequestExecutor.execute(apiRequest)
            if (result is MIRACLError) {
                return MIRACLError(AuthenticationSessionException.AbortSessionFail(result.value))
            }

            return MIRACLSuccess(Unit)
        } catch (ex: Exception) {
            return MIRACLError(AuthenticationSessionException.AbortSessionFail(ex))
        }
    }

    override suspend fun executeUpdateSessionRequest(
        accessId: String,
        userId: String
    ): MIRACLResult<Unit, Exception> {
        val requestBody = CodeStatusRequestBody(accessId, SessionStatus.USER.value, userId)

        try {
            val codeStatusRequestAsJson = jsonUtil.toJsonString(requestBody)
            val apiRequest = ApiRequest(
                method = HttpMethod.POST,
                headers = null,
                body = codeStatusRequestAsJson,
                params = null,
                url = apiSettings.codeStatusUrl
            )

            val result = apiRequestExecutor.execute(apiRequest)
            if (result is MIRACLError) {
                return MIRACLError(result.value)
            }

            return MIRACLSuccess(Unit)
        } catch (ex: Exception) {
            return MIRACLError(ex)
        }
    }
}
