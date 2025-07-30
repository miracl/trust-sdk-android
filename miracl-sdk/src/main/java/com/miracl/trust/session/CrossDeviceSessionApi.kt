package com.miracl.trust.session

import android.util.Base64
import com.miracl.trust.MIRACLError
import com.miracl.trust.MIRACLResult
import com.miracl.trust.MIRACLSuccess
import com.miracl.trust.network.ApiRequest
import com.miracl.trust.network.ApiRequestExecutor
import com.miracl.trust.network.ApiSettings
import com.miracl.trust.network.HttpMethod
import com.miracl.trust.signing.Signature
import com.miracl.trust.util.json.KotlinxSerializationJsonUtil
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

internal enum class CrossDeviceSessionStatus(val value: String) {
    WID("wid"),
    ABORT("abort"),
    USER("user"),
    SIGNED("signed")
}

@Serializable
internal data class CrossDeviceSessionRequestBody(
    @SerialName("wid") val wid: String,
    @SerialName("status") val status: String,
    @SerialName("userId") val userId: String? = null,
    @SerialName("signature") val signature: String? = null
)

@Serializable
internal data class CrossDeviceSessionResponse(
    @SerialName("description") val description: String,
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
    @SerialName("enableRegistrationCode") val quickCodeEnabled: Boolean,
    @SerialName("limitRegCodeVerified") val limitQuickCodeRegistration: Boolean,
    @SerialName("hash") val hash: String
)

internal interface CrossDeviceSessionApi {
    suspend fun executeGetSessionRequest(
        sessionId: String,
    ): MIRACLResult<CrossDeviceSessionResponse, CrossDeviceSessionException>

    suspend fun executeUpdateCrossDeviceSessionForSigningRequest(
        sessionId: String,
        signature: Signature
    ): MIRACLResult<Unit, Exception>

    suspend fun executeAbortSessionRequest(
        sessionId: String
    ): MIRACLResult<Unit, CrossDeviceSessionException>
}

internal class CrossDeviceSessionApiManager(
    private val apiRequestExecutor: ApiRequestExecutor,
    private val jsonUtil: KotlinxSerializationJsonUtil,
    private val apiSettings: ApiSettings,
) : CrossDeviceSessionApi {
    override suspend fun executeGetSessionRequest(
        sessionId: String,
    ): MIRACLResult<CrossDeviceSessionResponse, CrossDeviceSessionException> {
        val requestBody =
            CrossDeviceSessionRequestBody(sessionId, CrossDeviceSessionStatus.WID.value)

        try {
            val crossDeviceSessionRequestAsJson = jsonUtil.toJsonString(requestBody)
            val apiRequest = ApiRequest(
                method = HttpMethod.POST,
                headers = null,
                body = crossDeviceSessionRequestAsJson,
                params = null,
                url = apiSettings.codeStatusUrl
            )

            val result = apiRequestExecutor.execute(apiRequest)
            if (result is MIRACLError) {
                return MIRACLError(
                    CrossDeviceSessionException.GetCrossDeviceSessionFail(
                        cause = result.value
                    )
                )
            }

            val crossDeviceSessionResponse =
                jsonUtil.fromJsonString<CrossDeviceSessionResponse>((result as MIRACLSuccess).value)

            return MIRACLSuccess(crossDeviceSessionResponse)
        } catch (ex: Exception) {
            return MIRACLError(CrossDeviceSessionException.GetCrossDeviceSessionFail(cause = ex))
        }
    }

    override suspend fun executeUpdateCrossDeviceSessionForSigningRequest(
        sessionId: String,
        signature: Signature
    ): MIRACLResult<Unit, Exception> {
        try {
            val signatureJson = jsonUtil.toJsonString(signature)
            val encodedSignature =
                Base64.encodeToString(signatureJson.toByteArray(), Base64.NO_WRAP)

            val requestBody = CrossDeviceSessionRequestBody(
                wid = sessionId,
                status = CrossDeviceSessionStatus.SIGNED.value,
                userId = null,
                signature = encodedSignature
            )

            val crossDeviceSessionRequestAsJson = jsonUtil.toJsonString(requestBody)
            val apiRequest = ApiRequest(
                method = HttpMethod.POST,
                headers = null,
                body = crossDeviceSessionRequestAsJson,
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

    override suspend fun executeAbortSessionRequest(sessionId: String): MIRACLResult<Unit, CrossDeviceSessionException> {
        val requestBody =
            CrossDeviceSessionRequestBody(sessionId, CrossDeviceSessionStatus.ABORT.value)

        try {
            val crossDeviceSessionRequestAsJson = jsonUtil.toJsonString(requestBody)
            val apiRequest = ApiRequest(
                method = HttpMethod.POST,
                headers = null,
                body = crossDeviceSessionRequestAsJson,
                params = null,
                url = apiSettings.codeStatusUrl
            )

            val result = apiRequestExecutor.execute(apiRequest)
            if (result is MIRACLError) {
                return MIRACLError(
                    CrossDeviceSessionException.AbortCrossDeviceSessionFail(
                        cause = result.value
                    )
                )
            }

            return MIRACLSuccess(Unit)
        } catch (ex: Exception) {
            return MIRACLError(CrossDeviceSessionException.AbortCrossDeviceSessionFail(cause = ex))
        }
    }
}