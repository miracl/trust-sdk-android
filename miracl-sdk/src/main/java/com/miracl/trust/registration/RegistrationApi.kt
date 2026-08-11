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
internal data class RegisterRequestBody(
    @SerialName("userId") val userId: String,
    @SerialName("deviceName") val deviceName: String,
    @SerialName("activationToken") val activationToken: String,
    @SerialName("pushToken") val pushToken: String? = null,
    @SerialName("publicKey") val publicKey: String,
    @SerialName("deviceTag") val deviceTag: String,
    @SerialName("ver") val ver: Int = 2
)

@Serializable
internal data class RegisterResponse(
    @SerialName("mpinId") val mpinId: String,
    @SerialName("projectId") val projectId: String,
    @SerialName("designatedTAs") val designatedTAs: List<DesignatedTA>
)

@Serializable
internal data class DesignatedTA(
    @SerialName("url") val url: String,
    @SerialName("token") val token: String
)

@Serializable
internal data class TAShareRequestBody(
    @SerialName("mpinId") val mpinId: String,
    @SerialName("pubKey") val publicKey: String
)

@Serializable
internal data class TAShareResponse(
    @SerialName("node") val node: String,
    @SerialName("share") var share: String
)

internal interface RegistrationApi {
    suspend fun executeRegisterRequest(
        registerRequestBody: RegisterRequestBody,
        projectId: String
    ): MIRACLResult<RegisterResponse, RegistrationException>

    suspend fun executeTAShareRequest(
        designatedTA: DesignatedTA,
        taShareRequestBody: TAShareRequestBody
    ): MIRACLResult<TAShareResponse, RegistrationException>
}

internal class RegistrationApiManager(
    private val apiRequestExecutor: ApiRequestExecutor,
    private val jsonUtil: KotlinxSerializationJsonUtil,
    private val apiSettings: ApiSettings
) : RegistrationApi {
    companion object {
        const val INVALID_ACTIVATION_TOKEN = "INVALID_ACTIVATION_TOKEN"
    }

    override suspend fun executeRegisterRequest(
        registerRequestBody: RegisterRequestBody,
        projectId: String
    ): MIRACLResult<RegisterResponse, RegistrationException> {
        try {
            val registerRequestAsJson = jsonUtil.toJsonString(registerRequestBody)
            val registerRequest =
                ApiRequest(
                    method = HttpMethod.POST,
                    headers = null,
                    body = registerRequestAsJson,
                    params = null,
                    url = apiSettings.registerUrl
                )

            val result = apiRequestExecutor.execute(registerRequest)
            if (result is MIRACLError) {
                val exception = result.value
                if (exception is ApiException.ClientError && exception.clientErrorData?.code == INVALID_ACTIVATION_TOKEN) {
                    return MIRACLError(RegistrationException.InvalidActivationToken)
                }
                return MIRACLError(RegistrationException.RegistrationFail(exception))
            }

            val registerResponse =
                jsonUtil.fromJsonString<RegisterResponse>((result as MIRACLSuccess).value)

            return MIRACLSuccess(registerResponse)
        } catch (ex: Exception) {
            return MIRACLError(RegistrationException.RegistrationFail(ex))
        }
    }

    override suspend fun executeTAShareRequest(
        designatedTA: DesignatedTA,
        taShareRequestBody: TAShareRequestBody
    ): MIRACLResult<TAShareResponse, RegistrationException> {
        try {
            val taShareRequestAsJson = jsonUtil.toJsonString(taShareRequestBody)
            val taShareRequest =
                ApiRequest(
                    method = HttpMethod.POST,
                    headers = mapOf("Authorization" to "Bearer ${designatedTA.token}"),
                    body = taShareRequestAsJson,
                    params = null,
                    url = designatedTA.url
                )

            val result = apiRequestExecutor.execute(taShareRequest)
            if (result is MIRACLError) {
                return MIRACLError(RegistrationException.RegistrationFail(result.value))
            }

            val taShareResponse =
                jsonUtil.fromJsonString<TAShareResponse>((result as MIRACLSuccess).value)

            return MIRACLSuccess(taShareResponse)
        } catch (ex: Exception) {
            return MIRACLError(RegistrationException.RegistrationFail(ex))
        }
    }
}
