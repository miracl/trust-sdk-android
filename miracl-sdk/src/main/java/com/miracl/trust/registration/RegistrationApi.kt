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
    @SerialName("publicKey") val publicKey: String
)

@Serializable
internal data class RegisterResponse(
    @SerialName("mpinId") val mpinId: String,
    @SerialName("projectId") val projectId: String,
    @SerialName("dtas") val dtas: String,
    @SerialName("curve") val curve: String,
    @SerialName("secretUrls") val secretUrls: List<String>
)

@Serializable
internal data class DVSClientSecretResponse(
    @SerialName("dvsClientSecret") var dvsClientSecret: String
)

internal interface RegistrationApi {
    suspend fun executeRegisterRequest(
        registerRequestBody: RegisterRequestBody,
        projectId: String
    ): MIRACLResult<RegisterResponse, RegistrationException>

    suspend fun executeDVSClientSecretRequest(
        clientSecretUrl: String
    ): MIRACLResult<DVSClientSecretResponse, RegistrationException>

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

    override suspend fun executeDVSClientSecretRequest(
        clientSecretUrl: String
    ): MIRACLResult<DVSClientSecretResponse, RegistrationException> {
        try {
            val clientSecretShareRequest = ApiRequest(
                method = HttpMethod.GET,
                headers = null,
                body = null,
                params = null,
                url = clientSecretUrl
            )

            var result = apiRequestExecutor.execute(clientSecretShareRequest)

            if (result is MIRACLError) {
                if (result.value !is ApiException.ExecutionError) {
                    return MIRACLError(RegistrationException.RegistrationFail(result.value))
                }

                // Retry the request if there is an execution error
                result = apiRequestExecutor.execute(clientSecretShareRequest)
                if (result is MIRACLError) {
                    return MIRACLError(RegistrationException.RegistrationFail(result.value))
                }
            }

            val dvsClientSecretResponse =
                jsonUtil.fromJsonString<DVSClientSecretResponse>((result as MIRACLSuccess).value)

            return MIRACLSuccess(dvsClientSecretResponse)
        } catch (ex: java.lang.Exception) {
            return MIRACLError(RegistrationException.RegistrationFail(ex))
        }
    }
}
