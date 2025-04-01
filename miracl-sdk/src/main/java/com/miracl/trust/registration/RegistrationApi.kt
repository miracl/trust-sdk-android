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
    @SerialName("activateCode") val activationToken: String,
    @SerialName("pushToken") val pushToken: String? = null,
)

@Serializable
internal data class RegisterResponse(
    @SerialName("mpinId") val mpinId: String,
    @SerialName("projectId") val projectId: String,
    @SerialName("regOTT") val regOTT: String
)

@Serializable
internal data class SignatureResponse(
    @SerialName("dvsClientSecretShare") var dvsClientSecretShare: String,
    @SerialName("cs2url") val clientSecret2Url: String,
    @SerialName("dtas") val dtas: String,
    @SerialName("curve") val curve: String
)

@Serializable
internal data class DVSClientSecretRequestBody(
    @SerialName("publicKey") val publicKey: String,
    @SerialName("deviceName") val deviceName: String,
    @SerialName("dvsRegisterToken") val dvsRegisterToken: String
)

@Serializable
internal data class DVSClientSecret1Response(
    @SerialName("dvsClientSecretShare") val dvsClientSecretShare: String,
    @SerialName("cs2url") val clientSecret2Url: String,
    @SerialName("curve") val curve: String,
    @SerialName("dtas") val dtas: String,
    @SerialName("mpinId") val mpinId: String
)

@Serializable
internal data class DVSClientSecret2Response(
    @SerialName("dvsClientSecret") var dvsClientSecret: String
)

internal interface RegistrationApi {
    suspend fun executeRegisterRequest(
        registerRequestBody: RegisterRequestBody,
        projectId: String
    ): MIRACLResult<RegisterResponse, RegistrationException>

    suspend fun executeSignatureRequest(
        mpinId: String,
        regOTT: String,
        publicKey: String
    ): MIRACLResult<SignatureResponse, RegistrationException>

    suspend fun executeDVSClientSecret1Request(
        publicKey: String,
        dvsRegistrationToken: String,
        deviceName: String
    ): MIRACLResult<DVSClientSecret1Response, RegistrationException>

    suspend fun executeDVSClientSecret2Request(
        clientSecretUrl: String,
        projectId: String
    ): MIRACLResult<DVSClientSecret2Response, RegistrationException>

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
                    method = HttpMethod.PUT,
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

    override suspend fun executeSignatureRequest(
        mpinId: String,
        regOTT: String,
        publicKey: String
    ): MIRACLResult<SignatureResponse, RegistrationException> {
        try {
            val signatureParams = mutableMapOf(
                "regOTT" to regOTT,
                "publicKey" to publicKey
            )
            val signatureRequest = ApiRequest(
                method = HttpMethod.GET,
                headers = null,
                body = null,
                params = signatureParams,
                url = "${apiSettings.signatureUrl}/$mpinId"
            )

            val result = apiRequestExecutor.execute(signatureRequest)
            if (result is MIRACLError) {
                return MIRACLError(RegistrationException.RegistrationFail(result.value))
            }

            val signatureResponse =
                jsonUtil.fromJsonString<SignatureResponse>((result as MIRACLSuccess).value)

            return MIRACLSuccess(signatureResponse)
        } catch (ex: java.lang.Exception) {
            return MIRACLError(RegistrationException.RegistrationFail(ex))
        }
    }

    override suspend fun executeDVSClientSecret1Request(
        publicKey: String,
        dvsRegistrationToken: String,
        deviceName: String
    ): MIRACLResult<DVSClientSecret1Response, RegistrationException> {
        val requestBody = DVSClientSecretRequestBody(
            publicKey,
            deviceName,
            dvsRegistrationToken
        )

        try {
            val requestBodyJson = jsonUtil.toJsonString(requestBody)
            val apiRequest = ApiRequest(
                method = HttpMethod.POST,
                headers = null,
                body = requestBodyJson,
                params = null,
                url = apiSettings.dvsRegUrl
            )

            val result = apiRequestExecutor.execute(apiRequest)
            if (result is MIRACLError) {
                return MIRACLError(
                    RegistrationException.RegistrationFail(result.value)
                )
            }

            val dvsClientSecret1Response =
                jsonUtil.fromJsonString<DVSClientSecret1Response>((result as MIRACLSuccess).value)

            return MIRACLSuccess(dvsClientSecret1Response)
        } catch (ex: Exception) {
            return MIRACLError(RegistrationException.RegistrationFail(ex))
        }
    }

    override suspend fun executeDVSClientSecret2Request(
        clientSecretUrl: String,
        projectId: String
    ): MIRACLResult<DVSClientSecret2Response, RegistrationException> {
        try {
            val clientSecretShare2Request = ApiRequest(
                method = HttpMethod.GET,
                headers = null,
                body = null,
                params = null,
                url = clientSecretUrl
            )

            val result = apiRequestExecutor.execute(clientSecretShare2Request)
            if (result is MIRACLError) {
                return MIRACLError(RegistrationException.RegistrationFail(result.value))
            }

            val dvsClientSecret2Response =
                jsonUtil.fromJsonString<DVSClientSecret2Response>((result as MIRACLSuccess).value)

            return MIRACLSuccess(dvsClientSecret2Response)
        } catch (ex: java.lang.Exception) {
            return MIRACLError(RegistrationException.RegistrationFail(ex))
        }
    }
}
