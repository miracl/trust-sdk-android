package com.miracl.trust.authentication

import androidx.annotation.Keep
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
internal data class AuthenticateRequestBody(
    @SerialName("authOTT") val authOtt: String,
    @SerialName("wam") val wam: String = "dvs"
)

@Serializable
internal data class RenewSecretResponse(
    @SerialName("token") val token: String?,
    @SerialName("curve") val curve: String?
)

@Serializable
internal data class AuthenticateResponse(
    @SerialName("status") val status: Int,
    @SerialName("message") val message: String,
    @SerialName("dvsRegister") val renewSecretResponse: RenewSecretResponse?,
    @SerialName("jwt") val jwt: String?
)

@Serializable
internal data class Pass1Response(@SerialName("y") val Y: String)

@Serializable
internal data class Pass2RequestBody(
    @SerialName("mpin_id") val mpinId: String,
    @SerialName("WID") val accessId: String?,
    @SerialName("V") val V: String
)

@Serializable
internal data class Pass2Response(@SerialName("authOTT") val authOtt: String)

@Keep
internal interface AuthenticationApi {
    suspend fun executePass1Request(
        pass1RequestBody: Pass1RequestBody,
        projectId: String
    ): MIRACLResult<Pass1Response, AuthenticationException>

    suspend fun executePass2Request(
        pass2RequestBody: Pass2RequestBody,
        projectId: String
    ): MIRACLResult<Pass2Response, AuthenticationException>

    suspend fun executeAuthenticateRequest(
        authenticationRequestBody: AuthenticateRequestBody,
        projectId: String
    ): MIRACLResult<AuthenticateResponse, AuthenticationException>
}

internal class AuthenticationApiManager(
    private val apiRequestExecutor: ApiRequestExecutor,
    private val jsonUtil: KotlinxSerializationJsonUtil,
    private val apiSettings: ApiSettings,
) : AuthenticationApi {
    companion object {
        const val INVALID_AUTH = "INVALID_AUTH"
        const val UNSUCCESSFUL_AUTHENTICATION = "UNSUCCESSFUL_AUTHENTICATION"
        const val INVALID_AUTH_SESSION = "INVALID_AUTH_SESSION"
        const val INVALID_AUTHENTICATION_SESSION = "INVALID_AUTHENTICATION_SESSION"
        const val MPINID_EXPIRED = "MPINID_EXPIRED"
        const val EXPIRED_MPINID = "EXPIRED_MPINID"
        const val MPINID_REVOKED = "MPINID_REVOKED"
        const val REVOKED_MPINID = "REVOKED_MPINID"
        const val LIMITED_QUICKCODE_GENERATION = "LIMITED_QUICKCODE_GENERATION"
    }

    override suspend fun executePass1Request(
        pass1RequestBody: Pass1RequestBody,
        projectId: String
    ): MIRACLResult<Pass1Response, AuthenticationException> {
        try {
            val pass1RequestBodyAsJson = jsonUtil.toJsonString(pass1RequestBody)
            val apiRequest = ApiRequest(
                method = HttpMethod.POST,
                headers = null,
                body = pass1RequestBodyAsJson,
                params = null,
                url = apiSettings.pass1Url
            )

            val result = apiRequestExecutor.execute(apiRequest)
            if (result is MIRACLError) {
                val exception = result.value
                if (exception is ApiException.ClientError &&
                    (exception.clientErrorData?.code == MPINID_EXPIRED ||
                            exception.clientErrorData?.code == EXPIRED_MPINID)
                ) {
                    return MIRACLError(AuthenticationException.Revoked)
                }
                return MIRACLError(AuthenticationException.AuthenticationFail(exception))
            }

            val pass1Response =
                jsonUtil.fromJsonString<Pass1Response>((result as MIRACLSuccess).value)

            return MIRACLSuccess(pass1Response)
        } catch (ex: Exception) {
            return MIRACLError(AuthenticationException.AuthenticationFail(ex))
        }
    }

    override suspend fun executePass2Request(
        pass2RequestBody: Pass2RequestBody,
        projectId: String
    ): MIRACLResult<Pass2Response, AuthenticationException> {
        try {
            val pass2RequestBodyAsJson = jsonUtil.toJsonString(pass2RequestBody)
            val apiRequest = ApiRequest(
                method = HttpMethod.POST,
                headers = null,
                body = pass2RequestBodyAsJson,
                params = null,
                url = apiSettings.pass2Url
            )

            val result = apiRequestExecutor.execute(apiRequest)
            if (result is MIRACLError) {
                return MIRACLError(AuthenticationException.AuthenticationFail(result.value))
            }

            val pass2Response =
                jsonUtil.fromJsonString<Pass2Response>((result as MIRACLSuccess).value)

            return MIRACLSuccess(pass2Response)
        } catch (ex: Exception) {
            return MIRACLError(AuthenticationException.AuthenticationFail(ex))
        }
    }

    override suspend fun executeAuthenticateRequest(
        authenticationRequestBody: AuthenticateRequestBody,
        projectId: String
    ): MIRACLResult<AuthenticateResponse, AuthenticationException> {
        try {
            val authenticateRequestBodyAsJson = jsonUtil.toJsonString(authenticationRequestBody)
            val apiRequest = ApiRequest(
                method = HttpMethod.POST,
                headers = null,
                body = authenticateRequestBodyAsJson,
                params = null,
                url = apiSettings.authenticateUrl
            )

            val result = apiRequestExecutor.execute(apiRequest)
            if (result is MIRACLError) {
                val exception = result.value
                if (exception is ApiException.ClientError) {
                    return when (exception.clientErrorData?.code) {
                        INVALID_AUTH_SESSION, INVALID_AUTHENTICATION_SESSION -> {
                            MIRACLError(AuthenticationException.InvalidAuthenticationSession)
                        }

                        INVALID_AUTH, UNSUCCESSFUL_AUTHENTICATION -> {
                            MIRACLError(AuthenticationException.UnsuccessfulAuthentication)
                        }

                        MPINID_REVOKED, REVOKED_MPINID -> {
                            MIRACLError(AuthenticationException.Revoked)
                        }

                        else -> {
                            MIRACLError(AuthenticationException.AuthenticationFail(exception))
                        }
                    }
                }
                return MIRACLError(AuthenticationException.AuthenticationFail(exception))
            }

            val authenticateResponse =
                jsonUtil.fromJsonString<AuthenticateResponse>((result as MIRACLSuccess).value)

            return MIRACLSuccess(authenticateResponse)
        } catch (ex: Exception) {
            return MIRACLError(AuthenticationException.AuthenticationFail(ex))
        }
    }
}
