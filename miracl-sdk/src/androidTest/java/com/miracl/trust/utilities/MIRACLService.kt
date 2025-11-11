package com.miracl.trust.utilities

import android.net.Uri
import com.miracl.trust.MIRACLResult
import com.miracl.trust.MIRACLSuccess
import com.miracl.trust.network.ApiRequest
import com.miracl.trust.network.HttpMethod
import com.miracl.trust.network.HttpRequestExecutorException
import com.miracl.trust.network.HttpsURLConnectionRequestExecutor
import com.miracl.trust.signing.Signature
import com.miracl.trust.test.BuildConfig
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

@Serializable
data class SessionRequestBody(
    val projectId: String,
    val userId: String?,
    val description: String? = null,
    val hash: String? = null
)

@Serializable
data class AccessIdResponse(
    val qrURL: String,
    val webOTT: String
)

@Serializable
data class SessionStatusRequestBody(
    val webOTT: String
)

@Serializable
data class SessionStatusResponse(
    val status: String,
    val signature: String
)

@Serializable
data class VerificationRequestBody(
    val userId: String,
    val projectId: String,
    val accessId: String? = null,
    val expiration: Int? = null,
    val delivery: String = "no"
)

@Serializable
data class VerificationResponse(@SerialName("verificationURL") val verificationUrl: String)

@Serializable
internal data class ConfirmationRequestBody(val userId: String, val code: String)

@Serializable
internal data class ConfirmationResponse(val actToken: String)

@Serializable
data class SigningSessionCreateRequestBody(
    @SerialName("projectID") val projectId: String,
    @SerialName("userID") val userId: String,
    @SerialName("hash") val hash: String,
    @SerialName("description") val description: String
)

@Serializable
data class SigningSessionCreateResponse(val id: String, val qrURL: String, val expireTime: Long)

@Serializable
data class VerifySignatureRequestBody(
    val signature: Signature,
    val timestamp: Int
)

object MIRACLService {
    private val requestExecutor = HttpsURLConnectionRequestExecutor(10, 10)
    private val json = Json {
        encodeDefaults = true
        ignoreUnknownKeys = true
    }

    @JvmOverloads
    fun obtainAccessId(
        projectId: String = BuildConfig.CUV_PROJECT_ID,
        projectUrl: String = BuildConfig.CUV_PROJECT_URL,
        userId: String? = null,
        description: String? = null,
        hash: String? = null
    ): AccessIdResponse = runBlocking {
        val apiRequest = ApiRequest(
            method = HttpMethod.POST,
            headers = null,
            body = json.encodeToString(SessionRequestBody(projectId, userId, description, hash)),
            params = null,
            url = "$projectUrl/rps/v2/session"
        )

        val result = requestExecutor.execute(apiRequest)
        json.decodeFromString<AccessIdResponse>((result as MIRACLSuccess).value)
    }

    fun getSessionStatus(projectUrl: String, webOTT: String): SessionStatusResponse = runBlocking {
        val apiRequest = ApiRequest(
            method = HttpMethod.POST,
            headers = null,
            body = json.encodeToString(SessionStatusRequestBody(webOTT)),
            params = null,
            url = "$projectUrl/rps/v2/access"
        )

        val result = requestExecutor.execute(apiRequest)
        json.decodeFromString<SessionStatusResponse>((result as MIRACLSuccess).value)
    }

    fun getVerificationUrl(
        projectId: String = BuildConfig.CUV_PROJECT_ID,
        projectUrl: String = BuildConfig.CUV_PROJECT_URL,
        serviceAccountToken: String = BuildConfig.CUV_SERVICE_ACCOUNT_TOKEN,
        userId: String = USER_ID,
        accessId: String? = null,
        expiration: Int? = null
    ): String = runBlocking {
        val apiRequest = ApiRequest(
            method = HttpMethod.POST,
            headers = mapOf("Authorization" to "Bearer $serviceAccountToken"),
            body = json.encodeToString(
                VerificationRequestBody(
                    userId = userId,
                    projectId = projectId,
                    accessId = accessId,
                    expiration = expiration
                )
            ),
            params = null,
            url = "$projectUrl/verification"
        )

        val result = requestExecutor.execute(apiRequest)
        val verificationResponse =
            json.decodeFromString<VerificationResponse>((result as MIRACLSuccess).value)
        verificationResponse.verificationUrl
    }

    fun obtainActivationToken(
        projectId: String = BuildConfig.CUV_PROJECT_ID,
        projectUrl: String = BuildConfig.CUV_PROJECT_URL,
        serviceAccountToken: String = BuildConfig.CUV_SERVICE_ACCOUNT_TOKEN,
        userId: String = USER_ID
    ): String = runBlocking {
        val verificationUri =
            Uri.parse(getVerificationUrl(projectId, projectUrl, serviceAccountToken, userId))
        val userId = verificationUri.getQueryParameter("user_id")!!
        val code = verificationUri.getQueryParameter("code")!!

        val apiRequest = ApiRequest(
            method = HttpMethod.POST,
            headers = null,
            body = json.encodeToString(ConfirmationRequestBody(userId, code)),
            params = null,
            url = "$projectUrl/verification/confirmation"
        )

        val result = requestExecutor.execute(apiRequest)
        val activateInitiateResponse =
            json.decodeFromString<ConfirmationResponse>((result as MIRACLSuccess).value)
        activateInitiateResponse.actToken
    }

    suspend fun getJwkSet(projectUrl: String): MIRACLResult<String, HttpRequestExecutorException> {
        val apiRequest = ApiRequest(
            method = HttpMethod.GET,
            headers = null,
            body = null,
            params = null,
            url = "$projectUrl/.well-known/jwks"
        )

        return requestExecutor.execute(apiRequest)
    }

    fun createSigningSession(
        projectId: String,
        projectUrl: String,
        userId: String,
        hash: String,
        description: String
    ): SigningSessionCreateResponse = runBlocking {
        val apiRequest = ApiRequest(
            method = HttpMethod.POST,
            headers = null,
            body = json.encodeToString(
                SigningSessionCreateRequestBody(
                    projectId,
                    userId,
                    hash,
                    description
                )
            ),
            params = null,
            url = "$projectUrl/dvs/session"
        )

        val result = requestExecutor.execute(apiRequest)
        json.decodeFromString<SigningSessionCreateResponse>((result as MIRACLSuccess).value)
    }

    fun verifySignature(
        projectId: String,
        projectUrl: String,
        serviceAccountToken: String,
        signature: Signature,
        timestamp: Int
    ): Boolean = runBlocking {
        val apiRequest = ApiRequest(
            method = HttpMethod.POST,
            headers = mapOf("Authorization" to "Bearer $serviceAccountToken"),
            body = json.encodeToString(VerifySignatureRequestBody(signature, timestamp)),
            params = mapOf("project_id" to projectId),
            url = "$projectUrl/dvs/verify"
        )

        val result = requestExecutor.execute(apiRequest)
        result is MIRACLSuccess
    }
}