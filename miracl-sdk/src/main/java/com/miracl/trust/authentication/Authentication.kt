package com.miracl.trust.authentication

import android.net.Uri
import com.miracl.trust.MIRACLError
import com.miracl.trust.MIRACLResult
import com.miracl.trust.MIRACLSuccess
import com.miracl.trust.crypto.Crypto
import com.miracl.trust.delegate.PinProvider
import com.miracl.trust.model.User
import com.miracl.trust.model.isEmpty
import com.miracl.trust.model.revoke
import com.miracl.trust.registration.RegistratorContract
import com.miracl.trust.session.SessionApi
import com.miracl.trust.storage.UserStorage
import com.miracl.trust.util.acquirePin
import com.miracl.trust.util.hexStringToByteArray
import com.miracl.trust.util.log.Loggable
import com.miracl.trust.util.log.LoggerConstants
import com.miracl.trust.util.toHexString

internal enum class AuthenticatorScopes(val value: String) {
    SIGNING_AUTHENTICATION("dvs-auth"),
    OIDC("oidc"),
    JWT("jwt"),
    QUICK_CODE("reg-code")
}

internal interface AuthenticatorContract {
    suspend fun authenticate(
        user: User,
        accessId: String?,
        pinProvider: PinProvider,
        scope: Array<String>,
        deviceName: String
    ): MIRACLResult<AuthenticateResponse, AuthenticationException>

    suspend fun authenticateWithAppLink(
        user: User,
        appLink: Uri,
        pinProvider: PinProvider,
        scope: Array<String>,
        deviceName: String
    ): MIRACLResult<AuthenticateResponse, AuthenticationException>

    suspend fun authenticateWithQRCode(
        user: User,
        qrCode: String,
        pinProvider: PinProvider,
        scope: Array<String>,
        deviceName: String
    ): MIRACLResult<AuthenticateResponse, AuthenticationException>

    suspend fun authenticateWithNotificationPayload(
        payload: Map<String, String>,
        pinProvider: PinProvider,
        scope: Array<String>,
        deviceName: String
    ): MIRACLResult<AuthenticateResponse, AuthenticationException>
}

internal class Authenticator(
    private val authenticationApi: AuthenticationApi,
    private val sessionApi: SessionApi,
    private val crypto: Crypto,
    private val registrator: RegistratorContract,
    private val userStorage: UserStorage
) : AuthenticatorContract, Loggable {
    companion object {
        const val PUSH_NOTIFICATION_PROJECT_ID = "projectID"
        const val PUSH_NOTIFICATION_USER_ID = "userID"
        const val PUSH_NOTIFICATION_QR_URL = "qrURL"
    }

    override suspend fun authenticate(
        user: User,
        accessId: String?,
        pinProvider: PinProvider,
        scope: Array<String>,
        deviceName: String
    ): MIRACLResult<AuthenticateResponse, AuthenticationException> {
        logOperation(LoggerConstants.FLOW_STARTED)

        try {
            if (user.revoked) {
                return MIRACLError(AuthenticationException.Revoked)
            }

            if (user.projectId.isEmpty() || user.userId.isEmpty()) {
                return MIRACLError(AuthenticationException.InvalidUserData)
            }

            if (user.isEmpty()) {
                return MIRACLError(AuthenticationException.InvalidUserData)
            }

            val combinedMpinId = if (user.publicKey != null) {
                user.mpinId + user.publicKey
            } else user.mpinId

            // Update the status of the authentication session, if any
            accessId?.let {
                logOperation(LoggerConstants.AuthenticatorOperations.UPDATE_SESSION_STATUS)
                sessionApi.executeUpdateSessionRequest(accessId, user.userId)
            }

            var pinEntered: String? =
                acquirePin(pinProvider) ?: return MIRACLError(AuthenticationException.PinCancelled)
            if (pinEntered?.length != user.pinLength) {
                return MIRACLError(AuthenticationException.InvalidPin)
            }
            val pin =
                pinEntered.toIntOrNull() ?: return MIRACLError(AuthenticationException.InvalidPin)

            // Client 1
            logOperation(LoggerConstants.AuthenticatorOperations.CLIENT_PASS_1_PROOF)
            val pass1ProofResult = crypto.getClientPass1Proof(
                combinedMpinId,
                user.token,
                pin
            )
            if (pass1ProofResult is MIRACLError) {
                return MIRACLError(AuthenticationException.AuthenticationFail(pass1ProofResult.value))
            }

            val pass1Proof = (pass1ProofResult as MIRACLSuccess).value

            // Server 1
            val mpinId = user.mpinId.toHexString()
            val u = pass1Proof.U.toHexString()
            val publicKeyHex: String? = user.publicKey?.toHexString()

            val pass1RequestBody = Pass1RequestBody(
                mpinId = mpinId,
                dtas = user.dtas,
                U = u,
                scope = scope,
                publicKey = publicKeyHex
            )

            logOperation(LoggerConstants.AuthenticatorOperations.CLIENT_PASS_1_REQUEST)
            val pass1ResponseResult =
                authenticationApi.executePass1Request(pass1RequestBody, user.projectId)
            if (pass1ResponseResult is MIRACLError) {
                val exception = pass1ResponseResult.value
                if (exception is AuthenticationException.Revoked) {
                    revokeUser(user)
                }
                return MIRACLError(exception)
            }

            val pass1Response = (pass1ResponseResult as MIRACLSuccess).value

            // Client 2
            val y = pass1Response.Y.hexStringToByteArray()

            logOperation(LoggerConstants.AuthenticatorOperations.CLIENT_PASS_2_PROOF)
            val pass2ProofResult =
                crypto.getClientPass2Proof(
                    pass1Proof.X,
                    y,
                    pass1Proof.SEC
                )
            if (pass2ProofResult is MIRACLError) {
                return MIRACLError(AuthenticationException.AuthenticationFail(pass2ProofResult.value))
            }

            val pass2Proof = (pass2ProofResult as MIRACLSuccess).value

            // Server 2
            val v = pass2Proof.V.toHexString()
            val pass2RequestBody = Pass2RequestBody(
                mpinId = mpinId,
                accessId = accessId,
                V = v
            )

            logOperation(LoggerConstants.AuthenticatorOperations.CLIENT_PASS_2_REQUEST)
            val pass2ResponseResult =
                authenticationApi.executePass2Request(pass2RequestBody, user.projectId)
            if (pass2ResponseResult is MIRACLError) {
                return MIRACLError(pass2ResponseResult.value)
            }

            val pass2Response = (pass2ResponseResult as MIRACLSuccess).value

            // Authenticate
            val authenticateRequest =
                AuthenticateRequestBody(
                    authOtt = pass2Response.authOtt
                )

            logOperation(LoggerConstants.AuthenticatorOperations.AUTHENTICATE_REQUEST)
            val authenticationResponseResult =
                authenticationApi.executeAuthenticateRequest(authenticateRequest, user.projectId)
            if (authenticationResponseResult is MIRACLError) {
                val exception = authenticationResponseResult.value
                if (exception is AuthenticationException.Revoked) {
                    revokeUser(user)
                }
                return MIRACLError(exception)
            }

            val authenticateResponse = (authenticationResponseResult as MIRACLSuccess).value

            authenticateResponse.renewSecretResponse?.token?.let { dvsRegistrationToken ->
                logOperation(LoggerConstants.AuthenticatorOperations.RENEW_SECRET_STARTED)
                val renewResponse = registrator.overrideRegistration(
                    user.userId,
                    user.projectId,
                    dvsRegistrationToken,
                    { it.consume(pinEntered) },
                    deviceName
                )

                if (renewResponse is MIRACLSuccess) {
                    logOperation(LoggerConstants.AuthenticatorOperations.RENEW_SECRET_FINISHED)

                    logOperation(LoggerConstants.AuthenticatorOperations.RENEW_SECRET_AUTHENTICATE)
                    return authenticate(
                        renewResponse.value,
                        accessId,
                        { it.consume(pinEntered) },
                        scope,
                        deviceName
                    )
                }

                logOperation(LoggerConstants.AuthenticatorOperations.RENEW_SECRET_ERROR)
            }

            pinEntered = null
            return MIRACLSuccess(authenticateResponse)
        } catch (ex: Exception) {
            return MIRACLError(AuthenticationException.AuthenticationFail(ex))
        }
    }

    override suspend fun authenticateWithAppLink(
        user: User,
        appLink: Uri,
        pinProvider: PinProvider,
        scope: Array<String>,
        deviceName: String
    ): MIRACLResult<AuthenticateResponse, AuthenticationException> {
        val accessId = appLink.fragment
            ?: return MIRACLError(AuthenticationException.InvalidAppLink)

        return authenticate(user, accessId, pinProvider, scope, deviceName)
    }

    override suspend fun authenticateWithQRCode(
        user: User,
        qrCode: String,
        pinProvider: PinProvider,
        scope: Array<String>,
        deviceName: String
    ): MIRACLResult<AuthenticateResponse, AuthenticationException> {
        val accessId =
            Uri.parse(qrCode)?.fragment
                ?: return MIRACLError(AuthenticationException.InvalidQRCode)

        return authenticate(user, accessId, pinProvider, scope, deviceName)
    }

    override suspend fun authenticateWithNotificationPayload(
        payload: Map<String, String>,
        pinProvider: PinProvider,
        scope: Array<String>,
        deviceName: String
    ): MIRACLResult<AuthenticateResponse, AuthenticationException> {
        val projectId = payload[PUSH_NOTIFICATION_PROJECT_ID]
        val userId = payload[PUSH_NOTIFICATION_USER_ID]
        val qrUrl = payload[PUSH_NOTIFICATION_QR_URL]

        if (projectId.isNullOrBlank() || userId.isNullOrBlank() || qrUrl.isNullOrBlank()) {
            return MIRACLError(AuthenticationException.InvalidPushNotificationPayload)
        }

        val accessId = Uri.parse(qrUrl)?.fragment ?: return MIRACLError(
            AuthenticationException.InvalidPushNotificationPayload
        )

        val user = userStorage.getUser(userId, projectId) ?: return MIRACLError(
            AuthenticationException.UserNotFound
        )

        return authenticate(user, accessId, pinProvider, scope, deviceName)
    }

    private fun revokeUser(user: User) {
        try {
            userStorage.update(user.revoke())
        } catch (ex: Exception) {
            logger?.error(
                LoggerConstants.AUTHENTICATOR_TAG,
                LoggerConstants.AuthenticatorOperations.REVOKE_USER_ERROR.format(
                    ex
                )
            )
        }
    }

    private fun logOperation(operation: String) {
        logger?.info(LoggerConstants.AUTHENTICATOR_TAG, operation)
    }
}