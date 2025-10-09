package com.miracl.trust.registration

import android.net.Uri
import com.miracl.trust.MIRACLError
import com.miracl.trust.MIRACLResult
import com.miracl.trust.MIRACLSuccess
import com.miracl.trust.authentication.AuthenticationException
import com.miracl.trust.authentication.AuthenticatorContract
import com.miracl.trust.authentication.AuthenticatorScopes
import com.miracl.trust.delegate.PinProvider
import com.miracl.trust.model.QuickCode
import com.miracl.trust.model.User
import com.miracl.trust.session.AuthenticationSessionDetails
import com.miracl.trust.session.CrossDeviceSession
import com.miracl.trust.storage.UserStorage
import com.miracl.trust.util.log.Loggable
import com.miracl.trust.util.log.LoggerConstants
import com.miracl.trust.util.toHexString

internal class Verificator(
    private val authenticator: AuthenticatorContract,
    private val verificationApi: VerificationApi,
    private val userStorage: UserStorage
) : Loggable {
    suspend fun sendVerificationEmail(
        userId: String,
        projectId: String,
        deviceName: String,
        authenticationSessionDetails: AuthenticationSessionDetails? = null,
        crossDeviceSession: CrossDeviceSession? = null
    ): MIRACLResult<VerificationResponse, VerificationException> {
        logOperation(LoggerConstants.FLOW_STARTED)

        validateVerifyInput(userId, authenticationSessionDetails)?.let { error ->
            return MIRACLError(error)
        }

        val mpinId = userStorage.getUser(userId, projectId)?.mpinId?.toHexString()

        val verificationRequestBody = VerificationRequestBody(
            projectId,
            userId,
            deviceName,
            authenticationSessionDetails?.accessId ?: crossDeviceSession?.sessionId,
            mpinId
        )

        logOperation(LoggerConstants.VerificatorOperations.VERIFY_REQUEST)
        val verificationResult =
            verificationApi.executeVerificationRequest(verificationRequestBody)

        logOperation(LoggerConstants.FLOW_FINISHED)
        return when (verificationResult) {
            is MIRACLSuccess -> MIRACLSuccess(
                VerificationResponse(
                    backoff = verificationResult.value.backoff,
                    method = EmailVerificationMethod.fromString(verificationResult.value.method)
                )
            )

            is MIRACLError -> MIRACLError(verificationResult.value)
        }
    }

    suspend fun generateQuickCode(
        user: User,
        pinProvider: PinProvider,
        deviceName: String
    ): MIRACLResult<QuickCode, QuickCodeException> {
        logOperation(LoggerConstants.FLOW_STARTED)
        val authenticateResponse = authenticator.authenticate(
            user,
            null,
            pinProvider,
            arrayOf(AuthenticatorScopes.QUICK_CODE.value),
            deviceName
        )

        if (authenticateResponse is MIRACLError) {
            return MIRACLError(
                when (authenticateResponse.value) {
                    is AuthenticationException.InvalidPin -> QuickCodeException.InvalidPin
                    is AuthenticationException.PinCancelled -> QuickCodeException.PinCancelled
                    is AuthenticationException.UnsuccessfulAuthentication -> QuickCodeException.UnsuccessfulAuthentication
                    is AuthenticationException.Revoked -> QuickCodeException.Revoked
                    else -> QuickCodeException.GenerationFail(authenticateResponse.value)
                }
            )
        }

        val jwt = (authenticateResponse as MIRACLSuccess).value.jwt
        if (jwt == null) {
            return MIRACLError(QuickCodeException.GenerationFail())
        }

        val quickCodeVerificationRequestBody = QuickCodeVerificationRequestBody(
            projectId = user.projectId,
            jwt = jwt,
            deviceName = deviceName
        )

        logOperation(LoggerConstants.VerificatorOperations.QUICK_CODE_REQUEST)
        val quickCodeResponse =
            verificationApi.executeQuickCodeVerificationRequest(quickCodeVerificationRequestBody)

        if (quickCodeResponse is MIRACLError) {
            return MIRACLError(quickCodeResponse.value)
        }

        logOperation(LoggerConstants.FLOW_FINISHED)
        val quickCode = (quickCodeResponse as MIRACLSuccess).value
        return MIRACLSuccess(QuickCode(quickCode.code, quickCode.expireTime, quickCode.ttlSeconds))
    }

    suspend fun getActivationToken(
        verificationUri: Uri
    ): MIRACLResult<ActivationTokenResponse, ActivationTokenException> {
        val userId = verificationUri.getQueryParameter("user_id") ?: ""
        val code = verificationUri.getQueryParameter("code") ?: ""

        return getActivationToken(userId, code)
    }

    suspend fun getActivationToken(
        userId: String,
        code: String
    ): MIRACLResult<ActivationTokenResponse, ActivationTokenException> {
        logOperation(LoggerConstants.FLOW_STARTED)

        validateActivationTokenInput(userId, code)?.let { error ->
            return MIRACLError(error)
        }

        val confirmationRequestBody = ConfirmationRequestBody(
            userId,
            code
        )

        logOperation(LoggerConstants.VerificatorOperations.ACTIVATION_TOKEN_REQUEST)
        val confirmationResult =
            verificationApi.executeConfirmationRequest(confirmationRequestBody)

        if (confirmationResult is MIRACLError) {
            return MIRACLError(confirmationResult.value)
        }
        val confirmationResponse = (confirmationResult as MIRACLSuccess).value

        if (confirmationResponse.activateToken.isBlank() || confirmationResponse.projectId.isBlank()) {
            return MIRACLError(ActivationTokenException.GetActivationTokenFail())
        }

        logOperation(LoggerConstants.FLOW_FINISHED)
        return MIRACLSuccess(
            ActivationTokenResponse(
                projectId = confirmationResponse.projectId,
                accessId = confirmationResponse.accessId,
                userId = userId,
                activationToken = confirmationResponse.activateToken
            )
        )
    }

    private fun validateVerifyInput(
        userId: String,
        authenticationSessionDetails: AuthenticationSessionDetails?
    ): VerificationException? {
        if (userId.isBlank()) {
            return VerificationException.EmptyUserId
        }

        if (authenticationSessionDetails?.accessId?.isBlank() == true) {
            return VerificationException.InvalidSessionDetails
        }

        return null
    }

    private fun validateActivationTokenInput(
        userId: String,
        code: String
    ): ActivationTokenException? {
        if (userId.isBlank()) {
            return ActivationTokenException.EmptyUserId
        }

        if (code.isBlank()) {
            return ActivationTokenException.EmptyVerificationCode
        }

        return null
    }

    private fun logOperation(operation: String) {
        logger?.info(LoggerConstants.VERIFICATOR_TAG, operation)
    }
}