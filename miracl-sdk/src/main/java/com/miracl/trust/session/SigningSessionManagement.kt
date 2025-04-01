package com.miracl.trust.session

import android.net.Uri
import com.miracl.trust.MIRACLError
import com.miracl.trust.MIRACLResult
import com.miracl.trust.MIRACLSuccess
import com.miracl.trust.util.log.Loggable
import com.miracl.trust.util.log.LoggerConstants

internal interface SigningSessionManagerContract {
    suspend fun getSigningSessionDetailsFromAppLink(appLink: Uri): MIRACLResult<SigningSessionDetails, SigningSessionException>
    suspend fun getSigningSessionDetailsFromQRCode(qrCode: String): MIRACLResult<SigningSessionDetails, SigningSessionException>
    suspend fun abortSigningSession(signingSessionDetails: SigningSessionDetails): MIRACLResult<Unit, SigningSessionException>
}

internal class SigningSessionManager(
    private val signingSessionApi: SigningSessionApi
) : SigningSessionManagerContract, Loggable {

    private suspend fun getSigningSessionDetails(sessionId: String): MIRACLResult<SigningSessionDetails, SigningSessionException> {
        logOperation(LoggerConstants.FLOW_STARTED)

        logOperation(LoggerConstants.SigningSessionManagementOperations.SESSION_DETAILS_REQUEST)
        val sessionDetailsResult =
            signingSessionApi.executeSigningSessionDetailsRequest(sessionId)

        if (sessionDetailsResult is MIRACLError) {
            return MIRACLError(sessionDetailsResult.value)
        }

        val signingSessionDetailsResponse = (sessionDetailsResult as MIRACLSuccess).value
        val signingSessionDetails = SigningSessionDetails(
            sessionId = sessionId,
            userId = signingSessionDetailsResponse.userId,
            signingHash = signingSessionDetailsResponse.hash,
            signingDescription = signingSessionDetailsResponse.description,
            status = SigningSessionStatus.fromString(signingSessionDetailsResponse.status),
            expireTime = signingSessionDetailsResponse.expireTime,
            projectId = signingSessionDetailsResponse.projectId,
            projectName = signingSessionDetailsResponse.projectName,
            projectLogoUrl = signingSessionDetailsResponse.projectLogoUrl,
            pinLength = signingSessionDetailsResponse.pinLength,
            verificationMethod = VerificationMethod.fromString(signingSessionDetailsResponse.verificationMethod),
            verificationUrl = signingSessionDetailsResponse.verificationUrl,
            verificationCustomText = signingSessionDetailsResponse.verificationCustomText,
            identityType = IdentityType.fromString(signingSessionDetailsResponse.identityType),
            identityTypeLabel = signingSessionDetailsResponse.identityTypeLabel,
            quickCodeEnabled = signingSessionDetailsResponse.quickCodeEnabled,
            limitQuickCodeRegistration = signingSessionDetailsResponse.limitQuickCodeRegistration
        )

        logOperation(LoggerConstants.FLOW_FINISHED)

        return MIRACLSuccess(signingSessionDetails)
    }

    override suspend fun getSigningSessionDetailsFromAppLink(appLink: Uri): MIRACLResult<SigningSessionDetails, SigningSessionException> {
        val sessionId = appLink.fragment
            ?: return MIRACLError(SigningSessionException.InvalidAppLink)

        return getSigningSessionDetails(sessionId)
    }

    override suspend fun getSigningSessionDetailsFromQRCode(qrCode: String): MIRACLResult<SigningSessionDetails, SigningSessionException> {
        val sessionId = Uri.parse(qrCode)?.fragment ?: return MIRACLError(
            SigningSessionException.InvalidQRCode
        )

        return getSigningSessionDetails(sessionId)
    }

    override suspend fun abortSigningSession(signingSessionDetails: SigningSessionDetails): MIRACLResult<Unit, SigningSessionException> {
        logOperation(LoggerConstants.FLOW_STARTED)

        if (signingSessionDetails.sessionId.isBlank()) {
            return MIRACLError(SigningSessionException.InvalidSigningSessionDetails)
        }

        logOperation(LoggerConstants.SigningSessionManagementOperations.ABORT_SESSION_REQUEST)
        val abortSigningSessionResult =
            signingSessionApi.executeSigningSessionAbortRequest(signingSessionDetails.sessionId)

        if (abortSigningSessionResult is MIRACLError) {
            return MIRACLError(abortSigningSessionResult.value)
        }

        logOperation(LoggerConstants.FLOW_FINISHED)
        return MIRACLSuccess(Unit)
    }

    private fun logOperation(operation: String) {
        logger?.info(LoggerConstants.SIGNING_SESSION_MANAGER_TAG, operation)
    }
}