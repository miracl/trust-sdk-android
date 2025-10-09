package com.miracl.trust.session

import android.net.Uri
import com.miracl.trust.MIRACLError
import com.miracl.trust.MIRACLResult
import com.miracl.trust.MIRACLSuccess
import com.miracl.trust.util.log.Loggable
import com.miracl.trust.util.log.LoggerConstants

internal enum class SessionStatus(val value: String) {
    WID("wid"),
    ABORT("abort"),
    USER("user")
}

internal interface SessionManagerContract {
    suspend fun getSessionDetailsFromAppLink(appLink: Uri): MIRACLResult<AuthenticationSessionDetails, AuthenticationSessionException>
    suspend fun getSessionDetailsFromQRCode(qrCode: String): MIRACLResult<AuthenticationSessionDetails, AuthenticationSessionException>
    suspend fun getSessionDetailsFromNotificationPayload(payload: Map<String, String>): MIRACLResult<AuthenticationSessionDetails, AuthenticationSessionException>
    suspend fun abortSession(authenticationSessionDetails: AuthenticationSessionDetails): MIRACLResult<Unit, AuthenticationSessionException>
}

internal class SessionManager(
    private val sessionApi: SessionApi
) : SessionManagerContract, Loggable {
    companion object {
        const val PUSH_NOTIFICATION_QR_URL = "qrURL"
    }

    private suspend fun getSessionDetails(accessId: String): MIRACLResult<AuthenticationSessionDetails, AuthenticationSessionException> {
        logOperation(LoggerConstants.FLOW_STARTED)

        logOperation(LoggerConstants.SessionManagementOperations.CODE_STATUS_REQUEST)
        val codeStatusResult =
            sessionApi.executeCodeStatusRequest(accessId, SessionStatus.WID.value)

        if (codeStatusResult is MIRACLError) {
            return MIRACLError(codeStatusResult.value)
        }

        val codeStatusResponse = (codeStatusResult as MIRACLSuccess).value
        val authenticationSessionDetails = AuthenticationSessionDetails(
            userId = codeStatusResponse.prerollId,
            projectId = codeStatusResponse.projectId,
            projectName = codeStatusResponse.projectName,
            projectLogoUrl = codeStatusResponse.projectLogoUrl,
            pinLength = codeStatusResponse.pinLength,
            accessId = accessId,
            verificationMethod = VerificationMethod.fromString(codeStatusResponse.verificationMethod),
            verificationUrl = codeStatusResponse.verificationUrl,
            verificationCustomText = codeStatusResponse.verificationCustomText,
            identityType = IdentityType.fromString(codeStatusResponse.identityType),
            identityTypeLabel = codeStatusResponse.identityTypeLabel,
            quickCodeEnabled = codeStatusResponse.quickCodeEnabled
        )

        logOperation(LoggerConstants.FLOW_FINISHED)

        return MIRACLSuccess(authenticationSessionDetails)
    }

    override suspend fun getSessionDetailsFromAppLink(appLink: Uri): MIRACLResult<AuthenticationSessionDetails, AuthenticationSessionException> {
        val accessId = appLink.fragment
            ?: return MIRACLError(AuthenticationSessionException.InvalidAppLink)

        return getSessionDetails(accessId)
    }

    override suspend fun getSessionDetailsFromQRCode(qrCode: String): MIRACLResult<AuthenticationSessionDetails, AuthenticationSessionException> {
        val accessId = Uri.parse(qrCode)?.fragment
            ?: return MIRACLError(AuthenticationSessionException.InvalidQRCode)

        return getSessionDetails(accessId)
    }

    override suspend fun getSessionDetailsFromNotificationPayload(payload: Map<String, String>): MIRACLResult<AuthenticationSessionDetails, AuthenticationSessionException> {
        val qrUrl = payload[PUSH_NOTIFICATION_QR_URL]

        if (qrUrl.isNullOrBlank()) {
            return MIRACLError(AuthenticationSessionException.InvalidNotificationPayload)
        }

        val accessId = Uri.parse(qrUrl)?.fragment
            ?: return MIRACLError(AuthenticationSessionException.InvalidNotificationPayload)

        return getSessionDetails(accessId)
    }

    override suspend fun abortSession(authenticationSessionDetails: AuthenticationSessionDetails): MIRACLResult<Unit, AuthenticationSessionException> {
        logOperation(LoggerConstants.FLOW_STARTED)

        if (authenticationSessionDetails.accessId.isBlank()) {
            return MIRACLError(AuthenticationSessionException.InvalidSessionDetails)
        }

        logOperation(LoggerConstants.SessionManagementOperations.ABORT_SESSION_REQUEST)
        val codeStatusResult =
            sessionApi.executeAbortSessionRequest(authenticationSessionDetails.accessId)

        if (codeStatusResult is MIRACLError) {
            return MIRACLError(codeStatusResult.value)
        }

        logOperation(LoggerConstants.FLOW_FINISHED)
        return MIRACLSuccess(Unit)
    }

    private fun logOperation(operation: String) {
        logger?.info(LoggerConstants.SESSION_MANAGER_TAG, operation)
    }
}