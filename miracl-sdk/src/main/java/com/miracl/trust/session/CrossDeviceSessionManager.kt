package com.miracl.trust.session

import android.net.Uri
import com.miracl.trust.MIRACLError
import com.miracl.trust.MIRACLResult
import com.miracl.trust.MIRACLSuccess
import com.miracl.trust.network.toProjectUrl
import com.miracl.trust.util.log.Loggable
import com.miracl.trust.util.log.LoggerConstants

internal interface CrossDeviceSessionManagerContract {
    suspend fun getCrossDeviceSessionFromAppLink(appLink: Uri): MIRACLResult<CrossDeviceSession, CrossDeviceSessionException>
    suspend fun getCrossDeviceSessionFromQRCode(qrCode: String): MIRACLResult<CrossDeviceSession, CrossDeviceSessionException>
    suspend fun getCrossDeviceSessionFromNotificationPayload(payload: Map<String, String>): MIRACLResult<CrossDeviceSession, CrossDeviceSessionException>
    suspend fun abortSession(crossDeviceSession: CrossDeviceSession): MIRACLResult<Unit, CrossDeviceSessionException>
}

internal class CrossDeviceSessionManager(
    private val crossDeviceSessionApi: CrossDeviceSessionApi
) : CrossDeviceSessionManagerContract, Loggable {
    companion object {
        const val PUSH_NOTIFICATION_QR_URL = "qrURL"
    }

    private suspend fun getCrossDeviceSession(
        sessionId: String,
        projectUrl: String
    ): MIRACLResult<CrossDeviceSession, CrossDeviceSessionException> {
        logOperation(LoggerConstants.FLOW_STARTED)

        logOperation(LoggerConstants.SessionManagementOperations.CODE_STATUS_REQUEST)
        val codeStatusResult = crossDeviceSessionApi.executeGetSessionRequest(sessionId, projectUrl)

        if (codeStatusResult is MIRACLError) {
            return MIRACLError(codeStatusResult.value)
        }

        val codeStatusResponse = (codeStatusResult as MIRACLSuccess).value
        val crossDeviceSession = CrossDeviceSession(
            sessionId = sessionId,
            sessionDescription = codeStatusResponse.description,
            userId = codeStatusResponse.prerollId,
            projectId = codeStatusResponse.projectId,
            projectUrl = projectUrl,
            projectName = codeStatusResponse.projectName,
            projectLogoUrl = codeStatusResponse.projectLogoUrl,
            pinLength = codeStatusResponse.pinLength,
            verificationMethod = VerificationMethod.fromString(codeStatusResponse.verificationMethod),
            verificationUrl = codeStatusResponse.verificationUrl,
            verificationCustomText = codeStatusResponse.verificationCustomText,
            identityType = IdentityType.fromString(codeStatusResponse.identityType),
            identityTypeLabel = codeStatusResponse.identityTypeLabel,
            quickCodeEnabled = codeStatusResponse.quickCodeEnabled,
            signingHash = codeStatusResponse.hash
        )

        logOperation(LoggerConstants.FLOW_FINISHED)

        return MIRACLSuccess(crossDeviceSession)
    }

    override suspend fun getCrossDeviceSessionFromAppLink(appLink: Uri): MIRACLResult<CrossDeviceSession, CrossDeviceSessionException> {
        val sessionId = appLink.fragment
            ?: return MIRACLError(CrossDeviceSessionException.InvalidAppLink)

        return getCrossDeviceSession(sessionId, appLink.toProjectUrl())
    }

    override suspend fun getCrossDeviceSessionFromQRCode(qrCode: String): MIRACLResult<CrossDeviceSession, CrossDeviceSessionException> {
        val uri = Uri.parse(qrCode)
        val sessionId = uri?.fragment
            ?: return MIRACLError(CrossDeviceSessionException.InvalidQRCode)

        return getCrossDeviceSession(sessionId, uri.toProjectUrl())
    }

    override suspend fun getCrossDeviceSessionFromNotificationPayload(payload: Map<String, String>): MIRACLResult<CrossDeviceSession, CrossDeviceSessionException> {
        val qrUrl = payload[PUSH_NOTIFICATION_QR_URL]

        if (qrUrl.isNullOrBlank()) {
            return MIRACLError(CrossDeviceSessionException.InvalidNotificationPayload)
        }

        val uri = Uri.parse(qrUrl)
        val sessionId = uri?.fragment
            ?: return MIRACLError(CrossDeviceSessionException.InvalidNotificationPayload)

        return getCrossDeviceSession(sessionId, uri.toProjectUrl())
    }

    override suspend fun abortSession(crossDeviceSession: CrossDeviceSession): MIRACLResult<Unit, CrossDeviceSessionException> {
        logOperation(LoggerConstants.FLOW_STARTED)

        if (crossDeviceSession.sessionId.isBlank()) {
            return MIRACLError(CrossDeviceSessionException.InvalidCrossDeviceSession)
        }

        logOperation(LoggerConstants.SessionManagementOperations.ABORT_SESSION_REQUEST)
        val codeStatusResult = crossDeviceSessionApi.executeAbortSessionRequest(
            sessionId = crossDeviceSession.sessionId,
            projectUrl = crossDeviceSession.projectUrl
        )

        if (codeStatusResult is MIRACLError) {
            return MIRACLError(codeStatusResult.value)
        }

        logOperation(LoggerConstants.FLOW_FINISHED)
        return MIRACLSuccess(Unit)
    }

    private fun logOperation(operation: String) {
        logger?.info(LoggerConstants.CROSS_DEVICE_SESSION_MANAGER_TAG, operation)
    }
}