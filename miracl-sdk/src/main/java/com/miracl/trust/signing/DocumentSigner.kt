package com.miracl.trust.signing

import com.miracl.trust.MIRACLError
import com.miracl.trust.MIRACLResult
import com.miracl.trust.MIRACLSuccess
import com.miracl.trust.authentication.AuthenticationException
import com.miracl.trust.authentication.AuthenticatorContract
import com.miracl.trust.authentication.AuthenticatorScopes
import com.miracl.trust.crypto.Crypto
import com.miracl.trust.crypto.CryptoException
import com.miracl.trust.delegate.PinProvider
import com.miracl.trust.model.User
import com.miracl.trust.model.isEmpty
import com.miracl.trust.session.CrossDeviceSession
import com.miracl.trust.session.CrossDeviceSessionApi
import com.miracl.trust.session.SigningSessionApi
import com.miracl.trust.session.SigningSessionDetails
import com.miracl.trust.session.SigningSessionException
import com.miracl.trust.session.SigningSessionStatus
import com.miracl.trust.storage.UserStorage
import com.miracl.trust.util.acquirePin
import com.miracl.trust.util.log.Loggable
import com.miracl.trust.util.log.LoggerConstants
import com.miracl.trust.util.secondsSince1970
import com.miracl.trust.util.toHexString
import com.miracl.trust.util.toUser
import java.util.*

internal class DocumentSigner(
    private val crypto: Crypto,
    private val authenticator: AuthenticatorContract,
    private val userStorage: UserStorage,
    private val signingSessionApi: SigningSessionApi,
    private val crossDeviceSessionApi: CrossDeviceSessionApi
) : Loggable {
    suspend fun sign(
        message: ByteArray,
        user: User,
        pinProvider: PinProvider,
        deviceName: String,
        signingSessionDetails: SigningSessionDetails? = null
    ): MIRACLResult<SigningResult, SigningException> {
        logOperation(LoggerConstants.FLOW_STARTED)

        validateInputParameters(user, message, signingSessionDetails)?.let { error ->
            return MIRACLError(error)
        }

        var pinEntered: String? =
            acquirePin(pinProvider) ?: return MIRACLError(SigningException.PinCancelled)
        if (pinEntered?.length != user.pinLength) {
            return MIRACLError(SigningException.InvalidPin)
        }
        val pin = pinEntered.toIntOrNull() ?: return MIRACLError(SigningException.InvalidPin)

        val authenticateResponse = authenticator.authenticate(
            user,
            null,
            { it.consume(pinEntered) },
            arrayOf(AuthenticatorScopes.SIGNING_AUTHENTICATION.value),
            deviceName
        )
        if (authenticateResponse is MIRACLError) {
            return MIRACLError(
                when (authenticateResponse.value) {
                    is AuthenticationException.UnsuccessfulAuthentication -> SigningException.UnsuccessfulAuthentication
                    is AuthenticationException.Revoked -> SigningException.Revoked
                    else -> SigningException.SigningFail(authenticateResponse.value.cause)
                }
            )
        }

        val currentUser = userStorage.getUser(user.userId, user.projectId)?.toUser() ?: user

        if (currentUser.publicKey == null || currentUser.publicKey.isEmpty()) {
            return MIRACLError(SigningException.EmptyPublicKey)
        }

        val combinedMpinId = currentUser.mpinId + currentUser.publicKey
        val timestamp = Date()

        logOperation(LoggerConstants.DocumentSignerOperations.SIGNING)
        val signResponse = crypto.sign(
            message,
            combinedMpinId,
            currentUser.token,
            timestamp,
            pin
        )

        validateCryptoSign(signResponse)?.let { error ->
            return MIRACLError(error)
        }

        pinEntered = null

        val signingResult = (signResponse as MIRACLSuccess).value
        val signature = Signature(
            mpinId = currentUser.mpinId.toHexString(),
            U = signingResult.u.toHexString(),
            V = signingResult.v.toHexString(),
            publicKey = currentUser.publicKey.toHexString(),
            dtas = currentUser.dtas,
            hash = message.toHexString(),
            timestamp = timestamp.secondsSince1970()
        )

        if (signingSessionDetails == null) {
            logOperation(LoggerConstants.FLOW_FINISHED)
            return MIRACLSuccess(SigningResult(signature, timestamp))
        }

        return completeSigningSession(signingSessionDetails, signature, timestamp)
    }

    suspend fun sign(
        crossDeviceSession: CrossDeviceSession,
        user: User,
        pinProvider: PinProvider,
        deviceName: String
    ): MIRACLResult<Unit, SigningException> {
        val signingResult =
            sign(crossDeviceSession.signingHash.toByteArray(), user, pinProvider, deviceName)

        if (signingResult is MIRACLError) {
            return MIRACLError(signingResult.value)
        }

        logOperation(LoggerConstants.DocumentSignerOperations.UPDATE_CROSS_DEVICE_SESSION_REQUEST)
        val updateSessionResult =
            crossDeviceSessionApi.executeUpdateCrossDeviceSessionForSigningRequest(
                sessionId = crossDeviceSession.sessionId,
                signature = (signingResult as MIRACLSuccess).value.signature
            )

        if (updateSessionResult is MIRACLError) {
            return MIRACLError(SigningException.SigningFail(updateSessionResult.value))
        }

        logOperation(LoggerConstants.FLOW_FINISHED)
        return MIRACLSuccess(Unit)
    }

    private suspend fun completeSigningSession(
        signingSessionDetails: SigningSessionDetails,
        signature: Signature,
        timestamp: Date
    ): MIRACLResult<SigningResult, SigningException> {
        logOperation(LoggerConstants.DocumentSignerOperations.UPDATE_SIGNING_SESSION_REQUEST)
        val updateSigningSessionResult =
            signingSessionApi.executeSigningSessionUpdateRequest(
                signingSessionDetails.sessionId,
                signature,
                timestamp.secondsSince1970()
            )

        if (updateSigningSessionResult is MIRACLError) {
            if (updateSigningSessionResult.value is SigningSessionException.InvalidSigningSession) {
                return MIRACLError(SigningException.InvalidSigningSession)
            }

            return MIRACLError(SigningException.SigningFail(updateSigningSessionResult.value))
        }

        val signingSessionStatus = SigningSessionStatus.fromString(
            (updateSigningSessionResult as MIRACLSuccess).value.status
        )

        if (signingSessionStatus != SigningSessionStatus.Signed) {
            return MIRACLError(SigningException.InvalidSigningSession)
        }

        logOperation(LoggerConstants.FLOW_FINISHED)
        return MIRACLSuccess(SigningResult(signature, timestamp))
    }

    private fun validateInputParameters(
        user: User,
        message: ByteArray,
        signingSessionDetails: SigningSessionDetails?
    ): SigningException? {
        if (user.isEmpty()) {
            return SigningException.InvalidUserData
        }

        if (user.revoked) {
            return SigningException.Revoked
        }

        if (message.isEmpty()) {
            return SigningException.EmptyMessageHash
        }

        if (signingSessionDetails?.sessionId?.isBlank() == true) {
            return SigningException.InvalidSigningSessionDetails
        }

        return null
    }

    private fun validateCryptoSign(
        signResponse: MIRACLResult<com.miracl.trust.crypto.SigningResult, CryptoException>
    ): SigningException? =
        when (signResponse) {
            is MIRACLError -> SigningException.SigningFail(signResponse.value)
            is MIRACLSuccess -> {
                if (signResponse.value.u.isEmpty()
                    || signResponse.value.v.isEmpty()
                ) {
                    SigningException.SigningFail()
                } else {
                    null
                }
            }
        }

    private fun logOperation(operation: String) {
        logger?.info(LoggerConstants.DOCUMENT_SIGNER_TAG, operation)
    }
}