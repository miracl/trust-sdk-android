package com.miracl.trust.registration

import androidx.annotation.VisibleForTesting
import com.miracl.trust.MIRACLError
import com.miracl.trust.MIRACLResult
import com.miracl.trust.MIRACLSuccess
import com.miracl.trust.crypto.Crypto
import com.miracl.trust.crypto.CryptoException
import com.miracl.trust.crypto.SigningKeyPair
import com.miracl.trust.crypto.SupportedEllipticCurves
import com.miracl.trust.delegate.PinProvider
import com.miracl.trust.model.User
import com.miracl.trust.storage.UserStorage
import com.miracl.trust.util.acquirePin
import com.miracl.trust.util.hexStringToByteArray
import com.miracl.trust.util.log.Loggable
import com.miracl.trust.util.log.LoggerConstants
import com.miracl.trust.util.toHexString

internal interface RegistratorContract {
    suspend fun register(
        userId: String,
        projectId: String,
        activationToken: String,
        pinProvider: PinProvider,
        deviceName: String,
        pushNotificationsToken: String?
    ): MIRACLResult<User, RegistrationException>

    suspend fun overrideRegistration(
        userId: String,
        projectId: String,
        dvsRegistrationToken: String,
        pinProvider: PinProvider,
        deviceName: String
    ): MIRACLResult<User, RegistrationException>
}

internal class Registrator(
    private val registrationApi: RegistrationApi,
    private val crypto: Crypto,
    private val userStorage: UserStorage
) : RegistratorContract, Loggable {
    companion object {
        internal const val MIN_PIN_LENGTH = 4
        internal const val MAX_PIN_LENGTH = 6
    }

    override suspend fun register(
        userId: String,
        projectId: String,
        activationToken: String,
        pinProvider: PinProvider,
        deviceName: String,
        pushNotificationsToken: String?
    ): MIRACLResult<User, RegistrationException> {
        logOperation(LoggerConstants.FLOW_STARTED)

        validateInput(userId, activationToken)?.let { exception ->
            return MIRACLError(exception)
        }

        val registerRequestBody = RegisterRequestBody(
            userId = userId.trim(),
            deviceName = deviceName.trim(),
            activationToken = activationToken.trim(),
            pushToken = pushNotificationsToken
        )

        try {
            logOperation(LoggerConstants.RegistratorOperations.REGISTER_REQUEST)
            val registerResponseResult =
                registrationApi.executeRegisterRequest(registerRequestBody, projectId)
            if (registerResponseResult is MIRACLError) {
                return MIRACLError(registerResponseResult.value)
            }

            val registerResponse = (registerResponseResult as MIRACLSuccess).value
            if (registerResponse.projectId != projectId) {
                return MIRACLError(RegistrationException.ProjectMismatch)
            }

            val signingKeyPairResponse = crypto.generateSigningKeyPair()
            if (signingKeyPairResponse is MIRACLError) {
                return MIRACLError(
                    RegistrationException.RegistrationFail(
                        signingKeyPairResponse.value
                    )
                )
            }

            val signingKeyPair = (signingKeyPairResponse as MIRACLSuccess).value

            logOperation(LoggerConstants.RegistratorOperations.SIGNATURE_REQUEST)
            val signatureResponseResult = registrationApi.executeSignatureRequest(
                registerResponse.mpinId,
                registerResponse.regOTT,
                signingKeyPair.publicKey.toHexString()
            )

            if (signatureResponseResult is MIRACLError) {
                return MIRACLError(signatureResponseResult.value)
            }

            val signatureResponse = (signatureResponseResult as MIRACLSuccess).value

            if (!SupportedEllipticCurves.values().map { it.name }
                    .contains(signatureResponse.curve)) {
                return MIRACLError(RegistrationException.UnsupportedEllipticCurve)
            }

            return finishRegistration(
                userId,
                projectId,
                registerResponse.mpinId,
                signingKeyPair,
                signatureResponse.dvsClientSecretShare,
                signatureResponse.clientSecret2Url,
                signatureResponse.dtas,
                pinProvider
            )
        } catch (ex: java.lang.Exception) {
            return MIRACLError(RegistrationException.RegistrationFail(ex))
        }
    }

    override suspend fun overrideRegistration(
        userId: String,
        projectId: String,
        dvsRegistrationToken: String,
        pinProvider: PinProvider,
        deviceName: String
    ): MIRACLResult<User, RegistrationException> {
        logOperation(LoggerConstants.RegistratorOperations.SIGNING_KEY_PAIR)
        val signingKeyPairResponse = crypto.generateSigningKeyPair()
        if (signingKeyPairResponse is MIRACLError) {
            return MIRACLError(
                RegistrationException.RegistrationFail(
                    signingKeyPairResponse.value
                )
            )
        }

        val signingKeyPair = (signingKeyPairResponse as MIRACLSuccess).value

        logOperation(LoggerConstants.RegistratorOperations.DVS_CLIENT_SECRET_1_REQUEST)
        val dvsClientSecret1ResponseResult = registrationApi.executeDVSClientSecret1Request(
            signingKeyPair.publicKey.toHexString(),
            dvsRegistrationToken,
            deviceName
        )
        validateDVSClientSecret1Response(dvsClientSecret1ResponseResult)?.let { error ->
            return MIRACLError(error)
        }

        val dvsClientSecret1Response = (dvsClientSecret1ResponseResult as MIRACLSuccess).value

        return finishRegistration(
            userId,
            projectId,
            dvsClientSecret1Response.mpinId,
            signingKeyPair,
            dvsClientSecret1Response.dvsClientSecretShare,
            dvsClientSecret1Response.clientSecret2Url,
            dvsClientSecret1Response.dtas,
            pinProvider
        )
    }

    @VisibleForTesting(otherwise = VisibleForTesting.PRIVATE)
    suspend fun finishRegistration(
        userId: String,
        projectId: String,
        mpinId: String,
        signingKeyPair: SigningKeyPair,
        clientSecretShare: String,
        clientSecret2Url: String,
        dtas: String,
        pinProvider: PinProvider
    ): MIRACLResult<User, RegistrationException> {
        try {
            logOperation(LoggerConstants.RegistratorOperations.DVS_CLIENT_SECRET_2_REQUEST)
            val clientSecretResponseResult =
                registrationApi.executeDVSClientSecret2Request(clientSecret2Url, projectId)
            validateDVSClientSecret2Response(clientSecretResponseResult)?.let { error ->
                return MIRACLError(error)
            }

            val clientSecretShare2Response = (clientSecretResponseResult as MIRACLSuccess).value
            val combinedMpinId = mpinId.hexStringToByteArray() + signingKeyPair.publicKey

            logOperation(LoggerConstants.RegistratorOperations.SIGNING_CLIENT_TOKEN)

            val pinEntered: String =
                acquirePin(pinProvider) ?: return MIRACLError(RegistrationException.PinCancelled)

            val pinLength = pinEntered.length
            if (pinLength < MIN_PIN_LENGTH || pinLength > MAX_PIN_LENGTH) {
                return MIRACLError(RegistrationException.InvalidPin)
            }

            val pin =
                pinEntered.toIntOrNull() ?: return MIRACLError(RegistrationException.InvalidPin)

            val tokenResult = crypto.getSigningClientToken(
                clientSecretShare1 = clientSecretShare.hexStringToByteArray(),
                clientSecretShare2 = clientSecretShare2Response.dvsClientSecret.hexStringToByteArray(),
                privateKey = signingKeyPair.privateKey,
                signingMpinId = combinedMpinId,
                pin = pin
            )

            clientSecretShare2Response.dvsClientSecret = ""

            validateDVSClientToken(tokenResult)?.let { error ->
                return MIRACLError(error)
            }

            val token = (tokenResult as MIRACLSuccess).value
            return createOrUpdateUser(
                userId = userId,
                projectId = projectId,
                pinLength = pinLength,
                mpinId = mpinId.hexStringToByteArray(),
                dtas = dtas,
                token = token,
                publicKey = signingKeyPair.publicKey
            )
        } catch (ex: java.lang.Exception) {
            return MIRACLError(RegistrationException.RegistrationFail(ex))
        }
    }

    private fun validateInput(
        userId: String,
        activationToken: String
    ): RegistrationException? {
        if (userId.isBlank()) {
            return RegistrationException.EmptyUserId
        }

        if (activationToken.isBlank()) {
            return RegistrationException.EmptyActivationToken
        }

        return null
    }

    private fun validateDVSClientSecret1Response(
        clientSecret1Response: MIRACLResult<DVSClientSecret1Response, RegistrationException>
    ): RegistrationException? =
        when (clientSecret1Response) {
            is MIRACLError -> clientSecret1Response.value

            is MIRACLSuccess -> {
                if (!SupportedEllipticCurves.values().map { it.name }
                        .contains(clientSecret1Response.value.curve)) {
                    RegistrationException.UnsupportedEllipticCurve
                } else if (clientSecret1Response.value.mpinId.isBlank()
                    || clientSecret1Response.value.dtas.isBlank()
                    || clientSecret1Response.value.dvsClientSecretShare.isBlank()
                    || clientSecret1Response.value.clientSecret2Url.isBlank()
                ) {
                    RegistrationException.RegistrationFail()
                } else {
                    null
                }
            }
        }

    private fun validateDVSClientSecret2Response(
        clientSecret2Response: MIRACLResult<DVSClientSecret2Response, RegistrationException>
    ): RegistrationException? =
        when (clientSecret2Response) {
            is MIRACLError -> clientSecret2Response.value

            is MIRACLSuccess -> {
                if (clientSecret2Response.value.dvsClientSecret.isBlank()) {
                    RegistrationException.RegistrationFail()
                } else {
                    null
                }
            }
        }

    private fun validateDVSClientToken(dvsClientTokenResponse: MIRACLResult<ByteArray, CryptoException>): RegistrationException? =
        when (dvsClientTokenResponse) {
            is MIRACLError -> RegistrationException.RegistrationFail(
                dvsClientTokenResponse.value
            )

            is MIRACLSuccess -> {
                if (dvsClientTokenResponse.value.isEmpty()) {
                    RegistrationException.RegistrationFail()
                } else {
                    null
                }
            }
        }

    private fun createOrUpdateUser(
        userId: String,
        projectId: String,
        pinLength: Int,
        mpinId: ByteArray,
        dtas: String,
        token: ByteArray,
        publicKey: ByteArray
    ): MIRACLResult<User, RegistrationException> {
        val user = User(
            userId = userId,
            projectId = projectId,
            revoked = false,
            pinLength = pinLength,
            mpinId = mpinId,
            dtas = dtas,
            token = token,
            publicKey = publicKey
        )

        if (userStorage.getUser(userId, projectId) == null) {
            logOperation(LoggerConstants.RegistratorOperations.SAVING_USER)
            val saveUserResult = saveUser(user)
            if (saveUserResult is MIRACLError) return MIRACLError(saveUserResult.value)
        } else {
            logOperation(LoggerConstants.RegistratorOperations.UPDATING_EXISTING_USER)
            val updateUserResult = updateUser(user)
            if (updateUserResult is MIRACLError) return MIRACLError(updateUserResult.value)
        }

        logOperation(LoggerConstants.FLOW_FINISHED)
        return MIRACLSuccess(user)
    }

    private fun saveUser(user: User): MIRACLResult<Unit, RegistrationException> {
        return try {
            userStorage.add(user)
            MIRACLSuccess(Unit)
        } catch (ex: Exception) {
            MIRACLError(RegistrationException.RegistrationFail(ex))
        }
    }

    private fun updateUser(user: User): MIRACLResult<Unit, RegistrationException> {
        return try {
            userStorage.update(user)
            MIRACLSuccess(Unit)
        } catch (ex: Exception) {
            MIRACLError(RegistrationException.RegistrationFail(ex))
        }
    }

    private fun logOperation(operation: String) {
        logger?.info(LoggerConstants.REGISTRATOR_TAG, operation)
    }
}
