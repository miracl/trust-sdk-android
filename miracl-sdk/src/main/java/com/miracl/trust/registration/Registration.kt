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
import com.miracl.trust.util.toUserDto
import com.miracl.trust.util.toHexString
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope

internal interface RegistratorContract {
    suspend fun register(
        userId: String,
        projectId: String,
        projectUrl: String,
        activationToken: String,
        pinProvider: PinProvider,
        deviceName: String,
        pushNotificationsToken: String?
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
        projectUrl: String,
        activationToken: String,
        pinProvider: PinProvider,
        deviceName: String,
        pushNotificationsToken: String?
    ): MIRACLResult<User, RegistrationException> {
        logOperation(LoggerConstants.FLOW_STARTED)

        validateInput(userId, activationToken)?.let { exception ->
            return MIRACLError(exception)
        }

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

        val registerRequestBody = RegisterRequestBody(
            userId = userId.trim(),
            deviceName = deviceName.trim(),
            activationToken = activationToken.trim(),
            pushToken = pushNotificationsToken,
            publicKey = signingKeyPair.publicKey.toHexString()
        )

        try {
            logOperation(LoggerConstants.RegistratorOperations.REGISTER_REQUEST)
            val registerResponseResult =
                registrationApi.executeRegisterRequest(registerRequestBody, projectUrl)
            if (registerResponseResult is MIRACLError) {
                return MIRACLError(registerResponseResult.value)
            }

            val registerResponse = (registerResponseResult as MIRACLSuccess).value
            if (registerResponse.projectId != projectId) {
                return MIRACLError(RegistrationException.ProjectMismatch)
            }

            if (!SupportedEllipticCurves.entries.map { it.name }
                    .contains(registerResponse.curve)) {
                return MIRACLError(RegistrationException.UnsupportedEllipticCurve)
            }

            return finishRegistration(
                userId,
                projectId,
                registerResponse.mpinId,
                signingKeyPair,
                registerResponse.secretUrls,
                registerResponse.dtas,
                pinProvider
            )
        } catch (ex: java.lang.Exception) {
            return MIRACLError(RegistrationException.RegistrationFail(ex))
        }
    }

    @VisibleForTesting(otherwise = VisibleForTesting.PRIVATE)
    suspend fun finishRegistration(
        userId: String,
        projectId: String,
        mpinId: String,
        signingKeyPair: SigningKeyPair,
        secretUrls: List<String>,
        dtas: String,
        pinProvider: PinProvider
    ): MIRACLResult<User, RegistrationException> = coroutineScope {
        try {
            logOperation(LoggerConstants.RegistratorOperations.DVS_CLIENT_SECRET_REQUESTS)
            val clientSecret1Request =
                async { registrationApi.executeDVSClientSecretRequest(secretUrls[0]) }
            val clientSecret2Request =
                async { registrationApi.executeDVSClientSecretRequest(secretUrls[1]) }

            val clientSecret1ResponseResult = clientSecret1Request.await()
            val clientSecret2ResponseResult = clientSecret2Request.await()

            validateDVSClientSecretResponse(clientSecret1ResponseResult)?.let { error ->
                return@coroutineScope MIRACLError(error)
            }
            val clientSecretShare1Response = (clientSecret1ResponseResult as MIRACLSuccess).value

            validateDVSClientSecretResponse(clientSecret2ResponseResult)?.let { error ->
                return@coroutineScope MIRACLError(error)
            }
            val clientSecretShare2Response = (clientSecret2ResponseResult as MIRACLSuccess).value

            val combinedMpinId = mpinId.hexStringToByteArray() + signingKeyPair.publicKey

            logOperation(LoggerConstants.RegistratorOperations.SIGNING_CLIENT_TOKEN)

            val pinEntered: String =
                acquirePin(pinProvider)
                    ?: return@coroutineScope MIRACLError(RegistrationException.PinCancelled)

            val pinLength = pinEntered.length
            if (pinLength < MIN_PIN_LENGTH || pinLength > MAX_PIN_LENGTH) {
                return@coroutineScope MIRACLError(RegistrationException.InvalidPin)
            }

            val pin = pinEntered.toIntOrNull() ?: return@coroutineScope MIRACLError(
                RegistrationException.InvalidPin
            )

            val tokenResult = crypto.getSigningClientToken(
                clientSecretShare1 = clientSecretShare1Response.dvsClientSecret.hexStringToByteArray(),
                clientSecretShare2 = clientSecretShare2Response.dvsClientSecret.hexStringToByteArray(),
                privateKey = signingKeyPair.privateKey,
                signingMpinId = combinedMpinId,
                pin = pin
            )

            clientSecretShare1Response.dvsClientSecret = ""
            clientSecretShare2Response.dvsClientSecret = ""

            validateDVSClientToken(tokenResult)?.let { error ->
                return@coroutineScope MIRACLError(error)
            }

            val token = (tokenResult as MIRACLSuccess).value
            createOrUpdateUser(
                userId = userId,
                projectId = projectId,
                pinLength = pinLength,
                mpinId = mpinId.hexStringToByteArray(),
                dtas = dtas,
                token = token,
                publicKey = signingKeyPair.publicKey
            )
        } catch (ex: java.lang.Exception) {
            MIRACLError(RegistrationException.RegistrationFail(ex))
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

    private fun validateDVSClientSecretResponse(
        clientSecret2Response: MIRACLResult<DVSClientSecretResponse, RegistrationException>
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
            userStorage.add(user.toUserDto())
            MIRACLSuccess(Unit)
        } catch (ex: Exception) {
            MIRACLError(RegistrationException.RegistrationFail(ex))
        }
    }

    private fun updateUser(user: User): MIRACLResult<Unit, RegistrationException> {
        return try {
            userStorage.update(user.toUserDto())
            MIRACLSuccess(Unit)
        } catch (ex: Exception) {
            MIRACLError(RegistrationException.RegistrationFail(ex))
        }
    }

    private fun logOperation(operation: String) {
        logger?.info(LoggerConstants.REGISTRATOR_TAG, operation)
    }
}
