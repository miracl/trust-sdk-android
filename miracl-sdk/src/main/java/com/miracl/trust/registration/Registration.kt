package com.miracl.trust.registration

import android.util.Base64
import androidx.annotation.VisibleForTesting
import com.miracl.trust.MIRACLError
import com.miracl.trust.MIRACLResult
import com.miracl.trust.MIRACLSuccess
import com.miracl.trust.core.DeviceTagProvider
import com.miracl.trust.crypto.Crypto
import com.miracl.trust.crypto.CryptoException
import com.miracl.trust.crypto.SigningKeyPair
import com.miracl.trust.delegate.PinProvider
import com.miracl.trust.model.User
import com.miracl.trust.storage.UserStorage
import com.miracl.trust.util.acquirePin
import com.miracl.trust.util.hexStringToByteArray
import com.miracl.trust.util.json.KotlinxSerializationJsonUtil
import com.miracl.trust.util.log.Logger
import com.miracl.trust.util.log.LoggerConstants
import com.miracl.trust.util.toUserDto
import com.miracl.trust.util.toHexString
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope

internal interface RegistratorContract {
    suspend fun register(
        userId: String,
        projectId: String,
        activationToken: String,
        pinProvider: PinProvider,
        deviceName: String,
        pushNotificationsToken: String?
    ): MIRACLResult<User, RegistrationException>
}

internal class Registrator(
    private val registrationApi: RegistrationApi,
    private val crypto: Crypto,
    private val userStorage: UserStorage,
    private val logger: Logger,
    private val deviceTagProvider: DeviceTagProvider,
    private val jsonUtil: KotlinxSerializationJsonUtil
) : RegistratorContract {
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
            publicKey = signingKeyPair.publicKey.toHexString(),
            deviceTag = deviceTagProvider.get()
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

            return finishRegistration(
                userId,
                projectId,
                registerResponse.mpinId,
                signingKeyPair,
                registerResponse.designatedTAs,
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
        designatedTAs: List<DesignatedTA>,
        pinProvider: PinProvider
    ): MIRACLResult<User, RegistrationException> = coroutineScope {
        try {
            val taShareRequestBody =
                TAShareRequestBody(mpinId, signingKeyPair.publicKey.toHexString())

            logOperation(LoggerConstants.RegistratorOperations.TA_SHARE_REQUESTS)
            val taShareResults = designatedTAs
                .take(2)
                .map { designatedTA ->
                    async {
                        registrationApi.executeTAShareRequest(
                            designatedTA,
                            taShareRequestBody
                        )
                    }
                }
                .awaitAll()

            val taShareResponses = taShareResults.map { response ->
                when (response) {
                    is MIRACLError -> return@coroutineScope MIRACLError(response.value)
                    is MIRACLSuccess -> response.value
                }
            }

            val nodes = taShareResponses.map { it.node }
            val dtas = Base64.encodeToString(
                jsonUtil.toJsonString(nodes).encodeToByteArray(),
                Base64.NO_WRAP
            )

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
                clientSecretShare1 = taShareResponses[0].share.hexStringToByteArray(),
                clientSecretShare2 = taShareResponses[1].share.hexStringToByteArray(),
                privateKey = signingKeyPair.privateKey,
                signingMpinId = combinedMpinId,
                pin = pin
            )

            taShareResponses[0].share = ""
            taShareResponses[1].share = ""

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
        logger.info(LoggerConstants.REGISTRATOR_TAG, operation)
    }
}
