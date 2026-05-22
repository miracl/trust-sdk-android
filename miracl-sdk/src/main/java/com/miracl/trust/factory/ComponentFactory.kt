package com.miracl.trust.factory

import android.content.Context
import com.miracl.trust.authentication.AuthenticationApi
import com.miracl.trust.authentication.Authenticator
import com.miracl.trust.authentication.AuthenticatorContract
import com.miracl.trust.core.DeviceTagProvider
import com.miracl.trust.crypto.Crypto
import com.miracl.trust.registration.*
import com.miracl.trust.session.*
import com.miracl.trust.signing.DocumentSigner
import com.miracl.trust.storage.UserStorage
import com.miracl.trust.storage.room.RoomDatabaseModule
import com.miracl.trust.util.log.Logger

internal class ComponentFactory(
    private val context: Context,
    private val logger: Logger,
    private val deviceTagProvider: DeviceTagProvider
) {
    private val crypto: Crypto = Crypto(logger)

    fun defaultUserStorage(projectId: String): UserStorage =
        RoomDatabaseModule(context, projectId).userStorage()

    fun createVerificator(
        authenticator: AuthenticatorContract,
        verificationApi: VerificationApi,
        userStorage: UserStorage
    ): Verificator =
        Verificator(authenticator, verificationApi, userStorage, logger, deviceTagProvider)

    fun createRegistrator(
        registrationApi: RegistrationApi,
        userStorage: UserStorage
    ): RegistratorContract =
        Registrator(
            registrationApi,
            crypto,
            userStorage,
            logger,
            deviceTagProvider
        )

    fun createAuthenticator(
        authenticationApi: AuthenticationApi,
        sessionApi: SessionApi,
        registrator: RegistratorContract,
        userStorage: UserStorage
    ): AuthenticatorContract =
        Authenticator(
            authenticationApi,
            sessionApi,
            crypto,
            registrator,
            userStorage,
            logger
        )

    fun createDocumentSigner(
        authenticator: AuthenticatorContract,
        userStorage: UserStorage,
        crossDeviceSessionApi: CrossDeviceSessionApi
    ): DocumentSigner =
        DocumentSigner(crypto, authenticator, userStorage, crossDeviceSessionApi, logger)

    fun createSessionManager(
        sessionApi: SessionApi
    ): SessionManagerContract =
        SessionManager(sessionApi, logger)

    fun createCrossDeviceSessionManager(
        crossDeviceSessionApi: CrossDeviceSessionApi
    ): CrossDeviceSessionManagerContract =
        CrossDeviceSessionManager(crossDeviceSessionApi, logger)
}
