package com.miracl.trust.factory

import android.content.Context
import com.miracl.trust.authentication.AuthenticationApi
import com.miracl.trust.authentication.Authenticator
import com.miracl.trust.authentication.AuthenticatorContract
import com.miracl.trust.crypto.Crypto
import com.miracl.trust.registration.*
import com.miracl.trust.session.*
import com.miracl.trust.signing.DocumentSigner
import com.miracl.trust.storage.UserStorage
import com.miracl.trust.storage.room.RoomDatabaseModule

internal class ComponentFactory(
    private val context: Context
) {
    private val crypto: Crypto = Crypto()

    fun defaultUserStorage(projectId: String): UserStorage =
        RoomDatabaseModule(context, projectId).userStorage()

    fun createVerificator(
        authenticator: AuthenticatorContract,
        verificationApi: VerificationApi,
        userStorage: UserStorage
    ): Verificator = Verificator(authenticator, verificationApi, userStorage)

    fun createRegistrator(
        registrationApi: RegistrationApi,
        userStorage: UserStorage
    ): RegistratorContract =
        Registrator(
            registrationApi,
            crypto,
            userStorage
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
            userStorage
        )

    fun createDocumentSigner(
        authenticator: AuthenticatorContract,
        userStorage: UserStorage,
        signingSessionApi: SigningSessionApi
    ): DocumentSigner =
        DocumentSigner(crypto, authenticator, userStorage, signingSessionApi)

    fun createSessionManager(
        sessionApi: SessionApi
    ): SessionManagerContract =
        SessionManager(sessionApi)

    fun createSigningSessionManager(
        signingSessionApi: SigningSessionApi
    ): SigningSessionManagerContract =
        SigningSessionManager(signingSessionApi)
}
