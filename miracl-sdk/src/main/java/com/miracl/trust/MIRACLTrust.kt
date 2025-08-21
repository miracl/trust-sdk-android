package com.miracl.trust

import android.content.Context
import android.net.Uri
import android.os.Build
import androidx.annotation.VisibleForTesting
import com.miracl.trust.authentication.*
import com.miracl.trust.authentication.AuthenticatorScopes
import com.miracl.trust.configuration.*
import com.miracl.trust.delegate.PinProvider
import com.miracl.trust.delegate.ResultHandler
import com.miracl.trust.factory.ComponentFactory
import com.miracl.trust.model.QuickCode
import com.miracl.trust.model.User
import com.miracl.trust.network.ApiRequestExecutor
import com.miracl.trust.network.ApiSettings
import com.miracl.trust.network.HttpsURLConnectionRequestExecutor
import com.miracl.trust.registration.*
import com.miracl.trust.session.*
import com.miracl.trust.session.SessionApiManager
import com.miracl.trust.session.SessionManagerContract
import com.miracl.trust.session.SigningSessionApiManager
import com.miracl.trust.session.SigningSessionManagerContract
import com.miracl.trust.signing.*
import com.miracl.trust.storage.UserStorageException
import com.miracl.trust.storage.UserStorage
import com.miracl.trust.util.json.KotlinxSerializationJsonUtil
import com.miracl.trust.util.log.DefaultLogger
import com.miracl.trust.util.log.Logger
import com.miracl.trust.util.log.LoggerConstants
import com.miracl.trust.util.toUserDto
import com.miracl.trust.util.toUser
import kotlinx.coroutines.*
import kotlin.jvm.Throws

/**
 * MIRACL Trust is the entry point of the MIRACL Trust SDK. It is configured and connects
 * with the MIRACL Trust Platform on its initialization.
 *
 * Initialization is done through [configure(context,configuration)][configure]. After initialization,
 * the SDK can be accessed through [getInstance()][getInstance].
 */
public class MIRACLTrust private constructor(
    context: Context,
    configuration: Configuration
) {
    public companion object {
        internal var logger: Logger? = null
            private set

        private const val NOT_INITIALIZED_EXCEPTION = "MIRACLTrust SDK not initialized!"

        private lateinit var instance: MIRACLTrust

        @JvmStatic
        public fun getInstance(): MIRACLTrust =
            if (this::instance.isInitialized) {
                instance
            } else {
                throw Exception(NOT_INITIALIZED_EXCEPTION)
            }

        /**
         * Initialize the MIRACLTrust SDK.
         *
         * > **To be used once**. Multiple uses could lead to unidentified behavior!
         *
         * @param context application context, used for managing storage.
         * @param configuration instance of [Configuration], used to configure the SDK.
         */
        @JvmStatic
        public fun configure(context: Context, configuration: Configuration) {
            instance = MIRACLTrust(context, configuration)
        }
    }

    //region Properties
    private val verificator: Verificator
    private val registrator: RegistratorContract
    private val documentSigner: DocumentSigner
    private val authenticator: AuthenticatorContract
    private val userStorage: UserStorage
    private val sessionManager: SessionManagerContract
    private val signingSessionManager: SigningSessionManagerContract

    private val miraclTrustScope: CoroutineScope

    @VisibleForTesting
    internal var resultHandlerDispatcher: CoroutineDispatcher = Dispatchers.Main

    private val deviceName: String = configuration.deviceName ?: Build.MODEL

    /** Project ID setting for the application in MIRACL Trust platform. */
    public var projectId: String = configuration.projectId
        private set

    //endregion

    //region Initialization
    init {
        logger = configuration.logger
            ?: DefaultLogger(
                configuration.loggingLevel ?: Logger.LoggingLevel.NONE
            )

        val httpRequestExecutor = configuration.httpRequestExecutor
            ?: HttpsURLConnectionRequestExecutor(
                configuration.connectTimeout,
                configuration.readTimeout
            )

        val apiRequestExecutor = ApiRequestExecutor(
            httpRequestExecutor,
            KotlinxSerializationJsonUtil,
            configuration.applicationInfo
        )

        val componentFactory = configuration.componentFactory ?: ComponentFactory(context)
        val apiSettings = ApiSettings(configuration.platformUrl)

        miraclTrustScope = CoroutineScope(SupervisorJob() + configuration.miraclCoroutineContext)

        userStorage = configuration.userStorage
            ?: componentFactory.defaultUserStorage(configuration.projectId)
        userStorage.loadStorage()

        val registrationApi = RegistrationApiManager(
            apiRequestExecutor = apiRequestExecutor,
            jsonUtil = KotlinxSerializationJsonUtil,
            apiSettings = apiSettings
        )

        registrator = componentFactory.createRegistrator(registrationApi, userStorage)

        val authenticationApi =
            AuthenticationApiManager(
                apiRequestExecutor = apiRequestExecutor,
                jsonUtil = KotlinxSerializationJsonUtil,
                apiSettings = apiSettings
            )

        val sessionApi =
            SessionApiManager(apiRequestExecutor, KotlinxSerializationJsonUtil, apiSettings)

        sessionManager = componentFactory.createSessionManager(sessionApi)

        authenticator =
            componentFactory.createAuthenticator(
                authenticationApi,
                sessionApi,
                registrator,
                userStorage
            )

        val verificationApi = VerificationApiManager(
            jsonUtil = KotlinxSerializationJsonUtil,
            apiRequestExecutor = apiRequestExecutor,
            apiSettings = apiSettings
        )

        verificator =
            componentFactory.createVerificator(authenticator, verificationApi, userStorage)

        val signingSessionApi =
            SigningSessionApiManager(apiRequestExecutor, KotlinxSerializationJsonUtil, apiSettings)
        signingSessionManager = componentFactory.createSigningSessionManager(signingSessionApi)

        documentSigner =
            componentFactory.createDocumentSigner(authenticator, userStorage, signingSessionApi)
    }
    //endregion

    //region SDK Configuration
    /**
     * Configure a new project ID when the SDK have to work with a different project.
     *
     * @param projectId `Project ID` setting for the MIRACL Platform that needs to be updated.
     */
    @Throws(ConfigurationException::class)
    public fun setProjectId(projectId: String) {
        if (projectId.isBlank()) {
            throw ConfigurationException.EmptyProjectId
        }

        this.projectId = projectId
    }
    //endregion

    //region Authentication Session management
    /**
     * Get `authentication` session details for project in MIRACL platform based on authentication session identifier.
     *
     * Use this method to get session details for application that tries to authenticate
     * against MIRACL Platform with the usage of AppLink.
     *
     * @param appLink a URI provided by the Intent.
     * @param resultHandler a callback to handle the result of getting session details.
     * - If successful, the result is [MIRACLSuccess] with the [AuthenticationSessionDetails].
     * - If an error occurs, the result is [MIRACLError] with exception describing issues with the
     * operation.
     */
    public fun getAuthenticationSessionDetailsFromAppLink(
        appLink: Uri,
        resultHandler: ResultHandler<AuthenticationSessionDetails, AuthenticationSessionException>
    ) {
        miraclTrustScope.launch {
            sessionManager.getSessionDetailsFromAppLink(appLink).also { result ->
                if (result is MIRACLError) {
                    logError(
                        LoggerConstants.SESSION_MANAGER_TAG,
                        result.value
                    )
                }

                withContext(resultHandlerDispatcher) {
                    resultHandler.onResult(result)
                }
            }
        }
    }

    /**
     * Get `authentication` session details for project in MIRACL platform based on authentication session identifier.
     *
     * Use this method to get session details for application that tries to authenticate
     * against MIRACL Platform with the usage of QR Code.
     *
     * @param qrCode a string read from the QR code.
     * @param resultHandler a callback to handle the result of getting session details.
     * - If successful, the result is [MIRACLSuccess] with the [AuthenticationSessionDetails].
     * - If an error occurs, the result is [MIRACLError] with exception describing issues with the
     * operation.
     */
    public fun getAuthenticationSessionDetailsFromQRCode(
        qrCode: String,
        resultHandler: ResultHandler<AuthenticationSessionDetails, AuthenticationSessionException>
    ) {
        miraclTrustScope.launch {
            sessionManager.getSessionDetailsFromQRCode(qrCode).also { result ->
                if (result is MIRACLError) {
                    logError(
                        LoggerConstants.SESSION_MANAGER_TAG,
                        result.value
                    )
                }

                withContext(resultHandlerDispatcher) {
                    resultHandler.onResult(result)
                }
            }
        }
    }

    /**
     * Get `authentication` session details for project in MIRACL platform based on authentication session identifier.
     *
     * Use this method to get session details for application that tries to authenticate
     * against MIRACL Platform with the usage of notification.
     *
     * @param payload key-value data provided by the notification.
     * @param resultHandler a callback to handle the result of getting session details.
     * - If successful, the result is [MIRACLSuccess] with the [AuthenticationSessionDetails].
     * - If an error occurs, the result is [MIRACLError] with exception describing issues with the
     * operation.
     */
    public fun getAuthenticationSessionDetailsFromNotificationPayload(
        payload: Map<String, String>,
        resultHandler: ResultHandler<AuthenticationSessionDetails, AuthenticationSessionException>
    ) {
        miraclTrustScope.launch {
            sessionManager.getSessionDetailsFromNotificationPayload(payload).also { result ->
                if (result is MIRACLError) {
                    logError(
                        LoggerConstants.SESSION_MANAGER_TAG,
                        result.value
                    )
                }

                withContext(resultHandlerDispatcher) {
                    resultHandler.onResult(result)
                }
            }
        }
    }

    /**
     * Cancel the authentication session.
     *
     * @param authenticationSessionDetails details for authentication session.
     * @param resultHandler a callback to handle the result of session abort.
     * - If successful, the result is [MIRACLSuccess].
     * - If an error occurs, the result is [MIRACLError] with exception describing issues with the
     * operation.
     */
    public fun abortAuthenticationSession(
        authenticationSessionDetails: AuthenticationSessionDetails,
        resultHandler: ResultHandler<Unit, AuthenticationSessionException>
    ) {
        miraclTrustScope.launch {
            sessionManager.abortSession(authenticationSessionDetails).also { result ->
                if (result is MIRACLError) {
                    logError(
                        LoggerConstants.SESSION_MANAGER_TAG,
                        result.value
                    )
                }

                withContext(resultHandlerDispatcher) {
                    resultHandler.onResult(result)
                }
            }
        }
    }
    //endregion

    //region Signing Session management
    /**
     * Get `signing` session details from MIRACL platform based on session identifier.
     *
     * Use this method to get signing session details for application that tries to sign
     * against MIRACL Platform with the usage of AppLink.
     *
     * @param appLink a URI provided by the Intent.
     * @param resultHandler a callback to handle the result of getting signing session details.
     * - If successful, the result is [MIRACLSuccess] with the [SigningSessionDetails].
     * - If an error occurs, the result is [MIRACLError] with exception describing issues with the
     * operation.
     */
    public fun getSigningSessionDetailsFromAppLink(
        appLink: Uri,
        resultHandler: ResultHandler<SigningSessionDetails, SigningSessionException>
    ) {
        miraclTrustScope.launch {
            signingSessionManager.getSigningSessionDetailsFromAppLink(appLink).also { result ->
                if (result is MIRACLError) {
                    logError(
                        LoggerConstants.SIGNING_SESSION_MANAGER_TAG,
                        result.value
                    )
                }

                withContext(resultHandlerDispatcher) {
                    resultHandler.onResult(result)
                }
            }
        }
    }

    /**
     * Get `signing` session details from MIRACL platform based on session identifier.
     *
     * Use this method to get signing session details for application that tries to sign
     * against MIRACL Platform with the usage of QR Code.
     *
     * @param qrCode a string read from the QR code.
     * @param resultHandler a callback to handle the result of getting signing session details.
     * - If successful, the result is [MIRACLSuccess] with the [SigningSessionDetails].
     * - If an error occurs, the result is [MIRACLError] with exception describing issues with the
     * operation.
     */
    public fun getSigningSessionDetailsFromQRCode(
        qrCode: String,
        resultHandler: ResultHandler<SigningSessionDetails, SigningSessionException>
    ) {
        miraclTrustScope.launch {
            signingSessionManager.getSigningSessionDetailsFromQRCode(qrCode).also { result ->
                if (result is MIRACLError) {
                    logError(
                        LoggerConstants.SIGNING_SESSION_MANAGER_TAG,
                        result.value
                    )
                }

                withContext(resultHandlerDispatcher) {
                    resultHandler.onResult(result)
                }
            }
        }
    }

    /**
     * Cancel the signing session.
     *
     * @param signingSessionDetails details for the signing session.
     * @param resultHandler a callback to handle the result of session abort.
     * - If successful, the result is [MIRACLSuccess].
     * - If an error occurs, the result is [MIRACLError] with exception describing issues with the
     * operation.
     */
    public fun abortSigningSession(
        signingSessionDetails: SigningSessionDetails,
        resultHandler: ResultHandler<Unit, SigningSessionException>
    ) {
        miraclTrustScope.launch {
            signingSessionManager.abortSigningSession(signingSessionDetails)
                .also { result ->
                    if (result is MIRACLError) {
                        logError(
                            LoggerConstants.SIGNING_SESSION_MANAGER_TAG,
                            result.value
                        )
                    }

                    withContext(resultHandlerDispatcher) {
                        resultHandler.onResult(result)
                    }
                }
        }
    }
    //endregion

    //region Verification
    /**
     * Default method to verify user identity against the MIRACL platform. In the current
     * implementation it is done by sending an email message.
     *
     * @param userId identifier of the user identity. To verify identity this identifier
     * needs to be valid email address.
     * @param resultHandler a callback to handle the result of the verification.
     * - If successful, the result is [MIRACLSuccess] with the [VerificationResponse].
     * - If an error occurs, the result is [MIRACLError] with exception describing issues with the
     * operation.
     */
    public fun sendVerificationEmail(
        userId: String,
        resultHandler: ResultHandler<VerificationResponse, VerificationException>
    ) {
        miraclTrustScope.launch {
            verificator.sendVerificationEmail(
                userId = userId,
                projectId = projectId,
                deviceName = deviceName
            ).also { result ->
                if (result is MIRACLError) {
                    logError(
                        LoggerConstants.VERIFICATOR_TAG,
                        result.value
                    )
                }

                withContext(resultHandlerDispatcher) {
                    resultHandler.onResult(result)
                }
            }
        }
    }

    /**
     * Default method to verify user identity against the MIRACL platform. In the current
     * implementation it is done by sending an email message.
     *
     * @param userId identifier of the user identity. To verify identity this identifier
     * needs to be valid email address.
     * @param authenticationSessionDetails details for authentication session.
     * @param resultHandler a callback to handle the result of the verification.
     * - If successful, the result is [MIRACLSuccess] with the [VerificationResponse].
     * - If an error occurs, the result is [MIRACLError] with exception describing issues with the
     * operation.
     */
    public fun sendVerificationEmail(
        userId: String,
        authenticationSessionDetails: AuthenticationSessionDetails,
        resultHandler: ResultHandler<VerificationResponse, VerificationException>
    ) {
        miraclTrustScope.launch {
            verificator.sendVerificationEmail(
                userId = userId,
                projectId = projectId,
                deviceName = deviceName,
                authenticationSessionDetails = authenticationSessionDetails
            ).also { result ->
                if (result is MIRACLError) {
                    logError(
                        LoggerConstants.VERIFICATOR_TAG,
                        result.value
                    )
                }

                withContext(resultHandlerDispatcher) {
                    resultHandler.onResult(result)
                }
            }
        }
    }

    /**
     * Generate [QuickCode](https://miracl.com/resources/docs/guides/built-in-user-verification/quickcode/)
     * for a registered user.
     * @param user the user to generate `QuickCode` for.
     * @param pinProvider a callback called from the SDK, when the user PIN is required.
     * @param resultHandler a callback to handle the result of the `QuickCode` generation.
     * - If successful, the result is [MIRACLSuccess] with the [QuickCode].
     * - If an error occurs, the result is [MIRACLError] with exception describing issues with the
     * operation.
     */
    public fun generateQuickCode(
        user: User,
        pinProvider: PinProvider,
        resultHandler: ResultHandler<QuickCode, QuickCodeException>
    ) {
        miraclTrustScope.launch {
            verificator.generateQuickCode(
                user,
                pinProvider,
                deviceName
            ).also { result ->
                if (result is MIRACLError) {
                    logError(
                        LoggerConstants.VERIFICATOR_TAG,
                        result.value
                    )
                }

                withContext(resultHandlerDispatcher) {
                    resultHandler.onResult(result)
                }
            }
        }
    }

    /**
     * The method confirms user verification and as a result, an activation token is obtained. This activation token should be used in the registration process.
     *
     * @param verificationUri a verification URI received as part of the verification process.
     * @param resultHandler a callback to handle the result of the verification.
     * - If successful, the result is [MIRACLSuccess] with the [ActivationTokenResponse].
     * - If an error occurs, the result is [MIRACLError] with exception describing issues with the
     * operation.
     */
    public fun getActivationToken(
        verificationUri: Uri,
        resultHandler: ResultHandler<ActivationTokenResponse, ActivationTokenException>
    ) {
        miraclTrustScope.launch {
            verificator.getActivationToken(
                verificationUri
            ).also { result ->
                if (result is MIRACLError) {
                    logError(
                        LoggerConstants.VERIFICATOR_TAG,
                        result.value
                    )
                }

                withContext(resultHandlerDispatcher) {
                    resultHandler.onResult(result)
                }
            }
        }
    }

    /**
     * The method confirms user verification and as a result, an activation token is obtained. This activation token should be used in the registration process.
     *
     * @param userId identifier of the user.
     * @param code the verification code sent to the user email.
     * @param resultHandler a callback to handle the result of the verification.
     * - If successful, the result is [MIRACLSuccess] with the [ActivationTokenResponse].
     * - If an error occurs, the result is [MIRACLError] with exception describing issues with the
     * operation.
     */
    public fun getActivationToken(
        userId: String,
        code: String,
        resultHandler: ResultHandler<ActivationTokenResponse, ActivationTokenException>
    ) {
        miraclTrustScope.launch {
            verificator.getActivationToken(
                userId, code
            ).also { result ->
                if (result is MIRACLError) {
                    logError(
                        LoggerConstants.VERIFICATOR_TAG,
                        result.value
                    )
                }

                withContext(resultHandlerDispatcher) {
                    resultHandler.onResult(result)
                }
            }
        }
    }
    //endregion

    //region Authentication User Registration
    /**
     * Provides end-user registration. Registers an end-user for a given MIRACLTrust Project
     * to the MIRACLTrust platform.
     *
     * @param userId provides an unique user id (i.e. email).
     * @param activationToken provides an activate token for verification.
     * @param pinProvider a callback called from the SDK, when the identity PIN is required.
     * @param pushNotificationsToken current device push notifications token. This is used
     * when push notifications for authentication are enabled in the platform.
     * @param resultHandler a callback to handle the result of the registration.
     * - If successful, the result is [MIRACLSuccess] with value of the registered user.
     * - If an error occurs, the result is [MIRACLError] with exception describing issues with the
     * operation.
     */
    @JvmOverloads
    public fun register(
        userId: String,
        activationToken: String,
        pinProvider: PinProvider,
        pushNotificationsToken: String? = null,
        resultHandler: ResultHandler<User, RegistrationException>
    ) {
        miraclTrustScope.launch {
            registrator.register(
                userId,
                projectId,
                activationToken,
                pinProvider,
                deviceName,
                pushNotificationsToken
            ).also { result ->
                if (result is MIRACLError) {
                    logError(
                        LoggerConstants.REGISTRATOR_TAG,
                        result.value
                    )
                }

                withContext(resultHandlerDispatcher) {
                    resultHandler.onResult(result)
                }
            }
        }
    }
    //endregion

    //region Authentication
    /**
     * Authenticate identity to the MIRACL Trust platform by generating a [JWT](https://jwt.io)
     * authentication token.
     *
     * Use this method to authenticate within your application.
     *
     * After the JWT authentication token is generated, it needs to be sent to the application
     * server for verification. When received, the application server should verify the
     * token signature using the MIRACL Trust [JWKS](https://api.mpin.io/.well-known/jwks)
     * endpoint and the `audience` claim which in this case is the application project ID.
     *
     * @param user the user to authenticate.
     * @param pinProvider a callback called from the SDK, when the identity PIN is required.
     * @param resultHandler a callback to handle the result of the authentication.
     * - If successful, the result is [MIRACLSuccess].
     * - If an error occurs, the result is [MIRACLError] with exception describing issues with the
     * operation.
     */
    public fun authenticate(
        user: User,
        pinProvider: PinProvider,
        resultHandler: ResultHandler<String, AuthenticationException>
    ) {
        miraclTrustScope.launch {
            authenticator.authenticate(
                user,
                null,
                pinProvider,
                arrayOf(AuthenticatorScopes.JWT.value),
                deviceName
            ).also { result ->
                when (result) {
                    is MIRACLSuccess -> {
                        val token = result.value.jwt

                        withContext(resultHandlerDispatcher) {
                            if (token != null) {
                                resultHandler.onResult(MIRACLSuccess(token))
                            } else {
                                resultHandler.onResult(MIRACLError(AuthenticationException.AuthenticationFail()))
                            }
                        }
                    }

                    is MIRACLError -> {
                        logError(
                            LoggerConstants.AUTHENTICATOR_TAG,
                            result.value
                        )

                        withContext(resultHandlerDispatcher) {
                            resultHandler.onResult(MIRACLError(result.value))
                        }
                    }
                }
            }
        }
    }

    /**
     * Authenticate identity in the MIRACL platform.
     *
     * Use this method to authenticate another device or application with the usage of
     * AppLink created by MIRACL platform.
     *
     * @param user the user to authenticate.
     * @param appLink a URI provided by the Intent.
     * @param pinProvider a callback called from the SDK, when the identity PIN is required.
     * @param resultHandler a callback to handle the result of the authentication.
     * - If successful, the result is [MIRACLSuccess].
     * - If an error occurs, the result is [MIRACLError] with exception describing issues with the
     * operation.
     */
    public fun authenticateWithAppLink(
        user: User,
        appLink: Uri,
        pinProvider: PinProvider,
        resultHandler: ResultHandler<Unit, AuthenticationException>
    ) {
        miraclTrustScope.launch {
            authenticator.authenticateWithAppLink(
                user,
                appLink,
                pinProvider,
                arrayOf(AuthenticatorScopes.OIDC.value),
                deviceName
            ).also { result ->
                when (result) {
                    is MIRACLSuccess -> {
                        withContext(resultHandlerDispatcher) {
                            resultHandler.onResult(MIRACLSuccess(Unit))
                        }
                    }

                    is MIRACLError -> {
                        logError(
                            LoggerConstants.AUTHENTICATOR_TAG,
                            result.value
                        )

                        withContext(resultHandlerDispatcher) {
                            resultHandler.onResult(MIRACLError(result.value))
                        }
                    }
                }
            }
        }
    }

    /**
     * Authenticate identity in the MIRACL platform.
     *
     * Use this method to authenticate another device or application with the usage of
     * QR Code presented on MIRACL login page.
     *
     * @param user the user to authenticate.
     * @param qrCode a string read from the QR code.
     * @param pinProvider a callback called from the SDK, when the identity PIN is required.
     * @param resultHandler a callback to handle the result of the authentication.
     * - If successful, the result is [MIRACLSuccess].
     * - If an error occurs, the result is [MIRACLError] with exception describing issues with the
     * operation.
     */
    public fun authenticateWithQRCode(
        user: User,
        qrCode: String,
        pinProvider: PinProvider,
        resultHandler: ResultHandler<Unit, AuthenticationException>
    ) {
        miraclTrustScope.launch {
            authenticator.authenticateWithQRCode(
                user,
                qrCode,
                pinProvider,
                arrayOf(AuthenticatorScopes.OIDC.value),
                deviceName
            ).also { result ->
                when (result) {
                    is MIRACLSuccess -> {
                        withContext(resultHandlerDispatcher) {
                            resultHandler.onResult(MIRACLSuccess(Unit))
                        }
                    }

                    is MIRACLError -> {
                        logError(
                            LoggerConstants.AUTHENTICATOR_TAG,
                            result.value
                        )

                        withContext(resultHandlerDispatcher) {
                            resultHandler.onResult(MIRACLError(result.value))
                        }
                    }
                }
            }
        }
    }

    /**
     * Authenticate identity in the MIRACL platform.
     *
     * Use this method to authenticate another device or application with the usage of
     * notification sent by MIRACL platform.
     *
     * @param payload key-value data provided by the notification.
     * @param pinProvider a callback called from the SDK, when the identity PIN is required.
     * @param resultHandler a callback to handle the result of the authentication.
     * - If successful, the result is [MIRACLSuccess].
     * - If an error occurs, the result is [MIRACLError] with exception describing issues with the
     * operation.
     */
    public fun authenticateWithNotificationPayload(
        payload: Map<String, String>,
        pinProvider: PinProvider,
        resultHandler: ResultHandler<Unit, AuthenticationException>
    ) {
        miraclTrustScope.launch {
            authenticator.authenticateWithNotificationPayload(
                payload,
                pinProvider,
                arrayOf(AuthenticatorScopes.OIDC.value),
                deviceName
            ).also { result ->
                when (result) {
                    is MIRACLSuccess -> {
                        withContext(resultHandlerDispatcher) {
                            resultHandler.onResult(MIRACLSuccess(Unit))
                        }
                    }

                    is MIRACLError -> {
                        logError(
                            LoggerConstants.AUTHENTICATOR_TAG,
                            result.value
                        )

                        withContext(resultHandlerDispatcher) {
                            resultHandler.onResult(MIRACLError(result.value))
                        }
                    }
                }
            }
        }
    }
    //endregion

    //region Signing
    /**
     * Create a cryptographic signature of the given document.
     * @param message the hash of the given document.
     * @param user an user with already registered signing identity.
     * @param pinProvider a callback called from the SDK, when the signing identity PIN is required.
     * @param resultHandler a callback to handle the result of the signing.
     * - If successful, the result is [MIRACLSuccess].
     * - If an error occurs, the result is [MIRACLError] with exception describing issues with the
     * operation.
     */
    public fun sign(
        message: ByteArray,
        user: User,
        pinProvider: PinProvider,
        resultHandler: ResultHandler<SigningResult, SigningException>
    ) {
        miraclTrustScope.launch {
            documentSigner
                .sign(
                    message,
                    user,
                    pinProvider,
                    deviceName
                )
                .also { result ->
                    if (result is MIRACLError) {
                        logError(
                            LoggerConstants.DOCUMENT_SIGNER_TAG,
                            result.value
                        )
                    }

                    withContext(resultHandlerDispatcher) {
                        resultHandler.onResult(result)
                    }
                }
        }
    }

    /**
     * Create a cryptographic signature of the given document.
     * @param message the hash of the given document.
     * @param user an user with already registered signing identity.
     * @param signingSessionDetails details for the signing session.
     * @param pinProvider a callback called from the SDK, when the signing identity PIN is required.
     * @param resultHandler a callback to handle the result of the signing.
     * - If successful, the result is [MIRACLSuccess].
     * - If an error occurs, the result is [MIRACLError] with exception describing issues with the
     * operation.
     * @suppress
     */
    public fun sign(
        message: ByteArray,
        user: User,
        signingSessionDetails: SigningSessionDetails,
        pinProvider: PinProvider,
        resultHandler: ResultHandler<SigningResult, SigningException>
    ) {
        miraclTrustScope.launch {
            documentSigner
                .sign(
                    message,
                    user,
                    pinProvider,
                    deviceName,
                    signingSessionDetails
                )
                .also { result ->
                    if (result is MIRACLError) {
                        logError(
                            LoggerConstants.DOCUMENT_SIGNER_TAG,
                            result.value
                        )
                    }

                    withContext(resultHandlerDispatcher) {
                        resultHandler.onResult(result)
                    }
                }
        }
    }
    //endregion

    //region Users
    /**
     * Get the registered users.
     * @return a list of users.
     */
    public suspend fun getUsers(): List<User> {
        return withContext(Dispatchers.IO) {
            try {
                userStorage.all().map { it.toUser() }
            } catch (ex: Exception) {
                throw UserStorageException(ex)
            }
        }
    }

    /**
     * Get the registered users.
     * @param resultHandler a callback to handle the result of the user retrieval.
     * - If successful, the result is [MIRACLSuccess] with a list of users.
     * - If an error occurs, the result is [MIRACLError] with a [UserStorageException].
     */
    public fun getUsers(resultHandler: ResultHandler<List<User>, UserStorageException>) {
        miraclTrustScope.launch {
            try {
                val users = userStorage.all().map { it.toUser() }

                withContext(resultHandlerDispatcher) {
                    resultHandler.onResult(MIRACLSuccess(users))
                }
            } catch (ex: Exception) {
                withContext(resultHandlerDispatcher) {
                    resultHandler.onResult(MIRACLError(UserStorageException(ex)))
                }
            }
        }
    }

    /**
     * Get a registered user.
     * @param userId Identifier of the user.
     * @return the user or null if there isn't registered user for the project with
     * this userId on the device.
     */
    public suspend fun getUser(userId: String): User? {
        return withContext(Dispatchers.IO) {
            try {
                userStorage.getUser(userId, projectId)?.toUser()
            } catch (ex: Exception) {
                throw UserStorageException(ex)
            }
        }
    }

    /**
     * Get a registered user.
     * @param userId Identifier of the user.
     * @param resultHandler a callback to handle the result of the user retrieval.
     * - If successful, the result is [MIRACLSuccess] with value of the user or null if
     *   there isn't registered user for the project with this userId on the device.
     * - If an error occurs, the result is [MIRACLError] with a [UserStorageException].
     */
    public fun getUser(userId: String, resultHandler: ResultHandler<User?, UserStorageException>) {
        miraclTrustScope.launch {
            try {
                val user = userStorage.getUser(userId, projectId)?.toUser()

                withContext(resultHandlerDispatcher) {
                    resultHandler.onResult(MIRACLSuccess(user))
                }
            } catch (ex: Exception) {
                withContext(resultHandlerDispatcher) {
                    resultHandler.onResult(MIRACLError(UserStorageException(ex)))
                }
            }
        }
    }

    /**
     * Delete a registered user.
     * @param user the user to be deleted.
     */
    public suspend fun delete(user: User) {
        withContext(Dispatchers.IO) {
            try {
                userStorage.delete(user.toUserDto())
            } catch (ex: Exception) {
                throw UserStorageException(ex)
            }
        }
    }

    /**
     * Delete a registered user.
     * @param user the user to be deleted.
     * @param resultHandler a callback to handle the result of the user removal.
     * - If successful, the result is [MIRACLSuccess].
     * - If an error occurs, the result is [MIRACLError] with a [UserStorageException].
     */
    public fun delete(user: User, resultHandler: ResultHandler<Unit, UserStorageException>) {
        miraclTrustScope.launch {
            try {
                userStorage.delete(user.toUserDto())

                withContext(resultHandlerDispatcher) {
                    resultHandler.onResult(MIRACLSuccess(Unit))
                }
            } catch (ex: Exception) {
                withContext(resultHandlerDispatcher) {
                    resultHandler.onResult(MIRACLError(UserStorageException(ex)))
                }
            }
        }
    }
    //endregion

    //region Private
    private fun logError(tag: String, exception: Exception) {
        logger?.error(
            tag,
            LoggerConstants.FLOW_ERROR
                .format(
                    exception
                )
        )
    }
    //endregion
}
