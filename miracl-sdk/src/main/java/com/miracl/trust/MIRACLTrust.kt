package com.miracl.trust

import android.content.Context
import android.net.Uri
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
import com.miracl.trust.registration.*
import com.miracl.trust.session.*
import com.miracl.trust.session.SessionApiManager
import com.miracl.trust.session.SessionManagerContract
import com.miracl.trust.signing.*
import com.miracl.trust.storage.UserStorageException
import com.miracl.trust.storage.UserStorage
import com.miracl.trust.util.UrlValidator
import com.miracl.trust.util.json.KotlinxSerializationJsonUtil
import com.miracl.trust.util.log.Logger
import com.miracl.trust.util.log.LoggerConstants
import com.miracl.trust.util.toUserDto
import com.miracl.trust.util.toUser
import kotlinx.coroutines.*
import kotlin.coroutines.CoroutineContext
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
    private val apiSettings: ApiSettings
    private val verificator: Verificator
    private val registrator: RegistratorContract
    private val documentSigner: DocumentSigner
    private val authenticator: AuthenticatorContract
    private val userStorage: UserStorage
    private val sessionManager: SessionManagerContract
    private val crossDeviceSessionManager: CrossDeviceSessionManagerContract

    private val miraclTrustCoroutineContext: CoroutineContext
    private val miraclTrustScope: CoroutineScope

    @VisibleForTesting
    internal var resultHandlerDispatcher: CoroutineDispatcher = Dispatchers.Main

    private val deviceName: String = configuration.deviceName

    /** Project ID setting for the application in MIRACL Trust platform. */
    public var projectId: String = configuration.projectId
        private set

    //endregion

    //region Initialization
    init {
        logger = configuration.logger

        val apiRequestExecutor = ApiRequestExecutor(
            configuration.httpRequestExecutor,
            KotlinxSerializationJsonUtil,
            configuration.applicationInfo
        )

        val componentFactory = configuration.componentFactory ?: ComponentFactory(context)
        apiSettings = ApiSettings(configuration.projectUrl)

        miraclTrustCoroutineContext = configuration.miraclCoroutineContext
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

        val crossDeviceSessionApi = CrossDeviceSessionApiManager(
            apiRequestExecutor,
            KotlinxSerializationJsonUtil,
            apiSettings
        )

        crossDeviceSessionManager =
            componentFactory.createCrossDeviceSessionManager(crossDeviceSessionApi)

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

        documentSigner = componentFactory.createDocumentSigner(
            authenticator = authenticator,
            userStorage = userStorage,
            crossDeviceSessionApi = crossDeviceSessionApi
        )
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

    /**
     * Configures new project settings when the SDK have to work with a different project.
     *
     * @param projectId The unique identifier for your MIRACL Trust project.
     * @param projectUrl MIRACL Trust Project URL that is used for communication with the MIRACL Trust API.
     */
    @Throws(ConfigurationException::class)
    public fun updateProjectSettings(projectId: String, projectUrl: String) {
        if (projectId.isBlank()) {
            throw ConfigurationException.EmptyProjectId
        }

        if (!UrlValidator.isValid(projectUrl)) {
            throw ConfigurationException.InvalidProjectUrl
        }

        this.projectId = projectId
        this.apiSettings.projectUrl = projectUrl
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

    //region CrossDeviceSession management
    /**
     * Get [CrossDeviceSession] for an AppLink.
     *
     * @param appLink a URI provided by the Intent.
     *
     * @return a [MIRACLResult] representing the result of the operation:
     * - If successful, returns [MIRACLSuccess] with the [CrossDeviceSession].
     * - If an error occurs, returns [MIRACLError] with a [CrossDeviceSessionException]
     * describing issues with the operation.
     * @suppress
     */
    @JvmSynthetic
    public suspend fun getCrossDeviceSessionFromAppLink(
        appLink: Uri,
    ): MIRACLResult<CrossDeviceSession, CrossDeviceSessionException> {
        return withContext(miraclTrustCoroutineContext) {
            crossDeviceSessionManager.getCrossDeviceSessionFromAppLink(appLink)
                .logIfError(LoggerConstants.CROSS_DEVICE_SESSION_MANAGER_TAG)
        }
    }

    /**
     * Get [CrossDeviceSession] for an AppLink.
     *
     * @param appLink a URI provided by the Intent.
     * @param resultHandler a callback to handle the result of getting details for the session.
     * - If successful, the result is [MIRACLSuccess] with the [CrossDeviceSession].
     * - If an error occurs, the result is [MIRACLError] with exception describing issues with the
     * operation.
     * @suppress
     */
    public fun getCrossDeviceSessionFromAppLink(
        appLink: Uri,
        resultHandler: ResultHandler<CrossDeviceSession, CrossDeviceSessionException>
    ) {
        miraclTrustScope.launch {
            crossDeviceSessionManager.getCrossDeviceSessionFromAppLink(appLink).also { result ->
                if (result is MIRACLError) {
                    logError(
                        LoggerConstants.CROSS_DEVICE_SESSION_MANAGER_TAG,
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
     * Get [CrossDeviceSession] for a QR code.
     *
     * @param qrCode a string read from the QR code.
     *
     * @return a [MIRACLResult] representing the result of the operation:
     * - If successful, returns [MIRACLSuccess] with the [CrossDeviceSession].
     * - If an error occurs, returns [MIRACLError] with a [CrossDeviceSessionException]
     * describing issues with the operation.
     * @suppress
     */
    @JvmSynthetic
    public suspend fun getCrossDeviceSessionFromQRCode(
        qrCode: String,
    ): MIRACLResult<CrossDeviceSession, CrossDeviceSessionException> {
        return withContext(miraclTrustCoroutineContext) {
            crossDeviceSessionManager.getCrossDeviceSessionFromQRCode(qrCode)
                .logIfError(LoggerConstants.CROSS_DEVICE_SESSION_MANAGER_TAG)
        }
    }

    /**
     * Get [CrossDeviceSession] for a QR code.
     *
     * @param qrCode a string read from the QR code.
     * @param resultHandler a callback to handle the result of getting details for the session.
     * - If successful, the result is [MIRACLSuccess] with the [CrossDeviceSession].
     * - If an error occurs, the result is [MIRACLError] with exception describing issues with the
     * operation.
     * @suppress
     */
    public fun getCrossDeviceSessionFromQRCode(
        qrCode: String,
        resultHandler: ResultHandler<CrossDeviceSession, CrossDeviceSessionException>
    ) {
        miraclTrustScope.launch {
            crossDeviceSessionManager.getCrossDeviceSessionFromQRCode(qrCode).also { result ->
                if (result is MIRACLError) {
                    logError(
                        LoggerConstants.CROSS_DEVICE_SESSION_MANAGER_TAG,
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
     * Get [CrossDeviceSession] from a notification payload.
     *
     * @param payload key-value data provided by the notification.
     *
     * @return a [MIRACLResult] representing the result of the operation:
     * - If successful, returns [MIRACLSuccess] with the [CrossDeviceSession].
     * - If an error occurs, returns [MIRACLError] with a [CrossDeviceSessionException]
     * describing issues with the operation.
     * @suppress
     */
    @JvmSynthetic
    public suspend fun getCrossDeviceSessionFromNotificationPayload(
        payload: Map<String, String>,
    ): MIRACLResult<CrossDeviceSession, CrossDeviceSessionException> {
        return withContext(miraclTrustCoroutineContext) {
            crossDeviceSessionManager.getCrossDeviceSessionFromNotificationPayload(payload)
                .logIfError(LoggerConstants.CROSS_DEVICE_SESSION_MANAGER_TAG)
        }
    }

    /**
     * Get [CrossDeviceSession] from a notification payload.
     *
     * @param payload key-value data provided by the notification.
     * @param resultHandler a callback to handle the result of getting details for the session.
     * - If successful, the result is [MIRACLSuccess] with the [CrossDeviceSession].
     * - If an error occurs, the result is [MIRACLError] with exception describing issues with the
     * operation.
     * @suppress
     */
    public fun getCrossDeviceSessionFromNotificationPayload(
        payload: Map<String, String>,
        resultHandler: ResultHandler<CrossDeviceSession, CrossDeviceSessionException>
    ) {
        miraclTrustScope.launch {
            crossDeviceSessionManager.getCrossDeviceSessionFromNotificationPayload(payload)
                .also { result ->
                    if (result is MIRACLError) {
                        logError(
                            LoggerConstants.CROSS_DEVICE_SESSION_MANAGER_TAG,
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
     * Cancels an ongoing [CrossDeviceSession].
     *
     * @param crossDeviceSession the session to cancel.
     *
     * @return a [MIRACLResult] representing the result of the operation:
     * - If successful, returns [MIRACLSuccess] with [Unit].
     * - If an error occurs, returns [MIRACLError] with a [CrossDeviceSessionException]
     * describing issues with the operation.
     * @suppress
     */
    @JvmSynthetic
    public suspend fun abortCrossDeviceSession(
        crossDeviceSession: CrossDeviceSession,
    ): MIRACLResult<Unit, CrossDeviceSessionException> {
        return withContext(miraclTrustCoroutineContext) {
            crossDeviceSessionManager.abortSession(crossDeviceSession)
                .logIfError(LoggerConstants.CROSS_DEVICE_SESSION_MANAGER_TAG)
        }
    }

    /**
     * Cancel the [CrossDeviceSession].
     *
     * @param crossDeviceSession the session to cancel.
     * @param resultHandler a callback to handle the result of session abort.
     * - If successful, the result is [MIRACLSuccess].
     * - If an error occurs, the result is [MIRACLError] with exception describing issues with the
     * operation.
     * @suppress
     */
    public fun abortCrossDeviceSession(
        crossDeviceSession: CrossDeviceSession,
        resultHandler: ResultHandler<Unit, CrossDeviceSessionException>
    ) {
        miraclTrustScope.launch {
            crossDeviceSessionManager.abortSession(crossDeviceSession).also { result ->
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

    //region Verification
    /**
     * Default method to verify user identity against the MIRACL Trust platform. In the current
     * implementation it is done by sending an email message.
     *
     * @param userId identifier of the user. To verify identity, this should be a valid email address.
     * @param crossDeviceSession the session from which the verification is initiated.
     *
     * @return a [MIRACLResult] representing the result of the verification:
     * - If successful, returns [MIRACLSuccess] with the [VerificationResponse].
     * - If an error occurs, returns [MIRACLError] with a [VerificationException]
     * describing issues with the operation.
     */
    @JvmSynthetic
    public suspend fun sendVerificationEmail(
        userId: String,
        crossDeviceSession: CrossDeviceSession? = null
    ): MIRACLResult<VerificationResponse, VerificationException> {
        return withContext(miraclTrustCoroutineContext) {
            verificator.sendVerificationEmail(
                userId = userId,
                projectId = projectId,
                deviceName = deviceName,
                crossDeviceSession = crossDeviceSession
            )
                .logIfError(LoggerConstants.VERIFICATOR_TAG)
        }
    }

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
     * Default method to verify user identity against the MIRACL Trust platform. In the current
     * implementation it is done by sending an email message.
     *
     * @param userId identifier of the user identity. To verify identity this identifier
     * needs to be valid email address.
     * @param crossDeviceSession the session from which the verification is started.
     * @param resultHandler a callback to handle the result of the verification.
     * - If successful, the result is [MIRACLSuccess] with the [VerificationResponse].
     * - If an error occurs, the result is [MIRACLError] with exception describing issues with the
     * operation.
     * @suppress
     */
    public fun sendVerificationEmail(
        userId: String,
        crossDeviceSession: CrossDeviceSession,
        resultHandler: ResultHandler<VerificationResponse, VerificationException>
    ) {
        miraclTrustScope.launch {
            verificator.sendVerificationEmail(
                userId = userId,
                projectId = projectId,
                deviceName = deviceName,
                crossDeviceSession = crossDeviceSession
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
     * Generates a [QuickCode](https://miracl.com/resources/docs/guides/built-in-user-verification/quickcode/)
     * for a registered user.
     *
     * @param user the user to generate the [QuickCode] for.
     * @param pinProvider a callback called from the SDK, when the user PIN is required.
     *
     * @return a [MIRACLResult] representing the result of the `QuickCode` generation:
     * - If successful, returns [MIRACLSuccess] with the generated [QuickCode].
     * - If an error occurs, returns [MIRACLError] with a [QuickCodeException]
     * describing issues with the operation.
     */
    @JvmSynthetic
    public suspend fun generateQuickCode(
        user: User,
        pinProvider: PinProvider,
    ): MIRACLResult<QuickCode, QuickCodeException> {
        return withContext(miraclTrustCoroutineContext) {
            verificator.generateQuickCode(
                user,
                pinProvider,
                deviceName
            )
                .logIfError(LoggerConstants.VERIFICATOR_TAG)
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
     * Confirms user verification and obtains an activation token that should be used
     * in the registration process.
     *
     * @param verificationUri a verification URI received as part of the verification process.
     *
     * @return a [MIRACLResult] representing the result of the verification:
     * - If successful, returns [MIRACLSuccess] with the [ActivationTokenResponse].
     * - If an error occurs, returns [MIRACLError] with an [ActivationTokenException]
     * describing issues with the operation.
     */
    @JvmSynthetic
    public suspend fun getActivationToken(
        verificationUri: Uri,
    ): MIRACLResult<ActivationTokenResponse, ActivationTokenException> {
        return withContext(miraclTrustCoroutineContext) {
            verificator.getActivationToken(verificationUri)
                .logIfError(LoggerConstants.VERIFICATOR_TAG)
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
     * Confirms user verification and obtains an activation token that should be used
     * in the registration process.
     *
     * @param userId identifier of the user.
     * @param code a verification code received as part of the verification process.
     *
     * @return a [MIRACLResult] representing the result of the verification:
     * - If successful, returns [MIRACLSuccess] with the [ActivationTokenResponse].
     * - If an error occurs, returns [MIRACLError] with an [ActivationTokenException]
     * describing issues with the operation.
     */
    @JvmSynthetic
    public suspend fun getActivationToken(
        userId: String,
        code: String,
    ): MIRACLResult<ActivationTokenResponse, ActivationTokenException> {
        return withContext(miraclTrustCoroutineContext) {
            verificator.getActivationToken(userId, code)
                .logIfError(LoggerConstants.VERIFICATOR_TAG)
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
     * Provides end-user registration. Registers an end-user for a given MIRACL Trust Project
     * to the MIRACL Trust platform.
     *
     * @param userId provides a unique user id (i.e. email).
     * @param activationToken provides an activation token for verification.
     * @param pinProvider a callback called from the SDK, when the identity PIN is required.
     * @param pushNotificationsToken current device push notifications token. This is used
     * when push notifications for authentication are enabled in the platform.
     *
     * @return a [MIRACLResult] representing the result of the registration:
     * - If successful, returns [MIRACLSuccess] with the registered [User].
     * - If an error occurs, returns [MIRACLError] with a [RegistrationException]
     * describing issues with the operation.
     */
    @JvmSynthetic
    public suspend fun register(
        userId: String,
        activationToken: String,
        pinProvider: PinProvider,
        pushNotificationsToken: String? = null
    ): MIRACLResult<User, RegistrationException> {
        return withContext(miraclTrustCoroutineContext) {
            registrator.register(
                userId,
                projectId,
                activationToken,
                pinProvider,
                deviceName,
                pushNotificationsToken
            )
                .logIfError(LoggerConstants.REGISTRATOR_TAG)
        }
    }

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
     * Authenticates a user to the MIRACL Trust platform by generating a
     * [JWT](https://datatracker.ietf.org/doc/html/rfc7519) authentication token.
     *
     * This method can be used to authenticate within your application.
     *
     * After the token is generated, it should be sent to the application server for
     * [verification](https://miracl.com/resources/docs/guides/authentication/jwt-verification/).
     *
     * @param user the user to authenticate.
     * @param pinProvider a callback called from the SDK when the identity PIN is required.
     *
     * @return a [MIRACLResult] representing the result of the authentication:
     * - If successful, returns [MIRACLSuccess] with the JWT token as a [String].
     * - If an error occurs, returns [MIRACLError] with an [AuthenticationException]
     * describing issues with the operation.
     */
    @JvmSynthetic
    public suspend fun authenticate(
        user: User,
        pinProvider: PinProvider
    ): MIRACLResult<String, AuthenticationException> {
        return withContext(miraclTrustCoroutineContext) {
            authenticator.authenticate(
                user = user,
                accessId = null,
                pinProvider = pinProvider,
                scope = arrayOf(AuthenticatorScopes.JWT.value),
                deviceName = deviceName
            ).let { result ->
                when (result) {
                    is MIRACLSuccess -> {
                        val token = result.value.jwt

                        if (token != null) {
                            MIRACLSuccess(token)
                        } else {
                            MIRACLError(AuthenticationException.AuthenticationFail())
                        }
                    }

                    is MIRACLError -> {
                        logError(
                            LoggerConstants.AUTHENTICATOR_TAG,
                            result.value
                        )

                        MIRACLError(result.value)
                    }
                }
            }
        }
    }

    /**
     * Authenticate identity to the MIRACL Trust platform by generating a
     * [JWT](https://datatracker.ietf.org/doc/html/rfc7519) authentication token.
     *
     * Use this method to authenticate within your application.
     *
     * After the JWT authentication token is generated, it needs to be sent to the application
     * server for [verification](https://miracl.com/resources/docs/guides/authentication/jwt-verification/).
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
     * Authenticates identity in the MIRACL Trust platform.
     *
     * Use this method to authenticate another device or application with the usage of
     * [CrossDeviceSession].
     *
     * @param user the user to authenticate.
     * @param crossDeviceSession details for the authentication operation.
     * @param pinProvider a callback called from the SDK when the identity PIN is required.
     *
     * @return a [MIRACLResult] representing the result of the authentication:
     * - If successful, returns [MIRACLSuccess] with [Unit].
     * - If an error occurs, returns [MIRACLError] with an [AuthenticationException]
     * describing issues with the operation.
     * @suppress
     */
    @JvmSynthetic
    public suspend fun authenticate(
        user: User,
        crossDeviceSession: CrossDeviceSession,
        pinProvider: PinProvider
    ): MIRACLResult<Unit, AuthenticationException> {
        return withContext(miraclTrustCoroutineContext) {
            authenticator.authenticateWithCrossDeviceSession(
                user,
                crossDeviceSession,
                pinProvider,
                arrayOf(AuthenticatorScopes.OIDC.value),
                deviceName
            ).let { result ->
                when (result) {
                    is MIRACLSuccess -> {
                        MIRACLSuccess(Unit)
                    }

                    is MIRACLError -> {
                        logError(
                            LoggerConstants.AUTHENTICATOR_TAG,
                            result.value
                        )

                        MIRACLError(result.value)
                    }
                }
            }
        }
    }

    /**
     * Authenticates identity in the MIRACL Trust platform.
     *
     * Use this method to authenticate another device or application with the usage of
     * [CrossDeviceSession].
     *
     * @param user the user to authenticate with.
     * @param crossDeviceSession details for the authentication operation.
     * @param pinProvider a callback called from the SDK, when the identity PIN is required.
     * @param resultHandler a callback to handle the result of the authentication.
     * - If successful, the result is [MIRACLSuccess].
     * - If an error occurs, the result is [MIRACLError] with exception describing issues with the
     * operation.
     * @suppress
     */
    public fun authenticate(
        user: User,
        crossDeviceSession: CrossDeviceSession,
        pinProvider: PinProvider,
        resultHandler: ResultHandler<Unit, AuthenticationException>
    ) {
        miraclTrustScope.launch {
            authenticator.authenticateWithCrossDeviceSession(
                user,
                crossDeviceSession,
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
     * Authenticates identity on the MIRACL Trust platform.
     *
     * Use this method to authenticate another device or application with the usage of
     * AppLink created by MIRACL Trust platform.
     *
     * @param user the user to authenticate.
     * @param appLink a URI provided by the Intent.
     * @param pinProvider a callback called from the SDK when the identity PIN is required.
     *
     * @return a [MIRACLResult] representing the result of the authentication:
     * - If successful, returns [MIRACLSuccess] with [Unit].
     * - If an error occurs, returns [MIRACLError] with an [AuthenticationException]
     * describing issues with the operation.
     */
    @JvmSynthetic
    public suspend fun authenticateWithAppLink(
        user: User,
        appLink: Uri,
        pinProvider: PinProvider,
    ): MIRACLResult<Unit, AuthenticationException> {
        return withContext(miraclTrustCoroutineContext) {
            authenticator.authenticateWithAppLink(
                user,
                appLink,
                pinProvider,
                arrayOf(AuthenticatorScopes.OIDC.value),
                deviceName
            ).let { result ->
                when (result) {
                    is MIRACLSuccess -> {
                        MIRACLSuccess(Unit)
                    }

                    is MIRACLError -> {
                        logError(
                            LoggerConstants.AUTHENTICATOR_TAG,
                            result.value
                        )

                        MIRACLError(result.value)
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
     * Authenticates identity in the MIRACL Trust platform.
     *
     * Use this method to authenticate another device or application with the usage of
     * QR Code presented on MIRACL Trust login page.
     *
     * @param user the user to authenticate.
     * @param qrCode a string read from the QR code.
     * @param pinProvider a callback called from the SDK when the identity PIN is required.
     *
     * @return a [MIRACLResult] representing the result of the authentication:
     * - If successful, returns [MIRACLSuccess] with [Unit].
     * - If an error occurs, returns [MIRACLError] with an [AuthenticationException]
     * describing issues with the operation.
     */
    @JvmSynthetic
    public suspend fun authenticateWithQRCode(
        user: User,
        qrCode: String,
        pinProvider: PinProvider,
    ): MIRACLResult<Unit, AuthenticationException> {
        return withContext(miraclTrustCoroutineContext) {
            authenticator.authenticateWithQRCode(
                user,
                qrCode,
                pinProvider,
                arrayOf(AuthenticatorScopes.OIDC.value),
                deviceName
            ).let { result ->
                when (result) {
                    is MIRACLSuccess -> {
                        MIRACLSuccess(Unit)
                    }

                    is MIRACLError -> {
                        logError(
                            LoggerConstants.AUTHENTICATOR_TAG,
                            result.value
                        )

                        MIRACLError(result.value)
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
     * Authenticates identity in the MIRACL Trust platform.
     *
     * Use this method to authenticate another device or application with the usage of
     * notification sent by MIRACL Trust platform.
     *
     * @param payload key-value data provided by the notification.
     * @param pinProvider a callback called from the SDK when the identity PIN is required.
     *
     * @return a [MIRACLResult] representing the result of the authentication:
     * - If successful, returns [MIRACLSuccess] with [Unit].
     * - If an error occurs, returns [MIRACLError] with an [AuthenticationException]
     * describing issues with the operation.
     */
    @JvmSynthetic
    public suspend fun authenticateWithNotificationPayload(
        payload: Map<String, String>,
        pinProvider: PinProvider,
    ): MIRACLResult<Unit, AuthenticationException> {
        return withContext(miraclTrustCoroutineContext) {
            authenticator.authenticateWithNotificationPayload(
                payload,
                pinProvider,
                arrayOf(AuthenticatorScopes.OIDC.value),
                deviceName
            ).let { result ->
                when (result) {
                    is MIRACLSuccess -> {
                        MIRACLSuccess(Unit)
                    }

                    is MIRACLError -> {
                        logError(
                            LoggerConstants.AUTHENTICATOR_TAG,
                            result.value
                        )

                        MIRACLError(result.value)
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
     * Creates a cryptographic signature of the given document.
     *
     * @param message the hash of the given document.
     * @param user a user to sign with.
     * @param pinProvider a callback called from the SDK when the signing identity PIN is required.
     *
     * @return a [MIRACLResult] representing the result of the signing operation:
     * - If successful, returns [MIRACLSuccess] with the [SigningResult].
     * - If an error occurs, returns [MIRACLError] with a [SigningException]
     * describing issues with the operation.
     */
    @JvmSynthetic
    public suspend fun sign(
        message: ByteArray,
        user: User,
        pinProvider: PinProvider,
    ): MIRACLResult<SigningResult, SigningException> {
        return withContext(miraclTrustCoroutineContext) {
            documentSigner.sign(
                message,
                user,
                pinProvider,
                deviceName
            )
                .logIfError(LoggerConstants.DOCUMENT_SIGNER_TAG)
        }
    }

    /**
     * Create a cryptographic signature of the given document.
     * @param message the hash of the given document.
     * @param user a user to sign with.
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
     * Generates a signature for a hash provided by the [crossDeviceSession] and updates the session.
     *
     * @param crossDeviceSession details for the signing operation.
     * @param user a user to sign with.
     * @param pinProvider a callback called from the SDK when the signing identity PIN is required.
     *
     * @return a [MIRACLResult] representing the result of the signing operation:
     * - If successful, returns [MIRACLSuccess] with [Unit].
     * - If an error occurs, returns [MIRACLError] with a [SigningException]
     * describing issues with the operation.
     * @suppress
     */
    @JvmSynthetic
    public suspend fun sign(
        crossDeviceSession: CrossDeviceSession,
        user: User,
        pinProvider: PinProvider
    ): MIRACLResult<Unit, SigningException> {
        return withContext(miraclTrustCoroutineContext) {
            documentSigner
                .sign(
                    crossDeviceSession = crossDeviceSession,
                    user = user,
                    pinProvider = pinProvider,
                    deviceName = deviceName
                )
                .logIfError(LoggerConstants.DOCUMENT_SIGNER_TAG)
        }
    }

    /**
     * Generates a signature for a hash provided by the [crossDeviceSession] parameter and updates
     * the session.
     *
     * @param crossDeviceSession details for the signing operation.
     * @param user a user to sign with.
     * @param pinProvider a callback called from the SDK, when the signing identity PIN is required.
     * @param resultHandler a callback to handle the result of the signing.
     * - If successful, the result is [MIRACLSuccess].
     * - If an error occurs, the result is [MIRACLError] with exception describing issues with the
     * operation.
     * @suppress
     */
    public fun sign(
        crossDeviceSession: CrossDeviceSession,
        user: User,
        pinProvider: PinProvider,
        resultHandler: ResultHandler<Unit, SigningException>
    ) {
        miraclTrustScope.launch {
            documentSigner
                .sign(
                    crossDeviceSession = crossDeviceSession,
                    user = user,
                    pinProvider = pinProvider,
                    deviceName = deviceName
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

    private fun <T> T.logIfError(tag: String): T {
        if (this is MIRACLError<*, *>) {
            logger?.error(
                tag,
                LoggerConstants.FLOW_ERROR
                    .format(
                        this.value
                    )
            )
        }

        return this
    }
    //endregion
}
