package com.miracl.trust

import android.content.Context
import android.net.Uri
import androidx.annotation.VisibleForTesting
import com.miracl.trust.authentication.*
import com.miracl.trust.authentication.AuthenticatorScopes
import com.miracl.trust.configuration.*
import com.miracl.trust.configuration.factory.ConfigurationFactory
import com.miracl.trust.configuration.factory.DefaultConfigurationFactory
import com.miracl.trust.core.DeviceTagProvider
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
import com.miracl.trust.storage.room.RoomDatabaseModule
import com.miracl.trust.util.UrlValidator
import com.miracl.trust.util.json.KotlinxSerializationJsonUtil
import com.miracl.trust.util.log.LoggerConstants
import com.miracl.trust.util.toUserDto
import com.miracl.trust.util.toUser
import kotlinx.coroutines.*
import kotlin.coroutines.CoroutineContext
import kotlin.jvm.Throws

/**
 * The entry point of the MIRACL Trust SDK. It is configured
 * and establishes a connection with the MIRACL Trust platform during initialisation.
 *
 * This is done through [configure(context,configuration)][configure]. Once initialised,
 * the SDK can be accessed through [getInstance()][getInstance].
 */
public class MIRACLTrust private constructor(
    context: Context,
    projectId: String,
    projectUrl: String,
    configuration: Configuration
) {
    public companion object {
        private const val NOT_INITIALIZED_EXCEPTION = "MIRACLTrust SDK not initialized!"

        @VisibleForTesting
        internal var configurationFactory: ConfigurationFactory = DefaultConfigurationFactory()

        @Volatile
        @VisibleForTesting
        internal var defaultUserStorage: UserStorage? = null

        @Volatile
        @VisibleForTesting
        internal var defaultConfiguration: Configuration? = null

        private lateinit var instance: MIRACLTrust

        @JvmStatic
        public fun getInstance(): MIRACLTrust =
            if (this::instance.isInitialized) {
                instance
            } else {
                throw Exception(NOT_INITIALIZED_EXCEPTION)
            }

        /**
         * Initialise the MIRACL Trust SDK.
         *
         * > **To be used once**. Multiple uses could lead to unidentified behaviour!
         *
         * @param context The application context, used for managing storage.
         * @param configuration The instance of the [Configuration], used to configure the SDK.
         */
        @JvmStatic
        public fun configure(context: Context, configuration: Configuration) {
            val projectId = requireNotNull(configuration.projectId) {
                "MIRACLTrust SDK: Project ID is missing. Pass a valid Project ID to Configuration.Builder."
            }

            configuration.userStorage?.loadStorage()
            instance = MIRACLTrust(
                projectId = projectId,
                projectUrl = configuration.projectUrl,
                context = context,
                configuration = configuration
            )
        }

        //region Authenticator API
        /**
         * This is an experimental API.
         * @suppress
         */
        @MIRACLTrustAuthenticatorApi
        public fun setDefaultConfiguration(configuration: Configuration) {
            configuration.userStorage?.loadStorage()
            this.defaultConfiguration = configuration
        }

        /**
         * This is an experimental API.
         * @suppress
         */
        @MIRACLTrustAuthenticatorApi
        public fun createInstance(
            context: Context,
            projectId: String,
            projectUrl: String
        ): MIRACLTrust {
            require(projectId.isNotEmpty()) {
                "MIRACLTrust SDK: Project ID cannot be empty. Pass a valid Project ID when calling createInstance()."
            }

            require(UrlValidator.isValid(projectUrl)) {
                "MIRACLTrust SDK: Project URL is invalid. Pass a valid URL when calling createInstance()."
            }

            val configuration = defaultConfiguration ?: configurationFactory.create()

            return MIRACLTrust(context, projectId, projectUrl, configuration)
        }

        /**
         * This is an experimental API.
         * @suppress
         */
        @MIRACLTrustAuthenticatorApi
        public suspend fun getUsers(context: Context): List<User> {
            val userStorage =
                defaultConfiguration?.userStorage ?: defaultUserStorage ?: synchronized(this) {
                    val userStorage = defaultConfiguration?.userStorage ?: defaultUserStorage

                    userStorage ?: RoomDatabaseModule(context, "").userStorage().also {
                        it.loadStorage()
                        defaultUserStorage = it
                    }
                }

            return withContext(Dispatchers.IO) {
                try {
                    userStorage.all().map { it.toUser() }
                } catch (ex: Exception) {
                    throw UserStorageException(ex)
                }
            }
        }
        //endregion
    }

    //region Properties
    private val logger = configuration.logger
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

    @VisibleForTesting
    internal val deviceName: String = configuration.deviceName

    /** Project ID setting for the application in the MIRACL Trust platform. */
    public var projectId: String = projectId
        private set

    //endregion

    //region Initialization
    init {
        val apiRequestExecutor = ApiRequestExecutor(
            configuration.httpRequestExecutor,
            KotlinxSerializationJsonUtil,
            configuration.applicationInfo
        )

        var componentFactory = configuration.componentFactory
        if (componentFactory == null) {
            val deviceTagProvider = DeviceTagProvider.create(context)
            componentFactory = ComponentFactory(context, logger, deviceTagProvider)
        }

        apiSettings = ApiSettings(projectUrl)

        miraclTrustCoroutineContext = configuration.miraclCoroutineContext
        miraclTrustScope = CoroutineScope(SupervisorJob() + configuration.miraclCoroutineContext)

        userStorage = configuration.userStorage ?: defaultUserStorage ?: synchronized(this) {
            defaultUserStorage ?: componentFactory.defaultUserStorage(projectId).also {
                it.loadStorage()
                defaultUserStorage = it
            }
        }

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
     * Configures a new Project ID when the SDK has to work with a different project.
     *
     * @param projectId The `Project ID` setting for the MIRACL Trust platform that must be updated.
     */
    @Throws(ConfigurationException::class)
    public fun setProjectId(projectId: String) {
        if (projectId.isBlank()) {
            throw ConfigurationException.EmptyProjectId
        }

        this.projectId = projectId
    }

    /**
     * Configures new project settings when the SDK has to work with a different project.
     *
     * @param projectId The unique identifier of the MIRACL Trust project.
     * @param projectUrl The MIRACL Trust Project URL that is used for communication with the MIRACL Trust API.
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
     * Gets `authentication` session details for a project in the MIRACL Trust platform based on the authentication session identifier.
     *
     * Use this method to get session details for an application that tries to authenticate
     * against the MIRACL Trust platform using an AppLink.
     *
     * @param appLink The URI provided by the Intent.
     * @param resultHandler A callback to handle the result of retrieving session details.
     * - If successful, the result is a [MIRACLSuccess] with the [AuthenticationSessionDetails].
     * - If an error occurs, the result is a [MIRACLError] with an exception describing issues with the
     * operation.
     */
    @Deprecated(
        message = "Use getCrossDeviceSessionFromAppLink(appLink, resultHandler) instead.",
        replaceWith = ReplaceWith("getCrossDeviceSessionFromAppLink(appLink, resultHandler)"),
        level = DeprecationLevel.WARNING
    )
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
     * Gets `authentication` session details for a project in the MIRACL Trust platform based on the authentication session identifier.
     *
     * Use this method to get session details for an application that tries to authenticate
     * against the MIRACL Trust platform using a QR Code.
     *
     * @param qrCode A string read from the QR code.
     * @param resultHandler A callback to handle the result of retrieving session details.
     * - If successful, the result is a [MIRACLSuccess] with the [AuthenticationSessionDetails].
     * - If an error occurs, the result is a [MIRACLError] with an exception describing issues with the
     * operation.
     */
    @Deprecated(
        message = "Use getCrossDeviceSessionFromQRCode(qrCode, resultHandler) instead.",
        replaceWith = ReplaceWith("getCrossDeviceSessionFromQRCode(qrCode, resultHandler)"),
        level = DeprecationLevel.WARNING
    )
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
     * Gets `authentication` session details for a project in the MIRACL Trust platform based on the authentication session identifier.
     *
     * Use this method to get session details for an application that tries to authenticate
     * against the MIRACL Trust platform using a notification.
     *
     * @param payload The key-value data provided by the notification.
     * @param resultHandler A callback to handle the result of retrieving session details.
     * - If successful, the result is a [MIRACLSuccess] with the [AuthenticationSessionDetails].
     * - If an error occurs, the result is a [MIRACLError] with an exception describing issues with the
     * operation.
     */
    @Deprecated(
        message = "Use getCrossDeviceSessionFromNotificationPayload(payload, resultHandler) instead.",
        replaceWith = ReplaceWith("getCrossDeviceSessionFromNotificationPayload(payload, resultHandler)"),
        level = DeprecationLevel.WARNING
    )
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
     * Cancels the authentication session.
     *
     * @param authenticationSessionDetails The details for the authentication session.
     * @param resultHandler A callback to handle the result of the session abort.
     * - If successful, the result is a [MIRACLSuccess].
     * - If an error occurs, the result is a [MIRACLError] with an exception describing issues with the
     * operation.
     */
    @Deprecated("Use abortCrossDeviceSession(crossDeviceSession, resultHandler) instead.")
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
     * Gets the [CrossDeviceSession] for an AppLink.
     *
     * @param appLink The URI provided by the Intent.
     *
     * @return A [MIRACLResult] representing the result of the operation:
     * - If successful, returns a [MIRACLSuccess] with the [CrossDeviceSession].
     * - If an error occurs, returns a [MIRACLError] with a [CrossDeviceSessionException]
     * describing issues with the operation.
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
     * Gets the [CrossDeviceSession] for an AppLink.
     *
     * @param appLink The URI provided by the Intent.
     * @param resultHandler A callback to handle the result of retrieving session details.
     * - If successful, the result is a [MIRACLSuccess] with the [CrossDeviceSession].
     * - If an error occurs, the result is a [MIRACLError] with an exception describing issues with the
     * operation.
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
     * Gets the [CrossDeviceSession] for a QR code.
     *
     * @param qrCode A string read from the QR code.
     *
     * @return A [MIRACLResult] representing the result of the operation:
     * - If successful, returns a [MIRACLSuccess] with the [CrossDeviceSession].
     * - If an error occurs, returns a [MIRACLError] with a [CrossDeviceSessionException]
     * describing issues with the operation.
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
     * Gets the [CrossDeviceSession] for a QR code.
     *
     * @param qrCode A string read from the QR code.
     * @param resultHandler A callback to handle the result of retrieving session details.
     * - If successful, the result is a [MIRACLSuccess] with the [CrossDeviceSession].
     * - If an error occurs, the result is a [MIRACLError] with an exception describing issues with the
     * operation.
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
     * Gets the [CrossDeviceSession] from a notification payload.
     *
     * @param payload The key-value data provided by the notification.
     *
     * @return A [MIRACLResult] representing the result of the operation:
     * - If successful, returns a [MIRACLSuccess] with the [CrossDeviceSession].
     * - If an error occurs, returns a [MIRACLError] with a [CrossDeviceSessionException]
     * describing issues with the operation.
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
     * Gets the [CrossDeviceSession] from a notification payload.
     *
     * @param payload The key-value data provided by the notification.
     * @param resultHandler A callback to handle the result of retrieving session details.
     * - If successful, the result is a [MIRACLSuccess] with the [CrossDeviceSession].
     * - If an error occurs, the result is a [MIRACLError] with an exception describing issues with the
     * operation.
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
     * @param crossDeviceSession The session to cancel.
     *
     * @return A [MIRACLResult] representing the result of the operation:
     * - If successful, returns a [MIRACLSuccess] with [Unit].
     * - If an error occurs, returns a [MIRACLError] with a [CrossDeviceSessionException]
     * describing issues with the operation.
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
     * Cancels the [CrossDeviceSession].
     *
     * @param crossDeviceSession The session to cancel.
     * @param resultHandler A callback to handle the result of session abort.
     * - If successful, the result is a [MIRACLSuccess].
     * - If an error occurs, the result is a [MIRACLError] with an exception describing issues with the
     * operation.
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
     * Default method for verifying user identity against the MIRACL Trust platform. In the current
     * implementation, verification is done by sending an email message.
     *
     * @param userId The identifier of the user. Must be a valid email address.
     *
     * @return A [MIRACLResult] representing the result of the verification:
     * - If successful, returns a [MIRACLSuccess] with the [VerificationResponse].
     * - If an error occurs, returns a [MIRACLError] with a [VerificationException]
     * describing issues with the operation.
     */
    @JvmSynthetic
    public suspend fun sendVerificationEmail(
        userId: String
    ): MIRACLResult<VerificationResponse, VerificationException> {
        return withContext(miraclTrustCoroutineContext) {
            verificator.sendVerificationEmail(
                userId = userId,
                projectId = projectId,
                deviceName = deviceName
            )
                .logIfError(LoggerConstants.VERIFICATOR_TAG)
        }
    }

    /**
     * Default method for verifying user identity against the MIRACL Trust platform. In the current
     * implementation, verification is done by sending an email message.
     *
     * @param userId The identifier of the user. Must be a valid email address.
     * @param crossDeviceSession The session from which the verification is initiated.
     *
     * @return A [MIRACLResult] representing the result of the verification:
     * - If successful, returns a [MIRACLSuccess] with the [VerificationResponse].
     * - If an error occurs, returns a [MIRACLError] with a [VerificationException]
     * describing issues with the operation.
     */
    @JvmSynthetic
    public suspend fun sendVerificationEmail(
        userId: String,
        crossDeviceSession: CrossDeviceSession
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
     * Default method for verifying user identity against the MIRACL Trust platform. In the current
     * implementation, verification is done by sending an email message.
     *
     * @param userId The identifier of the user. Must be a valid email address.
     * @param resultHandler A callback to handle the result of the verification.
     * - If successful, the result is a [MIRACLSuccess] with the [VerificationResponse].
     * - If an error occurs, the result is a [MIRACLError] with an exception describing issues with the
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
     * Default method for verifying user identity against the MIRACL Trust platform. In the current
     * implementation, verification is done by sending an email message.
     *
     * @param userId The identifier of the user. Must be a valid email address.
     * @param authenticationSessionDetails The details for the authentication session.
     * @param resultHandler A callback to handle the result of the verification.
     * - If successful, the result is a [MIRACLSuccess] with the [VerificationResponse].
     * - If an error occurs, the result is a [MIRACLError] with an exception describing issues with the
     * operation.
     */
    @Deprecated("Use sendVerificationEmail(userId, crossDeviceSession, resultHandler) instead.")
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
     * Default method for verifying the user identity against the MIRACL Trust platform. In the current
     * implementation, verification is done by sending an email message.
     *
     * @param userId The identifier of the user. Must be a valid email address.
     * @param crossDeviceSession The session initiating the verification.
     * @param resultHandler A callback to handle the result of the verification.
     * - If successful, the result is a [MIRACLSuccess] with the [VerificationResponse].
     * - If an error occurs, the result is a [MIRACLError] with an exception describing issues with the
     * operation.
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
     * @param user The user for whom the [QuickCode] is generated.
     * @param pinProvider A callback called by the SDK when the PIN is requested.
     *
     * @return A [MIRACLResult] representing the result of the `QuickCode` generation:
     * - If successful, returns a [MIRACLSuccess] with the generated [QuickCode].
     * - If an error occurs, returns a [MIRACLError] with a [QuickCodeException]
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
     * Generates a [QuickCode](https://miracl.com/resources/docs/guides/built-in-user-verification/quickcode/)
     * for a registered user.
     * @param user The user for whom the [QuickCode] is generated.
     * @param pinProvider A callback called by the SDK when the PIN is requested.
     * @param resultHandler A callback to handle the result of the `QuickCode` generation.
     * - If successful, the result is a [MIRACLSuccess] with the [QuickCode].
     * - If an error occurs, the result is a [MIRACLError] with an exception describing issues with the
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
     * Confirms user verification and obtains an activation token that is used
     * in the registration process.
     *
     * @param verificationUri The verification URI received as part of the verification process.
     *
     * @return A [MIRACLResult] representing the result of the verification:
     * - If successful, returns a [MIRACLSuccess] with the [ActivationTokenResponse].
     * - If an error occurs, returns a [MIRACLError] with an [ActivationTokenException]
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
     * Confirms user verification and obtains an activation token that is used
     * in the registration process.
     *
     * @param verificationUri The verification URI received as part of the verification process.
     * @param resultHandler A callback to handle the result of the verification.
     * - If successful, the result is a [MIRACLSuccess] with the [ActivationTokenResponse].
     * - If an error occurs, the result is a [MIRACLError] with an exception describing issues with the
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
     * Confirms user verification and obtains an activation token that is used
     * in the registration process.
     *
     * @param userId The identifier of the user. Must be a valid email address.
     * @param code The verification code received as part of the verification process.
     *
     * @return A [MIRACLResult] representing the result of the verification:
     * - If successful, returns a [MIRACLSuccess] with the [ActivationTokenResponse].
     * - If an error occurs, returns a [MIRACLError] with an [ActivationTokenException]
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
     * Confirms user verification and obtains an activation token that is used
     * in the registration process.
     *
     * @param userId The identifier of the user. Must be a valid email address.
     * @param code The verification code sent to the user's email address.
     * @param resultHandler A callback to handle the result of the verification.
     * - If successful, the result is a [MIRACLSuccess] with the [ActivationTokenResponse].
     * - If an error occurs, the result is a [MIRACLError] with an exception describing issues with the
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
     * Provides end-user registration. Registers an end user for a given MIRACL Trust Project
     * to the MIRACL Trust platform.
     *
     * @param userId The identifier of the user.
     * @param activationToken Provides an activation token for verification.
     * @param pinProvider A callback called by the SDK when the PIN is requested.
     * @param pushNotificationsToken The current device's push notifications token. This is used
     * when push notifications for authentication are enabled in the platform.
     *
     * @return A [MIRACLResult] representing the result of the registration:
     * - If successful, returns a [MIRACLSuccess] with the registered [User].
     * - If an error occurs, returns a [MIRACLError] with a [RegistrationException]
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
     * Provides end-user registration. Registers an end user for a given MIRACL Trust project
     * on the MIRACL Trust platform.
     *
     * @param userId The identifier of the user.
     * @param activationToken Provides an activation token for verification.
     * @param pinProvider A callback called by the SDK when the PIN is requested.
     * @param pushNotificationsToken The current device's push notifications token. This is used
     * when push notifications for authentication are enabled in the platform.
     * @param resultHandler A callback to handle the result of the registration.
     * - If successful, the result is a [MIRACLSuccess] with the value of the registered user.
     * - If an error occurs, the result is a [MIRACLError] with an exception describing issues with the
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
     * Authenticates an end user to the MIRACL Trust platform by generating a
     * [JWT](https://datatracker.ietf.org/doc/html/rfc7519) authentication token.
     *
     * Use this method to authenticate within your application.
     *
     * After the token is generated, it must be sent to the application server for
     * [verification](https://miracl.com/resources/docs/guides/authentication/jwt-verification/).
     *
     * @param user The user to authenticate.
     * @param pinProvider A callback called by the SDK when the PIN is requested.
     *
     * @return A [MIRACLResult] representing the result of the authentication:
     * - If successful, returns a [MIRACLSuccess] with the JWT token as a [String].
     * - If an error occurs, returns a [MIRACLError] with an [AuthenticationException]
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
     * Authenticates an end user to the MIRACL Trust platform by generating a
     * [JWT](https://datatracker.ietf.org/doc/html/rfc7519) authentication token.
     *
     * Use this method to authenticate within your application.
     *
     * After the JWT authentication token is generated, it must be sent to the application
     * server for [verification](https://miracl.com/resources/docs/guides/authentication/jwt-verification/).
     *
     * @param user The user to authenticate.
     * @param pinProvider A callback called by the SDK when the PIN is requested.
     * @param resultHandler A callback to handle the result of the authentication.
     * - If successful, the result is a [MIRACLSuccess].
     * - If an error occurs, the result is a [MIRACLError] with an exception describing issues with the
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
     * Authenticates an end user on the MIRACL Trust platform.
     *
     * Use this method to authenticate another device or application using [CrossDeviceSession].
     *
     * @param user The user to authenticate.
     * @param crossDeviceSession The details for the authentication operation.
     * @param pinProvider A callback called by the SDK when the PIN is requested.
     *
     * @return A [MIRACLResult] representing the result of the authentication:
     * - If successful, returns a [MIRACLSuccess] with [Unit].
     * - If an error occurs, returns a [MIRACLError] with an [AuthenticationException]
     * describing issues with the operation.
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
     * Authenticates an end user on the MIRACL Trust platform.
     *
     * Use this method to authenticate another device or application using [CrossDeviceSession].
     *
     * @param user The user to authenticate with.
     * @param crossDeviceSession The details for the authentication operation.
     * @param pinProvider A callback called by the SDK when the PIN is requested.
     * @param resultHandler A callback to handle the result of the authentication.
     * - If successful, the result is a [MIRACLSuccess].
     * - If an error occurs, the result is a [MIRACLError] with an exception describing issues with the
     * operation.
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
     * Authenticates an end user on the MIRACL Trust platform.
     *
     * Use this method to authenticate another device or application using
     * an AppLink created by the MIRACL Trust platform.
     *
     * @param user The user to authenticate.
     * @param appLink The URI provided by the Intent.
     * @param pinProvider A callback called by the SDK when the PIN is requested.
     *
     * @return A [MIRACLResult] representing the result of the authentication:
     * - If successful, returns a [MIRACLSuccess] with [Unit].
     * - If an error occurs, returns a [MIRACLError] with an [AuthenticationException]
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
     * Authenticates an end user on the MIRACL Trust platform.
     *
     * Use this method to authenticate another device or application using
     * an AppLink created by the MIRACL Trust platform.
     *
     * @param user The user to authenticate.
     * @param appLink The URI provided by the Intent.
     * @param pinProvider A callback called by the SDK when the PIN is requested.
     * @param resultHandler A callback to handle the result of the authentication.
     * - If successful, the result is a [MIRACLSuccess].
     * - If an error occurs, the result is a [MIRACLError] with an exception describing issues with the
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
     * Authenticates an end user on the MIRACL Trust platform.
     *
     * Use this method to authenticate another device or application using
     * a QR Code displayed on the MIRACL Trust login page.
     *
     * @param user The user to authenticate.
     * @param qrCode A string read from the QR code.
     * @param pinProvider A callback called by the SDK when the PIN is requested.
     *
     * @return A [MIRACLResult] representing the result of the authentication:
     * - If successful, returns a [MIRACLSuccess] with [Unit].
     * - If an error occurs, returns a [MIRACLError] with an [AuthenticationException]
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
     * Authenticates an end user on the MIRACL Trust platform.
     *
     * Use this method to authenticate another device or application using
     * a QR Code displayed on the MIRACL Trust login page.
     *
     * @param user The user to authenticate.
     * @param qrCode A string read from the QR code.
     * @param pinProvider A callback called by the SDK when the PIN is requested.
     * @param resultHandler A callback to handle the result of the authentication.
     * - If successful, the result is a [MIRACLSuccess].
     * - If an error occurs, the result is a [MIRACLError] with an exception describing issues with the
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
     * Authenticates an end user on the MIRACL Trust platform.
     *
     * Use this method to authenticate another device or application using
     * a notification sent by the MIRACL Trust platform.
     *
     * @param payload The key-value data provided by the notification.
     * @param pinProvider A callback called by the SDK when the PIN is requested.
     *
     * @return A [MIRACLResult] representing the result of the authentication:
     * - If successful, returns a [MIRACLSuccess] with [Unit].
     * - If an error occurs, returns a [MIRACLError] with an [AuthenticationException]
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
     * Authenticates an end user on the MIRACL Trust platform.
     *
     * Use this method to authenticate another device or application using
     * a notification sent by the MIRACL Trust platform.
     *
     * @param payload The key-value data provided by the notification.
     * @param pinProvider A callback called by the SDK when the PIN is requested.
     * @param resultHandler A callback to handle the result of the authentication.
     * - If successful, the result is a [MIRACLSuccess].
     * - If an error occurs, the result is a [MIRACLError] with an exception describing issues with the
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
     * @param message The hash of the given document.
     * @param user A user to sign with.
     * @param pinProvider A callback called by the SDK when the PIN is requested.
     *
     * @return A [MIRACLResult] representing the result of the signing operation:
     * - If successful, returns a [MIRACLSuccess] with the [SigningResult].
     * - If an error occurs, returns a [MIRACLError] with a [SigningException]
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
     * Creates a cryptographic signature of the given document.
     * @param message The hash of the given document.
     * @param user A user to sign with.
     * @param pinProvider A callback called by the SDK when the PIN is requested.
     * @param resultHandler A callback to handle the result of the signing.
     * - If successful, the result is a [MIRACLSuccess].
     * - If an error occurs, the result is a [MIRACLError] with an exception describing issues with the
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
     * @param crossDeviceSession The details for the signing operation.
     * @param user A user to sign with.
     * @param pinProvider A callback called by the SDK when the PIN is requested.
     *
     * @return A [MIRACLResult] representing the result of the signing operation:
     * - If successful, returns a [MIRACLSuccess] with [Unit].
     * - If an error occurs, returns a [MIRACLError] with a [SigningException]
     * describing issues with the operation.
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
     * @param crossDeviceSession The details for the signing operation.
     * @param user A user to sign with.
     * @param pinProvider A callback called by the SDK when the PIN is requested.
     * @param resultHandler A callback to handle the result of the signing.
     * - If successful, the result is a [MIRACLSuccess].
     * - If an error occurs, the result is a [MIRACLError] with an exception describing issues with the
     * operation.
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
     * Gets the registered users.
     * @return A list of users.
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
     * Gets the registered users.
     * @param resultHandler A callback to handle the result of the user retrieval.
     * - If successful, the result is a [MIRACLSuccess] with a list of users.
     * - If an error occurs, the result is a [MIRACLError] with a [UserStorageException].
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
     * Gets a registered user.
     * @param userId The identifier of the user.
     * @return The user or null if there is no registered user with
     * this userId for the project on the device.
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
     * Gets a registered user.
     * @param userId The identifier of the user.
     * @param resultHandler A callback to handle the result of the user retrieval.
     * - If successful, the result is a [MIRACLSuccess] with the  value of the user or null if
     *   there is no registered user with this userId for the project on the device.
     * - If an error occurs, the result is a [MIRACLError] with a [UserStorageException].
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
     * Deletes a registered user.
     * @param user The user to be deleted.
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
     * Deletes a registered user.
     * @param user The user to be deleted.
     * @param resultHandler A callback to handle the result of the user removal.
     * - If successful, the result is a [MIRACLSuccess].
     * - If an error occurs, the result is a [MIRACLError] with a [UserStorageException].
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
        logger.error(
            tag,
            LoggerConstants.FLOW_ERROR
                .format(
                    exception
                )
        )
    }

    private fun <T> T.logIfError(tag: String): T {
        if (this is MIRACLError<*, *>) {
            logger.error(
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
