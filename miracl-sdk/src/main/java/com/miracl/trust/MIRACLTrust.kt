package com.miracl.trust

import android.content.Context
import android.net.Uri
import com.miracl.trust.authentication.*
import com.miracl.trust.configuration.*
import com.miracl.trust.delegate.PinProvider
import com.miracl.trust.delegate.ResultHandler
import com.miracl.trust.model.QuickCode
import com.miracl.trust.model.User
import com.miracl.trust.registration.*
import com.miracl.trust.session.*
import com.miracl.trust.signing.*
import com.miracl.trust.storage.UserStorageException
import com.miracl.trust.util.UrlValidator
import com.miracl.trust.util.log.Logger
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
    internal val base: MIRACLTrustCore

    /** Project ID setting for the application in MIRACL Trust platform. */
    public var projectId: String = configuration.projectId
        private set

    private var projectUrl: String = configuration.projectUrl

    //endregion

    //region Initialization
    init {
        MIRACLTrustCore.configure(context, ConfigurationCore(configuration))
        base = MIRACLTrustCore.getInstance()
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
        this.projectUrl = projectUrl
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
        base.getAuthenticationSessionDetailsFromAppLink(appLink, projectUrl, resultHandler)
        // TODO: Add check for project mismatch?
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
        base.getAuthenticationSessionDetailsFromQRCode(qrCode, projectUrl, resultHandler)
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
        base.getAuthenticationSessionDetailsFromNotificationPayload(payload, projectUrl, resultHandler)
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
        base.abortAuthenticationSession(authenticationSessionDetails, projectUrl, resultHandler)
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
        base.getSigningSessionDetailsFromAppLink(appLink, resultHandler)
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
        base.getSigningSessionDetailsFromQRCode(qrCode, resultHandler)
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
        base.abortSigningSession(signingSessionDetails, resultHandler)
    }
    //endregion

    //region CrossDeviceSession management
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
        base.getCrossDeviceSessionFromAppLink(appLink, projectUrl, resultHandler)
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
        base.getCrossDeviceSessionFromQRCode(qrCode, projectUrl, resultHandler)
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
        base.getCrossDeviceSessionFromNotificationPayload(payload, projectUrl, resultHandler)
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
        base.abortCrossDeviceSession(crossDeviceSession, projectUrl, resultHandler)
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
        base.sendVerificationEmail(
            userId = userId,
            projectId = projectId,
            projectUrl = projectUrl,
            resultHandler = resultHandler
        )
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
        base.sendVerificationEmail(
            userId = userId,
            projectId = projectId,
            projectUrl = projectUrl,
            authenticationSessionDetails = authenticationSessionDetails,
            resultHandler = resultHandler
        )
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
        base.sendVerificationEmail(
            userId = userId,
            projectId = projectId,
            projectUrl = projectUrl,
            crossDeviceSession = crossDeviceSession,
            resultHandler = resultHandler
        )
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
        base.generateQuickCode(
            user = user,
            projectUrl = projectUrl,
            pinProvider = pinProvider,
            resultHandler = resultHandler
        )
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
        base.getActivationToken(verificationUri, projectUrl, resultHandler)
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
        base.getActivationToken(
            userId = userId,
            code = code,
            projectUrl = projectUrl,
            resultHandler = resultHandler
        )
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
        base.register(
            userId,
            projectId,
            projectUrl,
            activationToken,
            pinProvider,
            pushNotificationsToken,
            resultHandler
        )
    }

    //endregion

    //region Authentication
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
        base.authenticate(user, projectUrl, pinProvider, resultHandler)
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
        base.authenticate(user, crossDeviceSession, projectUrl, pinProvider, resultHandler)
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
        base.authenticateWithAppLink(user, appLink, projectUrl, pinProvider, resultHandler)
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
        base.authenticateWithQRCode(user, qrCode, projectUrl, pinProvider, resultHandler)
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
        base.authenticateWithNotificationPayload(payload, projectUrl, pinProvider, resultHandler)
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
        base.sign(message, user, projectUrl, pinProvider, resultHandler)
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
        base.sign(message, user, signingSessionDetails, projectUrl, pinProvider, resultHandler)
    }

    /**
     * Generates a signature for a hash provided by the [crossDeviceSession] parameter and updates
     * the session.
     *
     * @param crossDeviceSession details for the signing operation.
     * @param user an user to sign with.
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
        base.sign(crossDeviceSession, user, projectUrl, pinProvider, resultHandler)
    }
    //endregion

    //region Users
    /**
     * Get the registered users.
     * @return a list of users.
     */
    public suspend fun getUsers(): List<User> {
        return base.getUsers()
    }

    /**
     * Get the registered users.
     * @param resultHandler a callback to handle the result of the user retrieval.
     * - If successful, the result is [MIRACLSuccess] with a list of users.
     * - If an error occurs, the result is [MIRACLError] with a [UserStorageException].
     */
    public fun getUsers(resultHandler: ResultHandler<List<User>, UserStorageException>) {
        base.getUsers(resultHandler)
    }

    /**
     * Get a registered user.
     * @param userId Identifier of the user.
     * @return the user or null if there isn't registered user for the project with
     * this userId on the device.
     */
    public suspend fun getUser(userId: String): User? {
        return base.getUser(userId, projectId)
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
        base.getUser(userId, projectId, resultHandler)
    }

    /**
     * Delete a registered user.
     * @param user the user to be deleted.
     */
    public suspend fun delete(user: User) {
        base.delete(user)
    }

    /**
     * Delete a registered user.
     * @param user the user to be deleted.
     * @param resultHandler a callback to handle the result of the user removal.
     * - If successful, the result is [MIRACLSuccess].
     * - If an error occurs, the result is [MIRACLError] with a [UserStorageException].
     */
    public fun delete(user: User, resultHandler: ResultHandler<Unit, UserStorageException>) {
        base.delete(user, resultHandler)
    }
    //endregion
}
