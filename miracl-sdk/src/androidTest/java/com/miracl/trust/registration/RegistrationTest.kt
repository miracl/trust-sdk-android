package com.miracl.trust.registration

import android.content.Context
import android.net.Uri
import android.os.Build
import androidx.room.Room
import androidx.test.core.app.ApplicationProvider
import androidx.test.platform.app.InstrumentationRegistry
import com.miracl.trust.BuildConfig
import com.miracl.trust.MIRACLError
import com.miracl.trust.MIRACLSuccess
import com.miracl.trust.authentication.AuthenticationApiManager
import com.miracl.trust.authentication.Authenticator
import com.miracl.trust.authentication.AuthenticatorScopes
import com.miracl.trust.crypto.Crypto
import com.miracl.trust.delegate.PinProvider
import com.miracl.trust.model.User
import com.miracl.trust.network.ApiRequestExecutor
import com.miracl.trust.network.ApiSettings
import com.miracl.trust.network.HttpsURLConnectionRequestExecutor
import com.miracl.trust.session.SessionApiManager
import com.miracl.trust.storage.UserStorage
import com.miracl.trust.storage.room.RoomUserStorage
import com.miracl.trust.storage.room.UserDatabase
import com.miracl.trust.util.json.KotlinxSerializationJsonUtil
import com.miracl.trust.utilities.*
import kotlinx.coroutines.runBlocking
import org.junit.Assert
import org.junit.Before
import org.junit.Test
import java.net.URL

class RegistrationTest {
    companion object {
        private const val WRONG_FORMAT_PIN = "FAIL"
    }

    private val projectId = BuildConfig.CUV_PROJECT_ID
    private val clientId = BuildConfig.CUV_CLIENT_ID
    private val clientSecret = BuildConfig.CUV_CLIENT_SECRET

    private val dvProjectId = BuildConfig.DV_PROJECT_ID

    private lateinit var verificator: Verificator
    private lateinit var registrator: Registrator
    private lateinit var authenticator: Authenticator
    private lateinit var userStorage: UserStorage

    @Before
    fun setUp() = runBlocking {
        val httpRequestExecutor = HttpsURLConnectionRequestExecutor(10, 10)
        val apiRequestExecutor =
            ApiRequestExecutor(httpRequestExecutor, KotlinxSerializationJsonUtil)
        val apiSettings = ApiSettings(BuildConfig.BASE_URL)

        val verificationApi =
            VerificationApiManager(KotlinxSerializationJsonUtil, apiRequestExecutor, apiSettings)

        val registrationApi = RegistrationApiManager(
            apiRequestExecutor = apiRequestExecutor,
            jsonUtil = KotlinxSerializationJsonUtil,
            apiSettings = apiSettings
        )

        val crypto = Crypto()

        val context = ApplicationProvider.getApplicationContext<Context>()
        val userDatabase = Room.inMemoryDatabaseBuilder(context, UserDatabase::class.java).build()
        userStorage = RoomUserStorage(userDatabase)

        registrator = Registrator(registrationApi, crypto, userStorage)

        val sessionApi =
            SessionApiManager(apiRequestExecutor, KotlinxSerializationJsonUtil, apiSettings)
        val authenticationApi =
            AuthenticationApiManager(apiRequestExecutor, KotlinxSerializationJsonUtil, apiSettings)
        authenticator =
            Authenticator(authenticationApi, sessionApi, crypto, registrator, userStorage)

        verificator = Verificator(authenticator, verificationApi, userStorage)
    }

    @Test
    fun testSuccessfulRegistration() = runBlocking {
        val activationToken = MIRACLService.obtainActivationToken(clientId, clientSecret, USER_ID)
        val result = register(activationToken)

        Assert.assertTrue(result is MIRACLSuccess)
        Assert.assertEquals(USER_ID, (result as MIRACLSuccess).value.userId)
    }

    @Test
    fun testSuccessfulRegistrationDefaultVerification() = runBlocking {
        // Send verification email
        val timestamp = getUnixTime()
        val sendEmailResult =
            verificator.sendVerificationEmail(USER_ID, dvProjectId, Build.MODEL, null)
        Assert.assertTrue(sendEmailResult is MIRACLSuccess)

        // Fetch the verification URL from the email
        val context = InstrumentationRegistry.getInstrumentation().context
        val verificationUrl = GmailService.getVerificationUrl(context, USER_ID, USER_ID, timestamp)
        Assert.assertNotNull(verificationUrl)

        // Get activation token
        val activationTokenResult = verificator.getActivationToken(Uri.parse(verificationUrl))
        Assert.assertTrue(activationTokenResult is MIRACLSuccess)

        // Register
        val activationToken = (activationTokenResult as MIRACLSuccess).value.activationToken
        val result = register(activationToken = activationToken, projectId = dvProjectId)

        Assert.assertTrue(result is MIRACLSuccess)
        Assert.assertEquals(USER_ID, (result as MIRACLSuccess).value.userId)
        Assert.assertEquals(dvProjectId, result.value.projectId)
    }

    @Test
    fun testSuccessfulRegistrationCustomVerification() = runBlocking {
        // Get verification URL
        val verificationUrl = MIRACLService.getVerificationUrl(clientId, clientSecret, USER_ID)
        Assert.assertNotNull(verificationUrl)

        // Get activation token
        val activationTokenResult = verificator.getActivationToken(Uri.parse(verificationUrl))
        Assert.assertTrue(activationTokenResult is MIRACLSuccess)

        // Register
        val activationToken = (activationTokenResult as MIRACLSuccess).value.activationToken
        val result = register(activationToken)

        Assert.assertTrue(result is MIRACLSuccess)
        Assert.assertEquals(USER_ID, (result as MIRACLSuccess).value.userId)
        Assert.assertEquals(projectId, result.value.projectId)
    }

    @Test
    fun testSuccessfulRegistrationWithQuickCode() = runBlocking {
        // Register with CUV
        val pin = randomNumericPin()
        val pinProvider = PinProvider { pinConsumer -> pinConsumer.consume(pin) }
        var activationToken = MIRACLService.obtainActivationToken(clientId, clientSecret, USER_ID)
        var result = register(activationToken = activationToken, pinProvider = pinProvider)
        Assert.assertTrue(result is MIRACLSuccess)

        // Generate QuickCode
        val generateQuickCodeResult = verificator.generateQuickCode(
            user = (result as MIRACLSuccess).value,
            pinProvider = pinProvider,
            deviceName = Build.MODEL
        )
        Assert.assertTrue(generateQuickCodeResult is MIRACLSuccess)

        // Get activation token
        val activationTokenResult = verificator.getActivationToken(
            userId = USER_ID,
            code = (generateQuickCodeResult as MIRACLSuccess).value.code
        )
        Assert.assertTrue(activationTokenResult is MIRACLSuccess)

        // Register
        activationToken = (activationTokenResult as MIRACLSuccess).value.activationToken
        result = register(activationToken)

        Assert.assertTrue(result is MIRACLSuccess)
        Assert.assertEquals(USER_ID, (result as MIRACLSuccess).value.userId)
        Assert.assertEquals(projectId, result.value.projectId)
    }

    @Test
    fun testRegistrationOverride() = runBlocking {
        // Registration
        var activationToken = MIRACLService.obtainActivationToken(clientId, clientSecret, USER_ID)
        var result = register(activationToken)
        Assert.assertTrue(result is MIRACLSuccess)
        Assert.assertEquals(USER_ID, (result as MIRACLSuccess).value.userId)

        // Override registration
        val pin = randomNumericPin()
        val pinProvider = PinProvider { pinConsumer -> pinConsumer.consume(pin) }
        activationToken = MIRACLService.obtainActivationToken(clientId, clientSecret, USER_ID)
        result = register(activationToken = activationToken, pinProvider = pinProvider)
        Assert.assertTrue(result is MIRACLSuccess)
        val user = (result as MIRACLSuccess).value
        Assert.assertEquals(USER_ID, user.userId)

        // Authentication
        val accessId = URL(MIRACLService.obtainAccessId().qrURL).ref
        val authenticationResult = authenticator.authenticate(
            user = user,
            accessId = accessId,
            pinProvider = pinProvider,
            scope = arrayOf(
                AuthenticatorScopes.JWT.value
            ),
            deviceName = Build.MODEL
        )
        Assert.assertTrue(authenticationResult is MIRACLSuccess)
    }

    @Test
    fun testRegistrationOverrideForRevokedUser() = runBlocking {
        // Registration
        var activationToken = MIRACLService.obtainActivationToken(clientId, clientSecret, USER_ID)
        val pin = randomNumericPin()
        val pinProvider = PinProvider { pinConsumer -> pinConsumer.consume(pin) }
        var result = register(activationToken = activationToken, pinProvider = pinProvider)

        Assert.assertTrue(result is MIRACLSuccess)
        var user = (result as MIRACLSuccess).value
        Assert.assertEquals(USER_ID, user.userId)

        // User revocation
        var accessId = URL(MIRACLService.obtainAccessId().qrURL).ref
        val wrongPin = generateWrongPin(pin)
        val wrongPinProvider = PinProvider { pinConsumer -> pinConsumer.consume(wrongPin) }

        var authenticationResult = authenticate(user, accessId, wrongPinProvider)
        Assert.assertTrue(authenticationResult is MIRACLError)

        authenticationResult = authenticate(user, accessId, wrongPinProvider)
        Assert.assertTrue(authenticationResult is MIRACLError)

        authenticationResult = authenticate(user, accessId, wrongPinProvider)
        Assert.assertTrue(authenticationResult is MIRACLError)

        user = userStorage.getUser(user.userId, user.projectId)!!
        Assert.assertTrue(user.revoked)

        // Override registration
        val newPin = randomNumericPin()
        val newPinProvider = PinProvider { pinConsumer -> pinConsumer.consume(newPin) }
        activationToken = MIRACLService.obtainActivationToken(clientId, clientSecret, USER_ID)
        result = register(activationToken = activationToken, pinProvider = newPinProvider)
        Assert.assertTrue(result is MIRACLSuccess)
        user = (result as MIRACLSuccess).value
        Assert.assertEquals(USER_ID, user.userId)

        // Authentication
        accessId = URL(MIRACLService.obtainAccessId().qrURL).ref
        authenticationResult = authenticator.authenticate(
            user = user,
            accessId = accessId,
            pinProvider = newPinProvider,
            scope = arrayOf(
                AuthenticatorScopes.JWT.value
            ),
            deviceName = Build.MODEL
        )
        Assert.assertTrue(authenticationResult is MIRACLSuccess)
    }

    @Test
    fun testRegistrationFailOnEmptyUserId() = runBlocking {
        // Arrange
        val emptyUserId = ""
        val activationToken = MIRACLService.obtainActivationToken(clientId, clientSecret, USER_ID)

        // Act
        val result = register(activationToken, emptyUserId)

        // Assert
        Assert.assertTrue(result is MIRACLError)
        Assert.assertEquals(
            RegistrationException.EmptyUserId,
            (result as MIRACLError).value
        )
    }

    @Test
    fun testRegistrationFailOnEmptyActivationToken() = runBlocking {
        // Arrange
        val activationToken = ""

        // Act
        val result = register(activationToken)

        // Assert
        Assert.assertTrue(result is MIRACLError)
        Assert.assertEquals(
            RegistrationException.EmptyActivationToken,
            (result as MIRACLError).value
        )
    }

    @Test
    fun testRegistrationFailOnInvalidActivationToken() = runBlocking {
        // Arrange
        val invalidActivationToken = "invalidActivationToken"

        // Act
        val result = register(invalidActivationToken)

        // Assert
        Assert.assertTrue(result is MIRACLError)
        Assert.assertEquals(
            RegistrationException.InvalidActivationToken,
            (result as MIRACLError).value
        )
    }

    @Test
    fun testRegistrationFailOnProjectMismatch() = runBlocking {
        // Arrange
        val differentProjectId = "differentProjectId"
        val activationToken = MIRACLService.obtainActivationToken(clientId, clientSecret, USER_ID)

        // Act
        val result = register(activationToken, projectId = differentProjectId)

        // Assert
        Assert.assertTrue(result is MIRACLError)
        Assert.assertEquals(RegistrationException.ProjectMismatch, (result as MIRACLError).value)
    }

    @Test
    fun testRegistrationFailOnEmptyPin() = runBlocking {
        // Arrange
        val activationToken = MIRACLService.obtainActivationToken(clientId, clientSecret, USER_ID)
        val pinProvider = PinProvider { pinConsumer -> pinConsumer.consume(null) }

        // Act
        val result = register(activationToken = activationToken, pinProvider = pinProvider)

        // Assert
        Assert.assertTrue(result is MIRACLError)
        Assert.assertTrue((result as MIRACLError).value is RegistrationException.PinCancelled)
    }

    @Test
    fun testRegistrationFailOnShorterPinLength() = runBlocking {
        // Arrange
        val activationToken = MIRACLService.obtainActivationToken(clientId, clientSecret, USER_ID)
        val pin = randomNumericPin(Registrator.MIN_PIN_LENGTH - 1)
        val pinProvider = PinProvider { pinConsumer -> pinConsumer.consume(pin) }

        // Act
        val result = register(activationToken = activationToken, pinProvider = pinProvider)

        // Assert
        Assert.assertTrue(result is MIRACLError)
        Assert.assertTrue((result as MIRACLError).value is RegistrationException.InvalidPin)
    }

    @Test
    fun testRegistrationFailOnLongerPinLength() = runBlocking {
        // Arrange
        val activationToken = MIRACLService.obtainActivationToken(clientId, clientSecret, USER_ID)
        val pin = randomNumericPin(Registrator.MAX_PIN_LENGTH + 1)
        val pinProvider = PinProvider { pinConsumer -> pinConsumer.consume(pin) }

        // Act
        val result = register(activationToken = activationToken, pinProvider = pinProvider)

        // Assert
        Assert.assertTrue(result is MIRACLError)
        Assert.assertTrue((result as MIRACLError).value is RegistrationException.InvalidPin)
    }

    @Test
    fun testRegistrationFailOnWrongFormatPin() = runBlocking {
        // Arrange
        val activationToken = MIRACLService.obtainActivationToken(clientId, clientSecret, USER_ID)
        val pinProvider = PinProvider { pinConsumer -> pinConsumer.consume(WRONG_FORMAT_PIN) }

        // Act
        val result = register(activationToken = activationToken, pinProvider = pinProvider)

        // Assert
        Assert.assertTrue(result is MIRACLError)
        Assert.assertTrue((result as MIRACLError).value is RegistrationException.InvalidPin)
    }

    private suspend fun register(
        activationToken: String,
        userId: String = USER_ID,
        projectId: String = BuildConfig.CUV_PROJECT_ID,
        pinProvider: PinProvider = PinProvider { pinConsumer -> pinConsumer.consume(randomNumericPin()) }
    ) = registrator.register(
        userId,
        projectId,
        activationToken,
        pinProvider,
        Build.MODEL,
        null
    )

    private suspend fun authenticate(user: User, accessId: String, pinProvider: PinProvider) =
        authenticator.authenticate(
            user,
            accessId,
            pinProvider,
            arrayOf(AuthenticatorScopes.JWT.value),
            Build.MODEL
        )
}