package com.miracl.trust.registration

import android.net.Uri
import androidx.test.platform.app.InstrumentationRegistry
import com.miracl.trust.BuildConfig
import com.miracl.trust.MIRACLError
import com.miracl.trust.MIRACLResult
import com.miracl.trust.MIRACLSuccess
import com.miracl.trust.MIRACLTrust
import com.miracl.trust.authentication.AuthenticationException
import com.miracl.trust.configuration.Configuration
import com.miracl.trust.delegate.PinProvider
import com.miracl.trust.model.QuickCode
import com.miracl.trust.model.User
import com.miracl.trust.utilities.GmailService
import com.miracl.trust.utilities.MIRACLService
import com.miracl.trust.utilities.USER_ID
import com.miracl.trust.utilities.generateWrongPin
import com.miracl.trust.utilities.getUnixTime
import com.miracl.trust.utilities.randomNumericPin
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.runTest
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

    private val testCoroutineDispatcher = StandardTestDispatcher()

    private lateinit var miraclTrust: MIRACLTrust
    private lateinit var pinProvider: PinProvider

    @Before
    fun setUp() = runTest {
        val configuration = Configuration.Builder(projectId)
            .coroutineContext(testCoroutineDispatcher)
            .build()

        MIRACLTrust.configure(InstrumentationRegistry.getInstrumentation().context, configuration)
        miraclTrust = MIRACLTrust.getInstance()
        miraclTrust.resultHandlerDispatcher = testCoroutineDispatcher

        pinProvider = PinProvider { pinConsumer -> pinConsumer.consume(randomNumericPin()) }
    }

    @Test
    fun testSuccessfulRegistration() = runTest {
        val activationToken = MIRACLService.obtainActivationToken(clientId, clientSecret, USER_ID)
        val result = register(activationToken)

        Assert.assertTrue(result is MIRACLSuccess)
        Assert.assertEquals(USER_ID, (result as MIRACLSuccess).value.userId)
    }

    @Test
    fun testSuccessfulRegistrationDefaultVerification() = runTest {
        // Send verification email
        miraclTrust.setProjectId(dvProjectId)
        val timestamp = getUnixTime()
        val sendEmailResult = sendVerificationEmail()
        Assert.assertTrue(sendEmailResult is MIRACLSuccess)

        // Fetch the verification URL from the email
        val context = InstrumentationRegistry.getInstrumentation().context
        val verificationUrl = GmailService.getVerificationUrl(context, USER_ID, USER_ID, timestamp)
        Assert.assertNotNull(verificationUrl)

        // Get activation token
        val activationTokenResult = getActivationToken(verificationUrl!!)
        Assert.assertTrue(activationTokenResult is MIRACLSuccess)

        // Register
        val activationToken = (activationTokenResult as MIRACLSuccess).value.activationToken
        val result = register(activationToken = activationToken)

        Assert.assertTrue(result is MIRACLSuccess)
        Assert.assertEquals(USER_ID, (result as MIRACLSuccess).value.userId)
        Assert.assertEquals(dvProjectId, result.value.projectId)
    }

    @Test
    fun testSuccessfulRegistrationCustomVerification() = runTest {
        // Get verification URL
        val verificationUrl = MIRACLService.getVerificationUrl(clientId, clientSecret, USER_ID)
        Assert.assertNotNull(verificationUrl)

        // Get activation token
        val activationTokenResult = getActivationToken(verificationUrl)
        Assert.assertTrue(activationTokenResult is MIRACLSuccess)

        // Register
        val activationToken = (activationTokenResult as MIRACLSuccess).value.activationToken
        val result = register(activationToken)

        Assert.assertTrue(result is MIRACLSuccess)
        Assert.assertEquals(USER_ID, (result as MIRACLSuccess).value.userId)
        Assert.assertEquals(projectId, result.value.projectId)
    }

    @Test
    fun testSuccessfulRegistrationWithQuickCode() = runTest {
        // Register with CUV
        val pin = randomNumericPin()
        val pinProvider = PinProvider { pinConsumer -> pinConsumer.consume(pin) }
        var activationToken = MIRACLService.obtainActivationToken(clientId, clientSecret, USER_ID)
        var result = register(activationToken = activationToken, pinProvider = pinProvider)
        Assert.assertTrue(result is MIRACLSuccess)
        val user = (result as MIRACLSuccess).value

        // Generate QuickCode
        val generateQuickCodeResult = generateQuickCode(
            user = user,
            pinProvider = pinProvider
        )
        Assert.assertTrue(generateQuickCodeResult is MIRACLSuccess)

        // Get activation token
        val activationTokenResult = getActivationToken(
            userId = user.userId,
            code = (generateQuickCodeResult as MIRACLSuccess).value.code
        )
        Assert.assertTrue(activationTokenResult is MIRACLSuccess)

        // Register
        activationToken = (activationTokenResult as MIRACLSuccess).value.activationToken
        result = register(activationToken)

        Assert.assertTrue(result is MIRACLSuccess)
        Assert.assertEquals(user.userId, (result as MIRACLSuccess).value.userId)
        Assert.assertEquals(user.projectId, result.value.projectId)
    }

    @Test
    fun testRegistrationOverride() = runTest {
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
        var authenticationResult = authenticate(user, pinProvider)
        Assert.assertTrue(authenticationResult is MIRACLSuccess)
    }

    @Test
    fun testRegistrationOverrideForRevokedUser() = runTest {
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

        var authenticationResult = authenticate(user, wrongPinProvider)
        Assert.assertTrue(authenticationResult is MIRACLError)

        authenticationResult = authenticate(user, wrongPinProvider)
        Assert.assertTrue(authenticationResult is MIRACLError)

        authenticationResult = authenticate(user, wrongPinProvider)
        Assert.assertTrue(authenticationResult is MIRACLError)

        user = miraclTrust.getUser(user.userId)!!
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
        authenticationResult = authenticate(user, newPinProvider)
        Assert.assertTrue(authenticationResult is MIRACLSuccess)
    }

    @Test
    fun testRegistrationFailOnEmptyUserId() = runTest {
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
    fun testRegistrationFailOnEmptyActivationToken() = runTest {
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
    fun testRegistrationFailOnInvalidActivationToken() = runTest {
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
    fun testRegistrationFailOnProjectMismatch() = runTest {
        // Arrange
        val differentProjectId = "differentProjectId"
        miraclTrust.setProjectId(differentProjectId)
        val activationToken = MIRACLService.obtainActivationToken(clientId, clientSecret, USER_ID)

        // Act
        val result = register(activationToken)

        // Assert
        Assert.assertTrue(result is MIRACLError)
        Assert.assertEquals(RegistrationException.ProjectMismatch, (result as MIRACLError).value)
    }

    @Test
    fun testRegistrationFailOnEmptyPin() = runTest {
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
    fun testRegistrationFailOnShorterPinLength() = runTest {
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
    fun testRegistrationFailOnLongerPinLength() = runTest {
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
    fun testRegistrationFailOnWrongFormatPin() = runTest {
        // Arrange
        val activationToken = MIRACLService.obtainActivationToken(clientId, clientSecret, USER_ID)
        val pinProvider = PinProvider { pinConsumer -> pinConsumer.consume(WRONG_FORMAT_PIN) }

        // Act
        val result = register(activationToken = activationToken, pinProvider = pinProvider)

        // Assert
        Assert.assertTrue(result is MIRACLError)
        Assert.assertTrue((result as MIRACLError).value is RegistrationException.InvalidPin)
    }

    private fun sendVerificationEmail(): MIRACLResult<VerificationResponse, VerificationException>? {
        var result: MIRACLResult<VerificationResponse, VerificationException>? = null
        miraclTrust.sendVerificationEmail(USER_ID) { result = it }
        testCoroutineDispatcher.scheduler.advanceUntilIdle()

        return result
    }

    private fun generateQuickCode(
        user: User,
        pinProvider: PinProvider
    ): MIRACLResult<QuickCode, QuickCodeException>? {
        var result: MIRACLResult<QuickCode, QuickCodeException>? = null
        miraclTrust.generateQuickCode(
            user = user,
            pinProvider = pinProvider,
        ) { result = it }
        testCoroutineDispatcher.scheduler.advanceUntilIdle()

        return result
    }

    private fun getActivationToken(
        verificationUrl: String
    ): MIRACLResult<ActivationTokenResponse, ActivationTokenException>? {
        var result: MIRACLResult<ActivationTokenResponse, ActivationTokenException>? = null
        miraclTrust.getActivationToken(Uri.parse(verificationUrl)) { result = it }
        testCoroutineDispatcher.scheduler.advanceUntilIdle()

        return result
    }

    private fun getActivationToken(
        userId: String,
        code: String
    ): MIRACLResult<ActivationTokenResponse, ActivationTokenException>? {
        var result: MIRACLResult<ActivationTokenResponse, ActivationTokenException>? = null
        miraclTrust.getActivationToken(userId, code) { result = it }
        testCoroutineDispatcher.scheduler.advanceUntilIdle()

        return result
    }

    private fun register(
        activationToken: String,
        userId: String = USER_ID,
        pinProvider: PinProvider = PinProvider { pinConsumer -> pinConsumer.consume(randomNumericPin()) }
    ): MIRACLResult<User, RegistrationException>? {
        var result: MIRACLResult<User, RegistrationException>? = null
        miraclTrust.register(userId, activationToken, pinProvider) { result = it }
        testCoroutineDispatcher.scheduler.advanceUntilIdle()

        return result
    }

    private fun authenticate(
        user: User,
        pinProvider: PinProvider
    ): MIRACLResult<String, AuthenticationException>? {
        var result: MIRACLResult<String, AuthenticationException>? = null
        miraclTrust.authenticate(user, pinProvider) { result = it }
        testCoroutineDispatcher.scheduler.advanceUntilIdle()

        return result
    }
}