package com.miracl.trust.authentication

import androidx.test.platform.app.InstrumentationRegistry
import com.miracl.trust.BuildConfig
import com.miracl.trust.MIRACLError
import com.miracl.trust.MIRACLResult
import com.miracl.trust.MIRACLSuccess
import com.miracl.trust.MIRACLTrust
import com.miracl.trust.configuration.Configuration
import com.miracl.trust.delegate.PinProvider
import com.miracl.trust.model.User
import com.miracl.trust.registration.RegistrationException
import com.miracl.trust.utilities.MIRACLService
import com.miracl.trust.utilities.USER_ID
import com.miracl.trust.utilities.WRONG_FORMAT_PIN
import com.miracl.trust.utilities.generateWrongPin
import com.miracl.trust.utilities.randomNumericPin
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.runTest
import org.junit.Assert
import org.junit.Before
import org.junit.Test

class NotificationAuthenticationTest {
    private val projectId = BuildConfig.CUV_PROJECT_ID
    private val projectUrl = BuildConfig.CUV_PROJECT_URL

    private val testCoroutineDispatcher = StandardTestDispatcher()

    private lateinit var miraclTrust: MIRACLTrust
    private lateinit var pin: String
    private lateinit var pinProvider: PinProvider
    private lateinit var user: User

    @Before
    fun setUp() = runTest {
        val configuration = Configuration.Builder(projectId, projectUrl)
            .coroutineContext(testCoroutineDispatcher)
            .build()

        MIRACLTrust.configure(InstrumentationRegistry.getInstrumentation().context, configuration)
        miraclTrust = MIRACLTrust.getInstance()
        miraclTrust.resultHandlerDispatcher = testCoroutineDispatcher

        pin = randomNumericPin()
        pinProvider = PinProvider { pinConsumer -> pinConsumer.consume(pin) }
        val activationToken = MIRACLService.obtainActivationToken()

        var registrationResult: MIRACLResult<User, RegistrationException>? = null
        miraclTrust.register(
            userId = USER_ID,
            activationToken = activationToken,
            pinProvider = pinProvider,
            pushNotificationsToken = null,
            resultHandler = { result -> registrationResult = result }
        )
        testCoroutineDispatcher.scheduler.advanceUntilIdle()
        Assert.assertTrue(registrationResult is MIRACLSuccess)

        user = (registrationResult as MIRACLSuccess).value
    }

    @Test
    fun testSuccessfulNotificationAuthentication() = runTest {
        // Arrange
        val qrUrl = MIRACLService.obtainAccessId().qrURL
        val payload = mapOf(
            "projectID" to projectId,
            "userID" to USER_ID,
            "qrURL" to qrUrl
        )
        var result: MIRACLResult<Unit, AuthenticationException>? = null

        // Act
        miraclTrust.authenticateWithNotificationPayload(payload, pinProvider) { result = it }
        testCoroutineDispatcher.scheduler.advanceUntilIdle()

        // Assert
        Assert.assertTrue(result is MIRACLSuccess)
    }

    @Test
    fun testAuthenticationFailOnInvalidNotificationPayload() {
        // Arrange
        val payload = mapOf<String, String>()
        var result: MIRACLResult<Unit, AuthenticationException>? = null

        // Act
        miraclTrust.authenticateWithNotificationPayload(payload, pinProvider) { result = it }
        testCoroutineDispatcher.scheduler.advanceUntilIdle()

        // Assert
        Assert.assertTrue(result is MIRACLError)
        Assert.assertEquals(
            AuthenticationException.InvalidPushNotificationPayload,
            (result as MIRACLError).value
        )
    }

    @Test
    fun testNotificationAuthenticationFailOnInvalidAccessId() {
        // Arrange
        val invalidAccessId = "invalidAccessId"
        val payload = mapOf(
            "projectID" to projectId,
            "userID" to USER_ID,
            "qrURL" to "https://mcl.mpin.io/mobile-login/#$invalidAccessId"
        )
        var result: MIRACLResult<Unit, AuthenticationException>? = null

        // Act
        miraclTrust.authenticateWithNotificationPayload(payload, pinProvider) { result = it }
        testCoroutineDispatcher.scheduler.advanceUntilIdle()

        // Assert
        Assert.assertTrue(result is MIRACLError)
        Assert.assertEquals(
            AuthenticationException.InvalidAuthenticationSession,
            (result as MIRACLError).value
        )
    }

    @Test
    fun testNotificationAuthenticationFailToGetUser() = runTest {
        // Arrange
        val invalidUserId = USER_ID + "123"
        val qrUrl = MIRACLService.obtainAccessId().qrURL
        val payload = mapOf(
            "projectID" to projectId,
            "userID" to invalidUserId,
            "qrURL" to qrUrl
        )
        var result: MIRACLResult<Unit, AuthenticationException>? = null

        // Act
        miraclTrust.authenticateWithNotificationPayload(payload, pinProvider) { result = it }
        testCoroutineDispatcher.scheduler.advanceUntilIdle()

        // Assert
        Assert.assertTrue(result is MIRACLError)
        Assert.assertEquals(
            AuthenticationException.UserNotFound,
            (result as MIRACLError).value
        )
    }

    @Test
    fun testNotificationAuthenticationFailOnEmptyPin() = runTest {
        // Arrange
        val emptyPinProvider = PinProvider { it.consume(null) }
        val qrUrl = MIRACLService.obtainAccessId().qrURL
        val payload = mapOf(
            "projectID" to projectId,
            "userID" to USER_ID,
            "qrURL" to qrUrl
        )
        var result: MIRACLResult<Unit, AuthenticationException>? = null

        // Act
        miraclTrust.authenticateWithNotificationPayload(payload, emptyPinProvider) { result = it }
        testCoroutineDispatcher.scheduler.advanceUntilIdle()

        // Assert
        Assert.assertTrue(result is MIRACLError)
        Assert.assertEquals(
            AuthenticationException.PinCancelled,
            (result as MIRACLError).value
        )
    }

    @Test
    fun testNotificationAuthenticationFailOnShorterPin() = runTest {
        // Arrange
        val shorterPinProvider = PinProvider { it.consume(randomNumericPin(pin.length - 1)) }
        val qrUrl = MIRACLService.obtainAccessId().qrURL
        val payload = mapOf(
            "projectID" to projectId,
            "userID" to USER_ID,
            "qrURL" to qrUrl
        )
        var result: MIRACLResult<Unit, AuthenticationException>? = null

        // Act
        miraclTrust.authenticateWithNotificationPayload(payload, shorterPinProvider) { result = it }
        testCoroutineDispatcher.scheduler.advanceUntilIdle()

        // Assert
        Assert.assertTrue(result is MIRACLError)
        Assert.assertEquals(
            AuthenticationException.InvalidPin,
            (result as MIRACLError).value
        )
    }

    @Test
    fun testNotificationAuthenticationFailOnLongerPin() = runTest {
        // Arrange
        val longerPinProvider = PinProvider { it.consume(randomNumericPin(pin.length + 1)) }
        val qrUrl = MIRACLService.obtainAccessId().qrURL
        val payload = mapOf(
            "projectID" to projectId,
            "userID" to USER_ID,
            "qrURL" to qrUrl
        )
        var result: MIRACLResult<Unit, AuthenticationException>? = null

        // Act
        miraclTrust.authenticateWithNotificationPayload(payload, longerPinProvider) { result = it }
        testCoroutineDispatcher.scheduler.advanceUntilIdle()

        // Assert
        Assert.assertTrue(result is MIRACLError)
        Assert.assertEquals(
            AuthenticationException.InvalidPin,
            (result as MIRACLError).value
        )
    }

    @Test
    fun testNotificationAuthenticationFailOnWrongFormatPin() = runTest {
        // Arrange
        val wrongFormatPinProvider = PinProvider { it.consume(WRONG_FORMAT_PIN) }
        val qrUrl = MIRACLService.obtainAccessId().qrURL
        val payload = mapOf(
            "projectID" to projectId,
            "userID" to USER_ID,
            "qrURL" to qrUrl
        )
        var result: MIRACLResult<Unit, AuthenticationException>? = null

        // Act
        miraclTrust.authenticateWithNotificationPayload(payload, wrongFormatPinProvider) {
            result = it
        }
        testCoroutineDispatcher.scheduler.advanceUntilIdle()

        // Assert
        Assert.assertTrue(result is MIRACLError)
        Assert.assertEquals(
            AuthenticationException.InvalidPin,
            (result as MIRACLError).value
        )
    }

    @Test
    fun testNotificationAuthenticationFailOnWrongPin() = runTest {
        // Arrange
        val wrongPinProvider = PinProvider { it.consume(generateWrongPin(pin)) }
        val qrUrl = MIRACLService.obtainAccessId().qrURL
        val payload = mapOf(
            "projectID" to projectId,
            "userID" to USER_ID,
            "qrURL" to qrUrl
        )
        var result: MIRACLResult<Unit, AuthenticationException>? = null

        // Act
        miraclTrust.authenticateWithNotificationPayload(payload, wrongPinProvider) { result = it }
        testCoroutineDispatcher.scheduler.advanceUntilIdle()

        // Assert
        Assert.assertTrue(result is MIRACLError)
        Assert.assertEquals(
            AuthenticationException.UnsuccessfulAuthentication,
            (result as MIRACLError).value
        )
    }

    @Test
    fun testNotificationAuthenticationFailOnRevokedUser() = runTest {
        // Arrange
        val wrongPinProvider = PinProvider { it.consume(generateWrongPin(pin)) }
        val qrUrl = MIRACLService.obtainAccessId().qrURL
        val payload = mapOf(
            "projectID" to projectId,
            "userID" to USER_ID,
            "qrURL" to qrUrl
        )
        var result: MIRACLResult<Unit, AuthenticationException>? = null

        miraclTrust.authenticateWithNotificationPayload(payload, wrongPinProvider) { result = it }
        testCoroutineDispatcher.scheduler.advanceUntilIdle()
        Assert.assertTrue(result is MIRACLError)
        Assert.assertEquals(
            AuthenticationException.UnsuccessfulAuthentication,
            (result as MIRACLError).value
        )

        miraclTrust.authenticateWithNotificationPayload(payload, wrongPinProvider) { result = it }
        testCoroutineDispatcher.scheduler.advanceUntilIdle()
        Assert.assertTrue(result is MIRACLError)
        Assert.assertEquals(
            AuthenticationException.UnsuccessfulAuthentication,
            (result as MIRACLError).value
        )

        miraclTrust.authenticateWithNotificationPayload(payload, wrongPinProvider) { result = it }
        testCoroutineDispatcher.scheduler.advanceUntilIdle()
        Assert.assertTrue(result is MIRACLError)
        Assert.assertEquals(AuthenticationException.Revoked, (result as MIRACLError).value)

        Assert.assertTrue(miraclTrust.getUser(user.userId)!!.revoked)

        // Act
        miraclTrust.authenticateWithNotificationPayload(payload, pinProvider) { result = it }
        testCoroutineDispatcher.scheduler.advanceUntilIdle()

        // Assert
        Assert.assertTrue(result is MIRACLError)
        Assert.assertEquals(AuthenticationException.Revoked, (result as MIRACLError).value)
    }
}