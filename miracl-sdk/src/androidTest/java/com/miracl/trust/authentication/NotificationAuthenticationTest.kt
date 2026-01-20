package com.miracl.trust.authentication

import androidx.test.platform.app.InstrumentationRegistry
import com.miracl.trust.BuildConfig
import com.miracl.trust.MIRACLError
import com.miracl.trust.MIRACLSuccess
import com.miracl.trust.MIRACLTrust
import com.miracl.trust.configuration.Configuration
import com.miracl.trust.delegate.PinProvider
import com.miracl.trust.model.User
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
    fun setUp() = runTest(testCoroutineDispatcher) {
        val configuration = Configuration.Builder(projectId, projectUrl)
            .coroutineContext(testCoroutineDispatcher)
            .build()

        MIRACLTrust.configure(InstrumentationRegistry.getInstrumentation().context, configuration)
        miraclTrust = MIRACLTrust.getInstance()

        pin = randomNumericPin()
        pinProvider = PinProvider { pinConsumer -> pinConsumer.consume(pin) }
        val activationToken = MIRACLService.obtainActivationToken()

        val registrationResult = miraclTrust.register(
            userId = USER_ID,
            activationToken = activationToken,
            pinProvider = pinProvider,
            pushNotificationsToken = null,
        )
        Assert.assertTrue(registrationResult is MIRACLSuccess)

        user = (registrationResult as MIRACLSuccess).value
    }

    @Test
    fun testSuccessfulNotificationAuthentication() = runTest(testCoroutineDispatcher) {
        // Arrange
        val qrUrl = MIRACLService.obtainAccessId().qrURL
        val payload = mapOf(
            "projectID" to projectId,
            "userID" to USER_ID,
            "qrURL" to qrUrl
        )

        // Act
        val result = miraclTrust.authenticateWithNotificationPayload(payload, pinProvider)

        // Assert
        Assert.assertTrue(result is MIRACLSuccess)
    }

    @Test
    fun testAuthenticationFailOnInvalidNotificationPayload() = runTest(testCoroutineDispatcher) {
        // Arrange
        val payload = mapOf<String, String>()

        // Act
        val result = miraclTrust.authenticateWithNotificationPayload(payload, pinProvider)

        // Assert
        Assert.assertTrue(result is MIRACLError)
        Assert.assertEquals(
            AuthenticationException.InvalidPushNotificationPayload,
            (result as MIRACLError).value
        )
    }

    @Test
    fun testNotificationAuthenticationFailOnInvalidAccessId() = runTest(testCoroutineDispatcher) {
        // Arrange
        val invalidAccessId = "invalidAccessId"
        val payload = mapOf(
            "projectID" to projectId,
            "userID" to USER_ID,
            "qrURL" to "https://mcl.mpin.io/mobile-login/#$invalidAccessId"
        )

        // Act
        val result = miraclTrust.authenticateWithNotificationPayload(payload, pinProvider)

        // Assert
        Assert.assertTrue(result is MIRACLError)
        Assert.assertEquals(
            AuthenticationException.InvalidAuthenticationSession,
            (result as MIRACLError).value
        )
    }

    @Test
    fun testNotificationAuthenticationFailToGetUser() = runTest(testCoroutineDispatcher) {
        // Arrange
        val invalidUserId = USER_ID + "123"
        val qrUrl = MIRACLService.obtainAccessId().qrURL
        val payload = mapOf(
            "projectID" to projectId,
            "userID" to invalidUserId,
            "qrURL" to qrUrl
        )

        // Act
        val result = miraclTrust.authenticateWithNotificationPayload(payload, pinProvider)

        // Assert
        Assert.assertTrue(result is MIRACLError)
        Assert.assertEquals(
            AuthenticationException.UserNotFound,
            (result as MIRACLError).value
        )
    }

    @Test
    fun testNotificationAuthenticationFailOnEmptyPin() = runTest(testCoroutineDispatcher) {
        // Arrange
        val emptyPinProvider = PinProvider { it.consume(null) }
        val qrUrl = MIRACLService.obtainAccessId().qrURL
        val payload = mapOf(
            "projectID" to projectId,
            "userID" to USER_ID,
            "qrURL" to qrUrl
        )

        // Act
        val result = miraclTrust.authenticateWithNotificationPayload(payload, emptyPinProvider)

        // Assert
        Assert.assertTrue(result is MIRACLError)
        Assert.assertEquals(
            AuthenticationException.PinCancelled,
            (result as MIRACLError).value
        )
    }

    @Test
    fun testNotificationAuthenticationFailOnShorterPin() = runTest(testCoroutineDispatcher) {
        // Arrange
        val shorterPinProvider = PinProvider { it.consume(randomNumericPin(pin.length - 1)) }
        val qrUrl = MIRACLService.obtainAccessId().qrURL
        val payload = mapOf(
            "projectID" to projectId,
            "userID" to USER_ID,
            "qrURL" to qrUrl
        )

        // Act
        val result = miraclTrust.authenticateWithNotificationPayload(payload, shorterPinProvider)

        // Assert
        Assert.assertTrue(result is MIRACLError)
        Assert.assertEquals(
            AuthenticationException.InvalidPin,
            (result as MIRACLError).value
        )
    }

    @Test
    fun testNotificationAuthenticationFailOnLongerPin() = runTest(testCoroutineDispatcher) {
        // Arrange
        val longerPinProvider = PinProvider { it.consume(randomNumericPin(pin.length + 1)) }
        val qrUrl = MIRACLService.obtainAccessId().qrURL
        val payload = mapOf(
            "projectID" to projectId,
            "userID" to USER_ID,
            "qrURL" to qrUrl
        )

        // Act
        val result = miraclTrust.authenticateWithNotificationPayload(payload, longerPinProvider)

        // Assert
        Assert.assertTrue(result is MIRACLError)
        Assert.assertEquals(
            AuthenticationException.InvalidPin,
            (result as MIRACLError).value
        )
    }

    @Test
    fun testNotificationAuthenticationFailOnWrongFormatPin() = runTest(testCoroutineDispatcher) {
        // Arrange
        val wrongFormatPinProvider = PinProvider { it.consume(WRONG_FORMAT_PIN) }
        val qrUrl = MIRACLService.obtainAccessId().qrURL
        val payload = mapOf(
            "projectID" to projectId,
            "userID" to USER_ID,
            "qrURL" to qrUrl
        )

        // Act
        val result =
            miraclTrust.authenticateWithNotificationPayload(payload, wrongFormatPinProvider)

        // Assert
        Assert.assertTrue(result is MIRACLError)
        Assert.assertEquals(
            AuthenticationException.InvalidPin,
            (result as MIRACLError).value
        )
    }

    @Test
    fun testNotificationAuthenticationFailOnWrongPin() = runTest(testCoroutineDispatcher) {
        // Arrange
        val wrongPinProvider = PinProvider { it.consume(generateWrongPin(pin)) }
        val qrUrl = MIRACLService.obtainAccessId().qrURL
        val payload = mapOf(
            "projectID" to projectId,
            "userID" to USER_ID,
            "qrURL" to qrUrl
        )

        // Act
        val result = miraclTrust.authenticateWithNotificationPayload(payload, wrongPinProvider)

        // Assert
        Assert.assertTrue(result is MIRACLError)
        Assert.assertEquals(
            AuthenticationException.UnsuccessfulAuthentication,
            (result as MIRACLError).value
        )
    }

    @Test
    fun testNotificationAuthenticationFailOnRevokedUser() = runTest(testCoroutineDispatcher) {
        // Arrange
        val wrongPinProvider = PinProvider { it.consume(generateWrongPin(pin)) }
        val qrUrl = MIRACLService.obtainAccessId().qrURL
        val payload = mapOf(
            "projectID" to projectId,
            "userID" to USER_ID,
            "qrURL" to qrUrl
        )

        var result = miraclTrust.authenticateWithNotificationPayload(payload, wrongPinProvider)
        Assert.assertTrue(result is MIRACLError)
        Assert.assertEquals(
            AuthenticationException.UnsuccessfulAuthentication,
            (result as MIRACLError).value
        )

        result = miraclTrust.authenticateWithNotificationPayload(payload, wrongPinProvider)
        Assert.assertTrue(result is MIRACLError)
        Assert.assertEquals(
            AuthenticationException.UnsuccessfulAuthentication,
            (result as MIRACLError).value
        )

        result = miraclTrust.authenticateWithNotificationPayload(payload, wrongPinProvider)
        Assert.assertTrue(result is MIRACLError)
        Assert.assertEquals(AuthenticationException.Revoked, (result as MIRACLError).value)

        Assert.assertTrue(miraclTrust.getUser(user.userId)!!.revoked)

        // Act
        result = miraclTrust.authenticateWithNotificationPayload(payload, pinProvider)

        // Assert
        Assert.assertTrue(result is MIRACLError)
        Assert.assertEquals(AuthenticationException.Revoked, (result as MIRACLError).value)
    }
}