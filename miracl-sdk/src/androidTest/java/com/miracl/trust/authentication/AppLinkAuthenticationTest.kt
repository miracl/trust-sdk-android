package com.miracl.trust.authentication

import android.net.Uri
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

class AppLinkAuthenticationTest {
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

        val registrationResult =  miraclTrust.register(
            userId = USER_ID,
            activationToken = activationToken,
            pinProvider = pinProvider,
            pushNotificationsToken = null,
        )
        Assert.assertTrue(registrationResult is MIRACLSuccess)

        user = (registrationResult as MIRACLSuccess).value
    }

    @Test
    fun testSuccessfulAppLinkAuthentication() = runTest(testCoroutineDispatcher) {
        // Arrange
        val appLink = Uri.parse(MIRACLService.obtainAccessId().qrURL)

        // Act
        val result = miraclTrust.authenticateWithAppLink(user, appLink, pinProvider)

        // Assert
        Assert.assertTrue(result is MIRACLSuccess)
    }

    @Test
    fun testAppLinkAuthenticationFailOnInvalidAccessId() = runTest(testCoroutineDispatcher) {
        // Arrange
        val appLink = Uri.parse("https://mcl.mpin.io/mobile/auth#invalidAccessId")

        // Act
        val result = miraclTrust.authenticateWithAppLink(user, appLink, pinProvider)

        // Assert
        Assert.assertTrue(result is MIRACLError)
        Assert.assertEquals(
            AuthenticationException.InvalidAuthenticationSession,
            (result as MIRACLError).value
        )
    }

    @Test
    fun testAppLinkAuthenticationFailOnEmptyPin() = runTest(testCoroutineDispatcher) {
        // Arrange
        val emptyPinProvider = PinProvider { it.consume(null) }
        val appLink = Uri.parse(MIRACLService.obtainAccessId().qrURL)

        // Act
        val result = miraclTrust.authenticateWithAppLink(user, appLink, emptyPinProvider)

        // Assert
        Assert.assertTrue(result is MIRACLError)
        Assert.assertEquals(
            AuthenticationException.PinCancelled,
            (result as MIRACLError).value
        )
    }

    @Test
    fun testAppLinkAuthenticationFailOnShorterPin() = runTest(testCoroutineDispatcher) {
        // Arrange
        val shorterPinProvider = PinProvider { it.consume(randomNumericPin(pin.length - 1)) }
        val appLink = Uri.parse(MIRACLService.obtainAccessId().qrURL)

        // Act
        val result = miraclTrust.authenticateWithAppLink(user, appLink, shorterPinProvider)

        // Assert
        Assert.assertTrue(result is MIRACLError)
        Assert.assertEquals(
            AuthenticationException.InvalidPin,
            (result as MIRACLError).value
        )
    }

    @Test
    fun testAppLinkAuthenticationFailOnLongerPin() = runTest(testCoroutineDispatcher) {
        // Arrange
        val longerPinProvider = PinProvider { it.consume(randomNumericPin(pin.length + 1)) }
        val appLink = Uri.parse(MIRACLService.obtainAccessId().qrURL)

        // Act
        val result = miraclTrust.authenticateWithAppLink(user, appLink, longerPinProvider)

        // Assert
        Assert.assertTrue(result is MIRACLError)
        Assert.assertEquals(
            AuthenticationException.InvalidPin,
            (result as MIRACLError).value
        )
    }

    @Test
    fun testAppLinkAuthenticationFailOnWrongFormatPin() = runTest(testCoroutineDispatcher) {
        // Arrange
        val wrongFormatPinProvider = PinProvider { it.consume(WRONG_FORMAT_PIN) }
        val appLink = Uri.parse(MIRACLService.obtainAccessId().qrURL)

        // Act
        val result = miraclTrust.authenticateWithAppLink(user, appLink, wrongFormatPinProvider)

        // Assert
        Assert.assertTrue(result is MIRACLError)
        Assert.assertEquals(
            AuthenticationException.InvalidPin,
            (result as MIRACLError).value
        )
    }

    @Test
    fun testAppLinkAuthenticationFailOnWrongPin() = runTest(testCoroutineDispatcher) {
        // Arrange
        val wrongPinProvider = PinProvider { it.consume(generateWrongPin(pin)) }
        val appLink = Uri.parse(MIRACLService.obtainAccessId().qrURL)

        // Act
        val result = miraclTrust.authenticateWithAppLink(user, appLink, wrongPinProvider)

        // Assert
        Assert.assertTrue(result is MIRACLError)
        Assert.assertEquals(
            AuthenticationException.UnsuccessfulAuthentication,
            (result as MIRACLError).value
        )
    }

    @Test
    fun testAppLinkAuthenticationFailOnRevokedUser() = runTest(testCoroutineDispatcher) {
        // Arrange
        val wrongPinProvider = PinProvider { it.consume(generateWrongPin(pin)) }
        val appLink = Uri.parse(MIRACLService.obtainAccessId().qrURL)

        var result = miraclTrust.authenticateWithAppLink(user, appLink, wrongPinProvider)
        Assert.assertTrue(result is MIRACLError)
        Assert.assertEquals(
            AuthenticationException.UnsuccessfulAuthentication,
            (result as MIRACLError).value
        )

        result = miraclTrust.authenticateWithAppLink(user, appLink, wrongPinProvider)
        Assert.assertTrue(result is MIRACLError)
        Assert.assertEquals(
            AuthenticationException.UnsuccessfulAuthentication,
            (result as MIRACLError).value
        )

        result = miraclTrust.authenticateWithAppLink(user, appLink, wrongPinProvider)
        Assert.assertTrue(result is MIRACLError)
        Assert.assertEquals(AuthenticationException.Revoked, (result as MIRACLError).value)

        Assert.assertTrue(miraclTrust.getUser(user.userId)!!.revoked)

        // Act
        result = miraclTrust.authenticateWithAppLink(user, appLink, pinProvider)

        // Assert
        Assert.assertTrue(result is MIRACLError)
        Assert.assertEquals(AuthenticationException.Revoked, (result as MIRACLError).value)
    }
}