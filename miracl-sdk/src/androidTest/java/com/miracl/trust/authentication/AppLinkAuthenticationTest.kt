package com.miracl.trust.authentication

import android.net.Uri
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

class AppLinkAuthenticationTest {
    private val projectId = BuildConfig.CUV_PROJECT_ID
    private val clientId = BuildConfig.CUV_CLIENT_ID
    private val clientSecret = BuildConfig.CUV_CLIENT_SECRET

    private val testCoroutineDispatcher = StandardTestDispatcher()

    private lateinit var miraclTrust: MIRACLTrust
    private lateinit var pin: String
    private lateinit var pinProvider: PinProvider
    private lateinit var user: User

    @Before
    fun setUp() = runTest {
        val configuration = Configuration.Builder(projectId)
            .platformUrl(BuildConfig.BASE_URL)
            .coroutineContext(testCoroutineDispatcher)
            .build()

        MIRACLTrust.configure(InstrumentationRegistry.getInstrumentation().context, configuration)
        miraclTrust = MIRACLTrust.getInstance()
        miraclTrust.resultHandlerDispatcher = testCoroutineDispatcher

        pin = randomNumericPin()
        pinProvider = PinProvider { pinConsumer -> pinConsumer.consume(pin) }
        val activationToken = MIRACLService.obtainActivationToken(clientId, clientSecret, USER_ID)

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
    fun testSuccessfulAppLinkAuthentication() = runTest {
        // Arrange
        val appLink = Uri.parse(MIRACLService.obtainAccessId().qrURL)
        var result: MIRACLResult<Unit, AuthenticationException>? = null

        // Act
        miraclTrust.authenticateWithAppLink(user, appLink, pinProvider) { result = it }
        testCoroutineDispatcher.scheduler.advanceUntilIdle()

        // Assert
        Assert.assertTrue(result is MIRACLSuccess)
    }

    @Test
    fun testAppLinkAuthenticationFailOnInvalidAccessId() {
        // Arrange
        val appLink = Uri.parse("https://mcl.mpin.io/mobile/auth#invalidAccessId")
        var result: MIRACLResult<Unit, AuthenticationException>? = null

        // Act
        miraclTrust.authenticateWithAppLink(user, appLink, pinProvider) { result = it }
        testCoroutineDispatcher.scheduler.advanceUntilIdle()

        // Assert
        Assert.assertTrue(result is MIRACLError)
        Assert.assertEquals(
            AuthenticationException.InvalidAuthenticationSession,
            (result as MIRACLError).value
        )
    }

    @Test
    fun testAppLinkAuthenticationFailOnEmptyPin() = runTest {
        // Arrange
        val emptyPinProvider = PinProvider { it.consume(null) }
        val appLink = Uri.parse(MIRACLService.obtainAccessId().qrURL)
        var result: MIRACLResult<Unit, AuthenticationException>? = null

        // Act
        miraclTrust.authenticateWithAppLink(user, appLink, emptyPinProvider) { result = it }
        testCoroutineDispatcher.scheduler.advanceUntilIdle()

        // Assert
        Assert.assertTrue(result is MIRACLError)
        Assert.assertEquals(
            AuthenticationException.PinCancelled,
            (result as MIRACLError).value
        )
    }

    @Test
    fun testAppLinkAuthenticationFailOnShorterPin() = runTest {
        // Arrange
        val shorterPinProvider = PinProvider { it.consume(randomNumericPin(pin.length - 1)) }
        val appLink = Uri.parse(MIRACLService.obtainAccessId().qrURL)
        var result: MIRACLResult<Unit, AuthenticationException>? = null

        // Act
        miraclTrust.authenticateWithAppLink(user, appLink, shorterPinProvider) { result = it }
        testCoroutineDispatcher.scheduler.advanceUntilIdle()

        // Assert
        Assert.assertTrue(result is MIRACLError)
        Assert.assertEquals(
            AuthenticationException.InvalidPin,
            (result as MIRACLError).value
        )
    }

    @Test
    fun testAppLinkAuthenticationFailOnLongerPin() = runTest {
        // Arrange
        val longerPinProvider = PinProvider { it.consume(randomNumericPin(pin.length + 1)) }
        val appLink = Uri.parse(MIRACLService.obtainAccessId().qrURL)
        var result: MIRACLResult<Unit, AuthenticationException>? = null

        // Act
        miraclTrust.authenticateWithAppLink(user, appLink, longerPinProvider) { result = it }
        testCoroutineDispatcher.scheduler.advanceUntilIdle()

        // Assert
        Assert.assertTrue(result is MIRACLError)
        Assert.assertEquals(
            AuthenticationException.InvalidPin,
            (result as MIRACLError).value
        )
    }

    @Test
    fun testAppLinkAuthenticationFailOnWrongFormatPin() = runTest {
        // Arrange
        val wrongFormatPinProvider = PinProvider { it.consume(WRONG_FORMAT_PIN) }
        val appLink = Uri.parse(MIRACLService.obtainAccessId().qrURL)
        var result: MIRACLResult<Unit, AuthenticationException>? = null

        // Act
        miraclTrust.authenticateWithAppLink(user, appLink, wrongFormatPinProvider) { result = it }
        testCoroutineDispatcher.scheduler.advanceUntilIdle()

        // Assert
        Assert.assertTrue(result is MIRACLError)
        Assert.assertEquals(
            AuthenticationException.InvalidPin,
            (result as MIRACLError).value
        )
    }

    @Test
    fun testAppLinkAuthenticationFailOnWrongPin() = runTest {
        // Arrange
        val wrongPinProvider = PinProvider { it.consume(generateWrongPin(pin)) }
        val appLink = Uri.parse(MIRACLService.obtainAccessId().qrURL)
        var result: MIRACLResult<Unit, AuthenticationException>? = null

        // Act
        miraclTrust.authenticateWithAppLink(user, appLink, wrongPinProvider) { result = it }
        testCoroutineDispatcher.scheduler.advanceUntilIdle()

        // Assert
        Assert.assertTrue(result is MIRACLError)
        Assert.assertEquals(
            AuthenticationException.UnsuccessfulAuthentication,
            (result as MIRACLError).value
        )
    }

    @Test
    fun testAppLinkAuthenticationFailOnRevokedUser() = runTest {
        // Arrange
        val wrongPinProvider = PinProvider { it.consume(generateWrongPin(pin)) }
        val appLink = Uri.parse(MIRACLService.obtainAccessId().qrURL)
        var result: MIRACLResult<Unit, AuthenticationException>? = null

        miraclTrust.authenticateWithAppLink(user, appLink, wrongPinProvider) { result = it }
        testCoroutineDispatcher.scheduler.advanceUntilIdle()
        Assert.assertTrue(result is MIRACLError)
        Assert.assertEquals(
            AuthenticationException.UnsuccessfulAuthentication,
            (result as MIRACLError).value
        )

        miraclTrust.authenticateWithAppLink(user, appLink, wrongPinProvider) { result = it }
        testCoroutineDispatcher.scheduler.advanceUntilIdle()
        Assert.assertTrue(result is MIRACLError)
        Assert.assertEquals(
            AuthenticationException.UnsuccessfulAuthentication,
            (result as MIRACLError).value
        )

        miraclTrust.authenticateWithAppLink(user, appLink, wrongPinProvider) { result = it }
        testCoroutineDispatcher.scheduler.advanceUntilIdle()
        Assert.assertTrue(result is MIRACLError)
        Assert.assertEquals(AuthenticationException.Revoked, (result as MIRACLError).value)

        Assert.assertTrue(miraclTrust.getUser(user.userId)!!.revoked)

        // Act
        miraclTrust.authenticateWithAppLink(user, appLink, pinProvider) { result = it }
        testCoroutineDispatcher.scheduler.advanceUntilIdle()

        // Assert
        Assert.assertTrue(result is MIRACLError)
        Assert.assertEquals(AuthenticationException.Revoked, (result as MIRACLError).value)
    }
}