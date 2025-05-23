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
import com.miracl.trust.utilities.JwtHelper
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

class AuthenticationTest {
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
    fun testSuccessfulAuthentication() = runTest {
        // Arrange
        var result: MIRACLResult<String, AuthenticationException>? = null

        // Act
        miraclTrust.authenticate(user, pinProvider) { result = it }
        testCoroutineDispatcher.scheduler.advanceUntilIdle()

        // Assert
        Assert.assertTrue(result is MIRACLSuccess)
        val token = (result as MIRACLSuccess).value

        val claims = JwtHelper.parseSignedClaims(token)
        Assert.assertTrue(claims.payload.audience.contains(projectId))
    }

    @Test
    fun testAuthenticationFailOnEmptyPin() {
        // Arrange
        val emptyPinProvider = PinProvider { it.consume(null) }
        var result: MIRACLResult<String, AuthenticationException>? = null

        // Act
        miraclTrust.authenticate(user, emptyPinProvider) { result = it }
        testCoroutineDispatcher.scheduler.advanceUntilIdle()

        // Assert
        Assert.assertTrue(result is MIRACLError)
        Assert.assertEquals(
            AuthenticationException.PinCancelled,
            (result as MIRACLError).value
        )
    }

    @Test
    fun testAuthenticationFailOnShorterPin() {
        // Arrange
        val shorterPinProvider = PinProvider { it.consume(randomNumericPin(pin.length - 1)) }
        var result: MIRACLResult<String, AuthenticationException>? = null

        // Act
        miraclTrust.authenticate(user, shorterPinProvider) { result = it }
        testCoroutineDispatcher.scheduler.advanceUntilIdle()

        // Assert
        Assert.assertTrue(result is MIRACLError)
        Assert.assertEquals(
            AuthenticationException.InvalidPin,
            (result as MIRACLError).value
        )
    }

    @Test
    fun testAuthenticationFailOnLongerPin() {
        // Arrange
        val longerPinProvider = PinProvider { it.consume(randomNumericPin(pin.length + 1)) }
        var result: MIRACLResult<String, AuthenticationException>? = null

        // Act
        miraclTrust.authenticate(user, longerPinProvider) { result = it }
        testCoroutineDispatcher.scheduler.advanceUntilIdle()

        // Assert
        Assert.assertTrue(result is MIRACLError)
        Assert.assertEquals(
            AuthenticationException.InvalidPin,
            (result as MIRACLError).value
        )
    }

    @Test
    fun testAuthenticationFailOnWrongFormatPin() {
        // Arrange
        val wrongFormatPinProvider = PinProvider { it.consume(WRONG_FORMAT_PIN) }
        var result: MIRACLResult<String, AuthenticationException>? = null

        // Act
        miraclTrust.authenticate(user, wrongFormatPinProvider) { result = it }
        testCoroutineDispatcher.scheduler.advanceUntilIdle()

        // Assert
        Assert.assertTrue(result is MIRACLError)
        Assert.assertEquals(
            AuthenticationException.InvalidPin,
            (result as MIRACLError).value
        )
    }

    @Test
    fun testAuthenticationFailOnWrongPin() {
        // Arrange
        val wrongPinProvider = PinProvider { it.consume(generateWrongPin(pin)) }
        var result: MIRACLResult<String, AuthenticationException>? = null

        // Act
        miraclTrust.authenticate(user, wrongPinProvider) { result = it }
        testCoroutineDispatcher.scheduler.advanceUntilIdle()

        // Assert
        Assert.assertTrue(result is MIRACLError)
        Assert.assertEquals(
            AuthenticationException.UnsuccessfulAuthentication,
            (result as MIRACLError).value
        )
    }

    @Test
    fun testAuthenticationFailOnRevokedUser() = runTest {
        // Arrange
        val wrongPinProvider = PinProvider { it.consume(generateWrongPin(pin)) }
        var result: MIRACLResult<String, AuthenticationException>? = null

        miraclTrust.authenticate(user, wrongPinProvider) { result = it }
        testCoroutineDispatcher.scheduler.advanceUntilIdle()
        Assert.assertTrue(result is MIRACLError)
        Assert.assertEquals(
            AuthenticationException.UnsuccessfulAuthentication,
            (result as MIRACLError).value
        )

        miraclTrust.authenticate(user, wrongPinProvider) { result = it }
        testCoroutineDispatcher.scheduler.advanceUntilIdle()
        Assert.assertTrue(result is MIRACLError)
        Assert.assertEquals(
            AuthenticationException.UnsuccessfulAuthentication,
            (result as MIRACLError).value
        )

        miraclTrust.authenticate(user, wrongPinProvider) { result = it }
        testCoroutineDispatcher.scheduler.advanceUntilIdle()
        Assert.assertTrue(result is MIRACLError)
        Assert.assertEquals(AuthenticationException.Revoked, (result as MIRACLError).value)

        Assert.assertTrue(miraclTrust.getUser(user.userId)!!.revoked)

        // Act
        miraclTrust.authenticate(user, pinProvider) { result = it }
        testCoroutineDispatcher.scheduler.advanceUntilIdle()

        // Assert
        Assert.assertTrue(result is MIRACLError)
        Assert.assertEquals(AuthenticationException.Revoked, (result as MIRACLError).value)
    }
}