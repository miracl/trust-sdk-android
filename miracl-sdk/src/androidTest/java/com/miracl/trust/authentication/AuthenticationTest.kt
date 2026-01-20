package com.miracl.trust.authentication

import androidx.test.platform.app.InstrumentationRegistry
import com.miracl.trust.BuildConfig
import com.miracl.trust.MIRACLError
import com.miracl.trust.MIRACLSuccess
import com.miracl.trust.MIRACLTrust
import com.miracl.trust.configuration.Configuration
import com.miracl.trust.delegate.PinProvider
import com.miracl.trust.model.User
import com.miracl.trust.session.CrossDeviceSession
import com.miracl.trust.session.IdentityType
import com.miracl.trust.session.VerificationMethod
import com.miracl.trust.utilities.JwtHelper
import com.miracl.trust.utilities.MIRACLService
import com.miracl.trust.utilities.USER_ID
import com.miracl.trust.utilities.WRONG_FORMAT_PIN
import com.miracl.trust.utilities.generateWrongPin
import com.miracl.trust.utilities.randomNumericPin
import com.miracl.trust.utilities.randomPinLength
import com.miracl.trust.utilities.randomUuidString
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.runTest
import org.junit.Assert
import org.junit.Before
import org.junit.Test
import kotlin.random.Random

class AuthenticationTest {
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
            pushNotificationsToken = null
        )
        Assert.assertTrue(registrationResult is MIRACLSuccess)

        user = (registrationResult as MIRACLSuccess).value
    }

    @Test
    fun testSuccessfulAuthentication() = runTest(testCoroutineDispatcher) {
        // Act
        val result = miraclTrust.authenticate(user, pinProvider)

        // Assert
        Assert.assertTrue(result is MIRACLSuccess)
        val token = (result as MIRACLSuccess).value

        val jwks = MIRACLService.getJwkSet(projectUrl)
        val claims = JwtHelper.parseSignedClaims(token, jwks)
        Assert.assertTrue(claims.payload.audience.contains(projectId))
    }

    @Test
    fun testSuccessfulAuthenticationWithCrossDeviceSession() = runTest(testCoroutineDispatcher) {
        // Arrange
        val qrCode = MIRACLService.obtainAccessId().qrURL
        val crossDeviceSession =
            (miraclTrust.getCrossDeviceSessionFromQRCode(qrCode) as MIRACLSuccess).value

        // Act
        val result = miraclTrust.authenticate(
            user = user,
            crossDeviceSession = crossDeviceSession,
            pinProvider = pinProvider
        )

        // Assert
        Assert.assertTrue(result is MIRACLSuccess)
    }

    @Test
    fun testAuthenticationWithCrossDeviceSessionFailOnInvalidSession() =
        runTest(testCoroutineDispatcher) {
            // Arrange
            val crossDeviceSession = CrossDeviceSession(
                sessionId = "invalidSessionId",
                sessionDescription = randomUuidString(),
                userId = randomUuidString(),
                projectId = randomUuidString(),
                projectName = randomUuidString(),
                projectLogoUrl = randomUuidString(),
                pinLength = randomPinLength(),
                verificationMethod = VerificationMethod.StandardEmail,
                verificationUrl = randomUuidString(),
                verificationCustomText = randomUuidString(),
                identityType = IdentityType.Email,
                identityTypeLabel = randomUuidString(),
                quickCodeEnabled = Random.nextBoolean(),
                signingHash = ""
            )

            // Act
            val result = miraclTrust.authenticate(user, crossDeviceSession, pinProvider)

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertEquals(
                AuthenticationException.InvalidCrossDeviceSession,
                (result as MIRACLError).value
            )
        }

    @Test
    fun testAuthenticationFailOnEmptyPin() = runTest(testCoroutineDispatcher) {
        // Arrange
        val emptyPinProvider = PinProvider { it.consume(null) }

        // Act
        val result = miraclTrust.authenticate(user, emptyPinProvider)

        // Assert
        Assert.assertTrue(result is MIRACLError)
        Assert.assertEquals(
            AuthenticationException.PinCancelled,
            (result as MIRACLError).value
        )
    }

    @Test
    fun testAuthenticationFailOnShorterPin() = runTest(testCoroutineDispatcher) {
        // Arrange
        val shorterPinProvider = PinProvider { it.consume(randomNumericPin(pin.length - 1)) }

        // Act
        val result = miraclTrust.authenticate(user, shorterPinProvider)

        // Assert
        Assert.assertTrue(result is MIRACLError)
        Assert.assertEquals(
            AuthenticationException.InvalidPin,
            (result as MIRACLError).value
        )
    }

    @Test
    fun testAuthenticationFailOnLongerPin() = runTest(testCoroutineDispatcher) {
        // Arrange
        val longerPinProvider = PinProvider { it.consume(randomNumericPin(pin.length + 1)) }

        // Act
        val result = miraclTrust.authenticate(user, longerPinProvider)
        testCoroutineDispatcher.scheduler.advanceUntilIdle()

        // Assert
        Assert.assertTrue(result is MIRACLError)
        Assert.assertEquals(
            AuthenticationException.InvalidPin,
            (result as MIRACLError).value
        )
    }

    @Test
    fun testAuthenticationFailOnWrongFormatPin() = runTest(testCoroutineDispatcher) {
        // Arrange
        val wrongFormatPinProvider = PinProvider { it.consume(WRONG_FORMAT_PIN) }

        // Act
        val result = miraclTrust.authenticate(user, wrongFormatPinProvider)

        // Assert
        Assert.assertTrue(result is MIRACLError)
        Assert.assertEquals(
            AuthenticationException.InvalidPin,
            (result as MIRACLError).value
        )
    }

    @Test
    fun testAuthenticationFailOnWrongPin() = runTest(testCoroutineDispatcher) {
        // Arrange
        val wrongPinProvider = PinProvider { it.consume(generateWrongPin(pin)) }

        // Act
        val result = miraclTrust.authenticate(user, wrongPinProvider)

        // Assert
        Assert.assertTrue(result is MIRACLError)
        Assert.assertEquals(
            AuthenticationException.UnsuccessfulAuthentication,
            (result as MIRACLError).value
        )
    }

    @Test
    fun testAuthenticationFailOnRevokedUser() = runTest(testCoroutineDispatcher) {
        // Arrange
        val wrongPinProvider = PinProvider { it.consume(generateWrongPin(pin)) }

        var result = miraclTrust.authenticate(user, wrongPinProvider)
        Assert.assertTrue(result is MIRACLError)
        Assert.assertEquals(
            AuthenticationException.UnsuccessfulAuthentication,
            (result as MIRACLError).value
        )

        result = miraclTrust.authenticate(user, wrongPinProvider)
        Assert.assertTrue(result is MIRACLError)
        Assert.assertEquals(
            AuthenticationException.UnsuccessfulAuthentication,
            (result as MIRACLError).value
        )

        result = miraclTrust.authenticate(user, wrongPinProvider)
        Assert.assertTrue(result is MIRACLError)
        Assert.assertEquals(AuthenticationException.Revoked, (result as MIRACLError).value)

        Assert.assertTrue(miraclTrust.getUser(user.userId)!!.revoked)

        // Act
        result = miraclTrust.authenticate(user, pinProvider)

        // Assert
        Assert.assertTrue(result is MIRACLError)
        Assert.assertEquals(AuthenticationException.Revoked, (result as MIRACLError).value)
    }
}