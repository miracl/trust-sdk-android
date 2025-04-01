package com.miracl.trust.registration

import androidx.test.platform.app.InstrumentationRegistry
import com.miracl.trust.BuildConfig
import com.miracl.trust.MIRACLError
import com.miracl.trust.MIRACLResult
import com.miracl.trust.MIRACLSuccess
import com.miracl.trust.MIRACLTrust
import com.miracl.trust.configuration.Configuration
import com.miracl.trust.delegate.PinProvider
import com.miracl.trust.model.QuickCode
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

class QuickCodeGenerationTest {
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
    fun testSuccessfulQuickCodeGeneration() {
        // Arrange
        var result: MIRACLResult<QuickCode, QuickCodeException>? = null

        // Act
        miraclTrust.generateQuickCode(user, pinProvider) { result = it }
        testCoroutineDispatcher.scheduler.advanceUntilIdle()

        // Assert
        Assert.assertTrue(result is MIRACLSuccess)
    }

    @Test
    fun testQuickCodeGenerationFailOnEmptyPin() {
        // Arrange
        val emptyPinProvider = PinProvider { it.consume(null) }
        var result: MIRACLResult<QuickCode, QuickCodeException>? = null

        // Act
        miraclTrust.generateQuickCode(user, emptyPinProvider) { result = it }
        testCoroutineDispatcher.scheduler.advanceUntilIdle()

        // Assert
        Assert.assertTrue(result is MIRACLError)
        Assert.assertEquals(
            QuickCodeException.PinCancelled,
            (result as MIRACLError).value
        )
    }

    @Test
    fun testQuickCodeGenerationFailOnShorterPin() {
        // Arrange
        val shorterPinProvider = PinProvider { it.consume(randomNumericPin(pin.length - 1)) }
        var result: MIRACLResult<QuickCode, QuickCodeException>? = null

        // Act
        miraclTrust.generateQuickCode(user, shorterPinProvider) { result = it }
        testCoroutineDispatcher.scheduler.advanceUntilIdle()

        // Assert
        Assert.assertTrue(result is MIRACLError)
        Assert.assertEquals(
            QuickCodeException.InvalidPin,
            (result as MIRACLError).value
        )
    }

    @Test
    fun testQuickCodeGenerationFailOnLongerPin() {
        // Arrange
        val longerPinProvider = PinProvider { it.consume(randomNumericPin(pin.length + 1)) }
        var result: MIRACLResult<QuickCode, QuickCodeException>? = null

        // Act
        miraclTrust.generateQuickCode(user, longerPinProvider) { result = it }
        testCoroutineDispatcher.scheduler.advanceUntilIdle()

        // Assert
        Assert.assertTrue(result is MIRACLError)
        Assert.assertEquals(
            QuickCodeException.InvalidPin,
            (result as MIRACLError).value
        )
    }

    @Test
    fun testQuickCodeGenerationFailOnWrongFormatPin() {
        // Arrange
        val wrongFormatPinProvider = PinProvider { it.consume(WRONG_FORMAT_PIN) }
        var result: MIRACLResult<QuickCode, QuickCodeException>? = null

        // Act
        miraclTrust.generateQuickCode(user, wrongFormatPinProvider) { result = it }
        testCoroutineDispatcher.scheduler.advanceUntilIdle()

        // Assert
        Assert.assertTrue(result is MIRACLError)
        Assert.assertEquals(
            QuickCodeException.InvalidPin,
            (result as MIRACLError).value
        )
    }

    @Test
    fun testQuickCodeGenerationFailOnWrongPin() {
        // Arrange
        val wrongPinProvider = PinProvider { it.consume(generateWrongPin(pin)) }
        var result: MIRACLResult<QuickCode, QuickCodeException>? = null

        // Act
        miraclTrust.generateQuickCode(user, wrongPinProvider) { result = it }
        testCoroutineDispatcher.scheduler.advanceUntilIdle()

        // Assert
        Assert.assertTrue(result is MIRACLError)
        Assert.assertEquals(
            QuickCodeException.UnsuccessfulAuthentication,
            (result as MIRACLError).value
        )
    }

    @Test
    fun testQuickCodeGenerationFailOnRevokedUser() = runTest {
        // Arrange
        val wrongPinProvider = PinProvider { it.consume(generateWrongPin(pin)) }
        var result: MIRACLResult<QuickCode, QuickCodeException>? = null

        miraclTrust.generateQuickCode(user, wrongPinProvider) { result = it }
        testCoroutineDispatcher.scheduler.advanceUntilIdle()
        Assert.assertTrue(result is MIRACLError)
        Assert.assertEquals(
            QuickCodeException.UnsuccessfulAuthentication,
            (result as MIRACLError).value
        )

        miraclTrust.generateQuickCode(user, wrongPinProvider) { result = it }
        testCoroutineDispatcher.scheduler.advanceUntilIdle()
        Assert.assertTrue(result is MIRACLError)
        Assert.assertEquals(
            QuickCodeException.UnsuccessfulAuthentication,
            (result as MIRACLError).value
        )

        miraclTrust.generateQuickCode(user, wrongPinProvider) { result = it }
        testCoroutineDispatcher.scheduler.advanceUntilIdle()
        Assert.assertTrue(result is MIRACLError)
        Assert.assertEquals(QuickCodeException.Revoked, (result as MIRACLError).value)

        Assert.assertTrue(miraclTrust.getUser(user.userId)!!.revoked)

        // Act
        miraclTrust.generateQuickCode(user, pinProvider) { result = it }
        testCoroutineDispatcher.scheduler.advanceUntilIdle()

        // Assert
        Assert.assertTrue(result is MIRACLError)
        Assert.assertEquals(QuickCodeException.Revoked, (result as MIRACLError).value)
    }

    @Test(expected = AssertionError::class)
    fun testFailOnLimitedQuickCodeGeneration() {
        // Arrange
        var quickCodeGenerationResult: MIRACLResult<QuickCode, QuickCodeException>? = null
        miraclTrust.generateQuickCode(user, pinProvider) { quickCodeGenerationResult = it }
        testCoroutineDispatcher.scheduler.advanceUntilIdle()
        Assert.assertTrue(quickCodeGenerationResult is MIRACLSuccess)

        var getActivationTokenResult:
                MIRACLResult<ActivationTokenResponse, ActivationTokenException>? = null

        miraclTrust.getActivationToken(
            userId = user.userId,
            code = (quickCodeGenerationResult as MIRACLSuccess).value.code,
            resultHandler = { getActivationTokenResult = it }
        )
        testCoroutineDispatcher.scheduler.advanceUntilIdle()
        Assert.assertTrue(getActivationTokenResult is MIRACLSuccess)


        var registrationResult: MIRACLResult<User, RegistrationException>? = null
        miraclTrust.register(
            userId = USER_ID,
            activationToken = (getActivationTokenResult as MIRACLSuccess).value.activationToken,
            pinProvider = pinProvider,
            pushNotificationsToken = null,
            resultHandler = { result -> registrationResult = result }
        )
        testCoroutineDispatcher.scheduler.advanceUntilIdle()
        Assert.assertTrue(registrationResult is MIRACLSuccess)

        val quickCodeGeneratedUser = (registrationResult as MIRACLSuccess).value

        // Act
        var result: MIRACLResult<QuickCode, QuickCodeException>? = null
        miraclTrust.generateQuickCode(quickCodeGeneratedUser, pinProvider) { result = it }
        testCoroutineDispatcher.scheduler.advanceUntilIdle()

        // Assert
        Assert.assertTrue(result is MIRACLError)
        Assert.assertEquals(
            QuickCodeException.LimitedQuickCodeGeneration,
            (result as MIRACLError).value
        )
    }
}