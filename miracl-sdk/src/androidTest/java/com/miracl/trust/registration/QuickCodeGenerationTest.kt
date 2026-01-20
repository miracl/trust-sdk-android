package com.miracl.trust.registration

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

class QuickCodeGenerationTest {
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
    fun testSuccessfulQuickCodeGeneration() = runTest(testCoroutineDispatcher) {
        val result = miraclTrust.generateQuickCode(user, pinProvider)
        Assert.assertTrue(result is MIRACLSuccess)
    }

    @Test
    fun testQuickCodeGenerationFailOnEmptyPin() = runTest(testCoroutineDispatcher) {
        // Arrange
        val emptyPinProvider = PinProvider { it.consume(null) }

        // Act
        val result = miraclTrust.generateQuickCode(user, emptyPinProvider)

        // Assert
        Assert.assertTrue(result is MIRACLError)
        Assert.assertEquals(
            QuickCodeException.PinCancelled,
            (result as MIRACLError).value
        )
    }

    @Test
    fun testQuickCodeGenerationFailOnShorterPin() = runTest(testCoroutineDispatcher) {
        // Arrange
        val shorterPinProvider = PinProvider { it.consume(randomNumericPin(pin.length - 1)) }

        // Act
        val result = miraclTrust.generateQuickCode(user, shorterPinProvider)

        // Assert
        Assert.assertTrue(result is MIRACLError)
        Assert.assertEquals(
            QuickCodeException.InvalidPin,
            (result as MIRACLError).value
        )
    }

    @Test
    fun testQuickCodeGenerationFailOnLongerPin() = runTest(testCoroutineDispatcher) {
        // Arrange
        val longerPinProvider = PinProvider { it.consume(randomNumericPin(pin.length + 1)) }

        // Act
        val result = miraclTrust.generateQuickCode(user, longerPinProvider)

        // Assert
        Assert.assertTrue(result is MIRACLError)
        Assert.assertEquals(
            QuickCodeException.InvalidPin,
            (result as MIRACLError).value
        )
    }

    @Test
    fun testQuickCodeGenerationFailOnWrongFormatPin() = runTest(testCoroutineDispatcher) {
        // Arrange
        val wrongFormatPinProvider = PinProvider { it.consume(WRONG_FORMAT_PIN) }

        // Act
        val result = miraclTrust.generateQuickCode(user, wrongFormatPinProvider)

        // Assert
        Assert.assertTrue(result is MIRACLError)
        Assert.assertEquals(
            QuickCodeException.InvalidPin,
            (result as MIRACLError).value
        )
    }

    @Test
    fun testQuickCodeGenerationFailOnWrongPin() = runTest(testCoroutineDispatcher) {
        // Arrange
        val wrongPinProvider = PinProvider { it.consume(generateWrongPin(pin)) }

        // Act
        val result = miraclTrust.generateQuickCode(user, wrongPinProvider)

        // Assert
        Assert.assertTrue(result is MIRACLError)
        Assert.assertEquals(
            QuickCodeException.UnsuccessfulAuthentication,
            (result as MIRACLError).value
        )
    }

    @Test
    fun testQuickCodeGenerationFailOnRevokedUser() = runTest(testCoroutineDispatcher) {
        // Arrange
        val wrongPinProvider = PinProvider { it.consume(generateWrongPin(pin)) }

        var result = miraclTrust.generateQuickCode(user, wrongPinProvider)
        Assert.assertTrue(result is MIRACLError)
        Assert.assertEquals(
            QuickCodeException.UnsuccessfulAuthentication,
            (result as MIRACLError).value
        )

        result = miraclTrust.generateQuickCode(user, wrongPinProvider)
        Assert.assertTrue(result is MIRACLError)
        Assert.assertEquals(
            QuickCodeException.UnsuccessfulAuthentication,
            (result as MIRACLError).value
        )

        result = miraclTrust.generateQuickCode(user, wrongPinProvider)
        Assert.assertTrue(result is MIRACLError)
        Assert.assertEquals(QuickCodeException.Revoked, (result as MIRACLError).value)

        Assert.assertTrue(miraclTrust.getUser(user.userId)!!.revoked)

        // Act
        result = miraclTrust.generateQuickCode(user, pinProvider)

        // Assert
        Assert.assertTrue(result is MIRACLError)
        Assert.assertEquals(QuickCodeException.Revoked, (result as MIRACLError).value)
    }
}