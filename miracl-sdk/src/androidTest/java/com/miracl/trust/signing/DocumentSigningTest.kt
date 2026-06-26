package com.miracl.trust.signing

import android.util.Base64
import androidx.test.platform.app.InstrumentationRegistry
import com.miracl.trust.BuildConfig
import com.miracl.trust.MIRACLError
import com.miracl.trust.MIRACLSuccess
import com.miracl.trust.MIRACLTrust
import com.miracl.trust.configuration.Configuration
import com.miracl.trust.delegate.PinProvider
import com.miracl.trust.model.User
import com.miracl.trust.util.json.KotlinxSerializationJsonUtil
import com.miracl.trust.util.secondsSince1970
import com.miracl.trust.util.toHexString
import com.miracl.trust.utilities.JwtHelper
import com.miracl.trust.utilities.MIRACLService
import com.miracl.trust.utilities.USER_ID
import com.miracl.trust.utilities.USER_PIN_LENGTH
import com.miracl.trust.utilities.WRONG_FORMAT_PIN
import com.miracl.trust.utilities.generateWrongPin
import com.miracl.trust.utilities.randomHash
import com.miracl.trust.utilities.randomNumericPin
import com.miracl.trust.utilities.randomUuidString
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.runTest
import org.junit.Assert
import org.junit.Before
import org.junit.Test

class DocumentSigningTest {
    private val projectId = BuildConfig.CUV_PROJECT_ID
    private val projectUrl = BuildConfig.CUV_PROJECT_URL
    private val serviceAccountToken = BuildConfig.CUV_SERVICE_ACCOUNT_TOKEN

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
        miraclTrust.resultHandlerDispatcher = testCoroutineDispatcher

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
    fun testSuccessfulDocumentSigning() = runTest(testCoroutineDispatcher) {
        // Sign
        val message = randomHash()
        val result = miraclTrust.sign(
            message = message,
            user = user,
            pinProvider = pinProvider
        )
        Assert.assertTrue(result is MIRACLSuccess)

        // Verify the signature
        val signingResult = (result as MIRACLSuccess).value
        val verifySignatureResponse = MIRACLService.verifySignature(
            projectId = projectId,
            projectUrl = projectUrl,
            serviceAccountToken = serviceAccountToken,
            signature = signingResult.signature,
            timestamp = signingResult.timestamp.secondsSince1970()
        )

        val jwks = MIRACLService.getDvsJwkSet(projectUrl)
        val claims = JwtHelper.parseSignedClaims(verifySignatureResponse.certificate, jwks)
        Assert.assertEquals(message.toHexString(), claims.payload["hash"])
    }

    @Test
    fun testSuccessfulCrossDeviceSessionSigning() = runTest(testCoroutineDispatcher) {
        // Arrange
        val createSessionResponse = MIRACLService.obtainAccessId(
            projectId = projectId,
            projectUrl = projectUrl,
            userId = USER_ID,
            hash = randomHash().toHexString(),
            description = randomUuidString()
        )

        val getCrossDeviceSessionResult =
            miraclTrust.getCrossDeviceSessionFromQRCode(createSessionResponse.qrURL)
        Assert.assertTrue(getCrossDeviceSessionResult is MIRACLSuccess)

        val crossDeviceSession = (getCrossDeviceSessionResult as MIRACLSuccess).value

        // Act
        val result = miraclTrust.signCrossDeviceSession(
            crossDeviceSession = crossDeviceSession,
            user = user,
            pinProvider = pinProvider
        )

        // Assert
        Assert.assertTrue(result is MIRACLSuccess)

        val sessionStatusResponse =
            MIRACLService.getSessionStatus(projectUrl, createSessionResponse.webOTT)

        val signatureJson = String(Base64.decode(sessionStatusResponse.signature, Base64.NO_WRAP))
        val signature = KotlinxSerializationJsonUtil.fromJsonString<Signature>(signatureJson)
        Assert.assertEquals(crossDeviceSession.signingHash, signature.hash)

        val verifySignatureResponse = MIRACLService.verifySignature(
            projectId = projectId,
            projectUrl = projectUrl,
            serviceAccountToken = serviceAccountToken,
            signature = signature,
            timestamp = signature.timestamp
        )

        val jwks = MIRACLService.getDvsJwkSet(projectUrl)
        val claims = JwtHelper.parseSignedClaims(verifySignatureResponse.certificate, jwks)
        Assert.assertEquals(crossDeviceSession.signingHash, claims.payload["hash"])
    }

    @Test
    fun testSigningFailOnEmptyMessage() = runTest(testCoroutineDispatcher) {
        // Arrange
        val emptyMessage = "".toByteArray()

        // Act
        val signingResult = miraclTrust.sign(
            message = emptyMessage,
            user = user,
            pinProvider = pinProvider
        )

        // Assert
        Assert.assertTrue(signingResult is MIRACLError)
        Assert.assertEquals(SigningException.EmptyMessageHash, (signingResult as MIRACLError).value)
    }

    @Test
    fun testSigningFailOnEmptyPin() = runTest(testCoroutineDispatcher) {
        // Arrange
        val emptyPinProvider = PinProvider { pinConsumer -> pinConsumer.consume(null) }

        // Act
        val signingResult = miraclTrust.sign(
            message = randomHash(),
            user = user,
            pinProvider = emptyPinProvider
        )

        // Assert
        Assert.assertTrue(signingResult is MIRACLError)
        Assert.assertEquals(SigningException.PinCancelled, (signingResult as MIRACLError).value)
    }

    @Test
    fun testSigningFailOnShorterPin() = runTest(testCoroutineDispatcher) {
        // Arrange
        val shorterPinProvider = PinProvider { pinConsumer ->
            pinConsumer.consume(randomNumericPin(USER_PIN_LENGTH - 1))
        }

        // Act
        val signingResult = miraclTrust.sign(
            message = randomHash(),
            user = user,
            pinProvider = shorterPinProvider
        )

        // Assert
        Assert.assertTrue(signingResult is MIRACLError)
        Assert.assertEquals(SigningException.InvalidPin, (signingResult as MIRACLError).value)
    }

    @Test
    fun testSigningFailOnLongerPin() = runTest(testCoroutineDispatcher) {
        // Arrange
        val longerPinProvider = PinProvider { pinConsumer ->
            pinConsumer.consume(randomNumericPin(USER_PIN_LENGTH + 1))
        }

        // Act
        val signingResult = miraclTrust.sign(
            message = randomHash(),
            user = user,
            pinProvider = longerPinProvider
        )

        // Assert
        Assert.assertTrue(signingResult is MIRACLError)
        Assert.assertEquals(SigningException.InvalidPin, (signingResult as MIRACLError).value)
    }

    @Test
    fun testSigningFailOnWrongFormatPin() = runTest(testCoroutineDispatcher) {
        // Arrange
        val wrongFormatPinProvider = PinProvider { pinConsumer ->
            pinConsumer.consume(WRONG_FORMAT_PIN)
        }

        // Act
        val signingResult = miraclTrust.sign(
            message = randomHash(),
            user = user,
            pinProvider = wrongFormatPinProvider
        )

        // Assert
        Assert.assertTrue(signingResult is MIRACLError)
        Assert.assertEquals(SigningException.InvalidPin, (signingResult as MIRACLError).value)
    }

    @Test
    fun testSigningFailOnWrongPin() = runTest(testCoroutineDispatcher) {
        // Arrange
        val wrongPinProvider = PinProvider { pinConsumer ->
            pinConsumer.consume(generateWrongPin(pin))
        }

        // Act
        val signingResult = miraclTrust.sign(
            message = randomHash(),
            user = user,
            pinProvider = wrongPinProvider
        )

        // Assert
        Assert.assertTrue(signingResult is MIRACLError)
        Assert.assertEquals(
            SigningException.UnsuccessfulAuthentication,
            (signingResult as MIRACLError).value
        )
    }

    @Test
    fun testSigningFailOnRevokedUser() = runTest(testCoroutineDispatcher) {
        // Arrange
        val wrongPinProvider = PinProvider { pinConsumer ->
            pinConsumer.consume(generateWrongPin(pin))
        }

        var signingResult = miraclTrust.sign(
            message = randomHash(),
            user = user,
            pinProvider = wrongPinProvider
        )
        Assert.assertTrue(signingResult is MIRACLError)
        Assert.assertEquals(
            SigningException.UnsuccessfulAuthentication,
            (signingResult as MIRACLError).value
        )

        signingResult = miraclTrust.sign(
            message = randomHash(),
            user = user,
            pinProvider = wrongPinProvider
        )
        Assert.assertTrue(signingResult is MIRACLError)
        Assert.assertEquals(
            SigningException.UnsuccessfulAuthentication,
            (signingResult as MIRACLError).value
        )

        signingResult = miraclTrust.sign(
            message = randomHash(),
            user = user,
            pinProvider = wrongPinProvider
        )
        Assert.assertTrue(signingResult is MIRACLError)
        Assert.assertEquals(SigningException.Revoked, (signingResult as MIRACLError).value)

        user = miraclTrust.getUser(user.userId)!!
        Assert.assertTrue(user.revoked)

        // Act
        signingResult = miraclTrust.sign(
            message = randomHash(),
            user = user,
            pinProvider = pinProvider
        )

        // Assert
        Assert.assertTrue(signingResult is MIRACLError)
        Assert.assertEquals(SigningException.Revoked, (signingResult as MIRACLError).value)
    }
}