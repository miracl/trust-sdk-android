package com.miracl.trust.session

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
import com.miracl.trust.utilities.randomHash
import com.miracl.trust.utilities.randomNumericPin
import com.miracl.trust.utilities.randomUuidString
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.runTest
import org.junit.Assert
import org.junit.Before
import org.junit.Test

class CrossDeviceSessionManagementTest {
    private val testCoroutineDispatcher = StandardTestDispatcher()

    private val projectId = BuildConfig.CUV_PROJECT_ID
    private val projectUrl = BuildConfig.CUV_PROJECT_URL
    private val userId = randomUuidString()
    private val description = randomUuidString()
    private val hash = randomHash().toHexString()

    private lateinit var miraclTrust: MIRACLTrust
    private lateinit var qrCode: String
    private lateinit var pinProvider: PinProvider
    private lateinit var user: User

    @Before
    fun setUp() = runTest(testCoroutineDispatcher) {
        val configuration = Configuration.Builder(projectId, projectUrl)
            .coroutineContext(testCoroutineDispatcher)
            .build()

        MIRACLTrust.configure(InstrumentationRegistry.getInstrumentation().context, configuration)
        miraclTrust = MIRACLTrust.getInstance()

        qrCode =
            MIRACLService.obtainAccessId(projectId, projectUrl, userId, description, hash).qrURL

        val pin = randomNumericPin()
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
    fun testGetCrossDeviceSessionFromAppLink() = runTest(testCoroutineDispatcher) {
        // Arrange
        val appLink = Uri.parse(qrCode)

        // Act
        val result = miraclTrust.getCrossDeviceSessionFromAppLink(appLink)

        // Assert
        Assert.assertTrue(result is MIRACLSuccess)

        val session = (result as MIRACLSuccess).value
        Assert.assertEquals(projectId, session.projectId)
        Assert.assertEquals(userId, session.userId)
        Assert.assertEquals(description, session.sessionDescription)
        Assert.assertEquals(hash, session.signingHash)
    }

    @Test
    fun testGetCrossDeviceSessionFromInvalidAppLink() = runTest(testCoroutineDispatcher) {
        // Arrange
        val appLink = Uri.parse("")

        // Act
        val result = miraclTrust.getCrossDeviceSessionFromAppLink(appLink)

        // Assert
        Assert.assertTrue(result is MIRACLError)
        Assert.assertEquals(
            CrossDeviceSessionException.InvalidAppLink,
            (result as MIRACLError).value
        )
    }

    @Test
    fun testGetCrossDeviceFromAppLinkInvalidAccessId() = runTest(testCoroutineDispatcher) {
        // Arrange
        val qrCode = "https://mcl.mpin.io#InvalidAccessId"
        val appLink = Uri.parse(qrCode)

        // Act
        val result = miraclTrust.getCrossDeviceSessionFromAppLink(appLink)

        // Assert
        Assert.assertTrue(result is MIRACLError)
        Assert.assertTrue((result as MIRACLError).value is CrossDeviceSessionException.GetCrossDeviceSessionFail)
    }

    @Test
    fun testGetCrossDeviceSessionFromQRCode() = runTest(testCoroutineDispatcher) {
        // Act
        val result = miraclTrust.getCrossDeviceSessionFromQRCode(qrCode)

        // Assert
        Assert.assertTrue(result is MIRACLSuccess)

        val session = (result as MIRACLSuccess).value
        Assert.assertEquals(projectId, session.projectId)
        Assert.assertEquals(userId, session.userId)
        Assert.assertEquals(description, session.sessionDescription)
        Assert.assertEquals(hash, session.signingHash)
    }

    @Test
    fun testGetCrossDeviceSessionFromQRCodeMissingURLFragment() = runTest(testCoroutineDispatcher) {
        // Arrange
        val qrCode = "https://mcl.mpin.io"

        // Act
        val result = miraclTrust.getCrossDeviceSessionFromQRCode(qrCode)

        // Assert
        Assert.assertTrue(result is MIRACLError)
        Assert.assertEquals(
            CrossDeviceSessionException.InvalidQRCode,
            (result as MIRACLError).value
        )
    }

    @Test
    fun testGetCrossDeviceSessionFromNotificationPayload() = runTest(testCoroutineDispatcher) {
        // Arrange
        val payload = mapOf(SessionManager.PUSH_NOTIFICATION_QR_URL to qrCode)

        // Act
        val result = miraclTrust.getCrossDeviceSessionFromNotificationPayload(payload)

        // Assert
        Assert.assertTrue(result is MIRACLSuccess)

        val session = (result as MIRACLSuccess).value
        Assert.assertEquals(projectId, session.projectId)
        Assert.assertEquals(userId, session.userId)
        Assert.assertEquals(description, session.sessionDescription)
        Assert.assertEquals(hash, session.signingHash)
    }

    @Test
    fun testGetCrossDeviceSessionFromNotificationPayloadMissingPayloadEntry() =
        runTest(testCoroutineDispatcher) {
            // Arrange
            val payload = mapOf<String, String>()

            // Act
            val result = miraclTrust.getCrossDeviceSessionFromNotificationPayload(payload)

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertEquals(
                CrossDeviceSessionException.InvalidNotificationPayload,
                (result as MIRACLError).value
            )
        }

    @Test
    fun testAbortCrossDeviceSession() = runTest(testCoroutineDispatcher) {
        // Arrange
        val crossDeviceSession: CrossDeviceSession =
            (miraclTrust.getCrossDeviceSessionFromQRCode(qrCode) as MIRACLSuccess).value

        // Act
        val result = miraclTrust.abortCrossDeviceSession(crossDeviceSession)

        // Assert
        Assert.assertTrue(result is MIRACLSuccess)
    }

    @Test
    fun testAbortCrossDeviceSessionEmptySessionId() = runTest(testCoroutineDispatcher) {
        // Arrange
        val crossDeviceSession = CrossDeviceSession(
            sessionId = "",
            sessionDescription = randomUuidString(),
            userId = randomUuidString(),
            projectId = randomUuidString(),
            signingHash = randomUuidString()
        )

        // Act
        val result = miraclTrust.abortCrossDeviceSession(crossDeviceSession)

        // Assert
        Assert.assertTrue(result is MIRACLError)
        Assert.assertEquals(
            CrossDeviceSessionException.InvalidCrossDeviceSession,
            (result as MIRACLError).value
        )
    }

    @Test
    fun testAuthenticateWithCrossDeviceSession() = runTest(testCoroutineDispatcher) {
        // Get the session
        val crossDeviceSession =
            (miraclTrust.getCrossDeviceSessionFromQRCode(qrCode) as MIRACLSuccess).value

        // Authenticate
        val result =
            miraclTrust.authenticateWithCrossDeviceSession(crossDeviceSession, user, pinProvider)

        // Assert
        Assert.assertTrue(result is MIRACLSuccess)
    }

    @Test
    fun testSignWithCrossDeviceSession() = runTest(testCoroutineDispatcher) {
        // Get the session
        val crossDeviceSession =
            (miraclTrust.getCrossDeviceSessionFromQRCode(qrCode) as MIRACLSuccess).value

        // Sign
        val result = miraclTrust.signWithCrossDeviceSession(crossDeviceSession, user, pinProvider)

        // Assert
        Assert.assertTrue(result is MIRACLSuccess)
    }

    @Test
    fun testAuthorizeCrossDeviceSession() = runTest(testCoroutineDispatcher) {
        // Get the session
        val crossDeviceSession =
            (miraclTrust.getCrossDeviceSessionFromQRCode(qrCode) as MIRACLSuccess).value

        // Authorize the session
        val result = miraclTrust.authorizeCrossDeviceSession(crossDeviceSession, user, pinProvider)

        // Assert
        Assert.assertTrue(result is MIRACLSuccess)
    }

    @Test
    fun testCompleteAuthenticationCrossDeviceSession() = runTest(testCoroutineDispatcher) {
        // Get the session
        val crossDeviceSession =
            (miraclTrust.getCrossDeviceSessionFromQRCode(qrCode) as MIRACLSuccess).value

        // Authenticate
        val authenticationResult = miraclTrust.generateAuthenticationToken(user, pinProvider)
        val authenticationToken = (authenticationResult as MIRACLSuccess).value

        // Complete the session
        val result = miraclTrust.completeCrossDeviceSession(
            crossDeviceSession.sessionId,
            authenticationToken
        )

        // Assert
        Assert.assertTrue(result is MIRACLSuccess)
    }

    @Test
    fun testCompleteSigningCrossDeviceSession() = runTest(testCoroutineDispatcher) {
        // Get the session
        val crossDeviceSession =
            (miraclTrust.getCrossDeviceSessionFromQRCode(qrCode) as MIRACLSuccess).value

        // Sign
        val signResult =
            miraclTrust.generateSignature(crossDeviceSession.signingHash.toByteArray(), user, pinProvider)
        val signingResult = (signResult as MIRACLSuccess).value

        // Complete the session
        val result = miraclTrust.completeCrossDeviceSession(
            sessionId = crossDeviceSession.sessionId,
            signingResult = signingResult
        )

        // Assert
        Assert.assertTrue(result is MIRACLSuccess)
    }
}