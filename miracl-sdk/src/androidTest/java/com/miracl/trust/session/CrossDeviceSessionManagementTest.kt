package com.miracl.trust.session

import android.net.Uri
import androidx.test.platform.app.InstrumentationRegistry
import com.miracl.trust.BuildConfig
import com.miracl.trust.MIRACLError
import com.miracl.trust.MIRACLResult
import com.miracl.trust.MIRACLSuccess
import com.miracl.trust.MIRACLTrust
import com.miracl.trust.configuration.Configuration
import com.miracl.trust.utilities.MIRACLService
import com.miracl.trust.utilities.randomPinLength
import com.miracl.trust.utilities.randomUuidString
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.runTest
import org.junit.Assert
import org.junit.Before
import org.junit.Test
import kotlin.random.Random

class CrossDeviceSessionManagementTest {
    private val testCoroutineDispatcher = StandardTestDispatcher()

    private val projectId = BuildConfig.CUV_PROJECT_ID
    private val projectUrl = BuildConfig.CUV_PROJECT_URL
    private val userId = randomUuidString()
    private val description = randomUuidString()
    private val hash = randomUuidString()

    private lateinit var miraclTrust: MIRACLTrust
    private lateinit var qrCode: String

    @Before
    fun setUp() = runTest {
        val configuration = Configuration.Builder(projectId, projectUrl)
            .coroutineContext(testCoroutineDispatcher)
            .build()

        MIRACLTrust.configure(InstrumentationRegistry.getInstrumentation().context, configuration)
        miraclTrust = MIRACLTrust.getInstance()
        miraclTrust.resultHandlerDispatcher = testCoroutineDispatcher

        qrCode =
            MIRACLService.obtainAccessId(projectId, projectUrl, userId, description, hash).qrURL
    }

    @Test
    fun testGetCrossDeviceSessionFromAppLink() = runTest {
        // Arrange
        val appLink = Uri.parse(qrCode)
        var result: MIRACLResult<CrossDeviceSession, CrossDeviceSessionException>? = null

        // Act
        miraclTrust.getCrossDeviceSessionFromAppLink(appLink) { result = it }
        testCoroutineDispatcher.scheduler.advanceUntilIdle()

        // Assert
        Assert.assertTrue(result is MIRACLSuccess)

        val session = (result as MIRACLSuccess).value
        Assert.assertEquals(projectId, session.projectId)
        Assert.assertEquals(userId, session.userId)
        Assert.assertEquals(description, session.sessionDescription)
        Assert.assertEquals(hash, session.signingHash)
    }

    @Test
    fun testGetCrossDeviceSessionFromInvalidAppLink() = runTest {
        // Arrange
        val appLink = Uri.parse("")
        var result: MIRACLResult<CrossDeviceSession, CrossDeviceSessionException>? = null

        // Act
        miraclTrust.getCrossDeviceSessionFromAppLink(appLink) { result = it }
        testCoroutineDispatcher.scheduler.advanceUntilIdle()

        // Assert
        Assert.assertTrue(result is MIRACLError)
        Assert.assertEquals(
            CrossDeviceSessionException.InvalidAppLink,
            (result as MIRACLError).value
        )
    }

    @Test
    fun testGetCrossDeviceFromAppLinkInvalidAccessId() = runTest {
        // Arrange
        val qrCode = "https://mcl.mpin.io#InvalidAccessId"
        val appLink = Uri.parse(qrCode)
        var result: MIRACLResult<CrossDeviceSession, CrossDeviceSessionException>? = null

        // Act
        miraclTrust.getCrossDeviceSessionFromAppLink(appLink) { result = it }
        testCoroutineDispatcher.scheduler.advanceUntilIdle()

        // Assert
        Assert.assertTrue(result is MIRACLError)
        Assert.assertTrue((result as MIRACLError).value is CrossDeviceSessionException.GetCrossDeviceSessionFail)
    }

    @Test
    fun testGetCrossDeviceSessionFromQRCode() = runTest {
        // Arrange
        var result: MIRACLResult<CrossDeviceSession, CrossDeviceSessionException>? = null

        // Act
        miraclTrust.getCrossDeviceSessionFromQRCode(qrCode) { result = it }
        testCoroutineDispatcher.scheduler.advanceUntilIdle()

        // Assert
        Assert.assertTrue(result is MIRACLSuccess)

        val session = (result as MIRACLSuccess).value
        Assert.assertEquals(projectId, session.projectId)
        Assert.assertEquals(userId, session.userId)
        Assert.assertEquals(description, session.sessionDescription)
        Assert.assertEquals(hash, session.signingHash)
    }

    @Test
    fun testGetCrossDeviceSessionFromQRCodeMissingURLFragment() = runTest {
        // Arrange
        val qrCode = "https://mcl.mpin.io"
        var result: MIRACLResult<CrossDeviceSession, CrossDeviceSessionException>? = null

        // Act
        miraclTrust.getCrossDeviceSessionFromQRCode(qrCode) { result = it }
        testCoroutineDispatcher.scheduler.advanceUntilIdle()

        // Assert
        Assert.assertTrue(result is MIRACLError)
        Assert.assertEquals(
            CrossDeviceSessionException.InvalidQRCode,
            (result as MIRACLError).value
        )
    }

    @Test
    fun testGetCrossDeviceSessionFromNotificationPayload() = runTest {
        // Arrange
        val payload = mapOf(SessionManager.PUSH_NOTIFICATION_QR_URL to qrCode)
        var result: MIRACLResult<CrossDeviceSession, CrossDeviceSessionException>? = null

        // Act
        miraclTrust.getCrossDeviceSessionFromNotificationPayload(payload) { result = it }
        testCoroutineDispatcher.scheduler.advanceUntilIdle()

        // Assert
        Assert.assertTrue(result is MIRACLSuccess)

        val session = (result as MIRACLSuccess).value
        Assert.assertEquals(projectId, session.projectId)
        Assert.assertEquals(userId, session.userId)
        Assert.assertEquals(description, session.sessionDescription)
        Assert.assertEquals(hash, session.signingHash)
    }

    @Test
    fun testGetCrossDeviceSessionFromNotificationPayloadMissingPayloadEntry() = runTest {
        // Arrange
        val payload = mapOf<String, String>()
        var result: MIRACLResult<CrossDeviceSession, CrossDeviceSessionException>? = null

        // Act
        miraclTrust.getCrossDeviceSessionFromNotificationPayload(payload) { result = it }
        testCoroutineDispatcher.scheduler.advanceUntilIdle()

        // Assert
        Assert.assertTrue(result is MIRACLError)
        Assert.assertEquals(
            CrossDeviceSessionException.InvalidNotificationPayload,
            (result as MIRACLError).value
        )
    }

    @Test
    fun testAbortCrossDeviceSession() = runTest {
        // Arrange
        var crossDeviceSession: CrossDeviceSession? = null
        miraclTrust.getCrossDeviceSessionFromQRCode(qrCode) {
            crossDeviceSession = (it as MIRACLSuccess).value
        }
        testCoroutineDispatcher.scheduler.advanceUntilIdle()
        var result: MIRACLResult<Unit, CrossDeviceSessionException>? = null

        // Act
        miraclTrust.abortCrossDeviceSession(crossDeviceSession!!) { result = it }
        testCoroutineDispatcher.scheduler.advanceUntilIdle()

        // Assert
        Assert.assertTrue(result is MIRACLSuccess)
    }

    @Test
    fun testAbortCrossDeviceSessionEmptySessionId() = runTest {
        // Arrange
        val crossDeviceSession = CrossDeviceSession(
            sessionId = "",
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
            signingHash = randomUuidString()
        )
        var result: MIRACLResult<Unit, CrossDeviceSessionException>? = null

        // Act
        miraclTrust.abortCrossDeviceSession(crossDeviceSession) { result = it }
        testCoroutineDispatcher.scheduler.advanceUntilIdle()

        // Assert
        Assert.assertTrue(result is MIRACLError)
        Assert.assertEquals(
            CrossDeviceSessionException.InvalidCrossDeviceSession,
            (result as MIRACLError).value
        )
    }
}