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
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.StandardTestDispatcher
import org.junit.Assert
import org.junit.Before
import org.junit.Test
import kotlin.random.Random

class CrossDeviceSessionManagementTest {
    private val projectId = BuildConfig.CUV_PROJECT_ID

    private val testCoroutineDispatcher = StandardTestDispatcher()

    private lateinit var miraclTrust: MIRACLTrust

    @Before
    fun setUp() = runBlocking {
        val configuration = Configuration.Builder(projectId)
            .platformUrl(BuildConfig.BASE_URL)
            .coroutineContext(testCoroutineDispatcher)
            .build()

        MIRACLTrust.configure(InstrumentationRegistry.getInstrumentation().context, configuration)
        miraclTrust = MIRACLTrust.getInstance()
        miraclTrust.resultHandlerDispatcher = testCoroutineDispatcher
    }

    @Test
    fun testGetCrossDeviceSessionFromAppLink() = runBlocking {
        // Arrange
        val appLink = Uri.parse(MIRACLService.obtainAccessId(projectId).qrURL)
        var result: MIRACLResult<CrossDeviceSession, CrossDeviceSessionException>? = null

        // Act
        miraclTrust.getCrossDeviceSessionFromAppLink(appLink) { result = it }
        testCoroutineDispatcher.scheduler.advanceUntilIdle()

        // Assert
        Assert.assertTrue(result is MIRACLSuccess)
        Assert.assertEquals(projectId, (result as MIRACLSuccess).value.projectId)
    }

    @Test
    fun testGetCrossDeviceSessionFromInvalidAppLink() = runBlocking {
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
    fun testGetCrossDeviceFromAppLinkInvalidAccessId() = runBlocking {
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
    fun testGetCrossDeviceSessionFromQRCode() = runBlocking {
        // Arrange
        val qrCode = MIRACLService.obtainAccessId(projectId).qrURL
        var result: MIRACLResult<CrossDeviceSession, CrossDeviceSessionException>? = null

        // Act
        miraclTrust.getCrossDeviceSessionFromQRCode(qrCode) { result = it }
        testCoroutineDispatcher.scheduler.advanceUntilIdle()

        // Assert
        Assert.assertTrue(result is MIRACLSuccess)
        Assert.assertEquals(projectId, (result as MIRACLSuccess).value.projectId)
    }

    @Test
    fun testGetCrossDeviceSessionFromQRCodeMissingURLFragment() = runBlocking {
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
    fun testGetCrossDeviceSessionFromNotificationPayload() = runBlocking {
        // Arrange
        val qrCode = MIRACLService.obtainAccessId(projectId).qrURL
        val payload = mapOf(SessionManager.PUSH_NOTIFICATION_QR_URL to qrCode)
        var result: MIRACLResult<CrossDeviceSession, CrossDeviceSessionException>? = null

        // Act
        miraclTrust.getCrossDeviceSessionFromNotificationPayload(payload) { result = it }
        testCoroutineDispatcher.scheduler.advanceUntilIdle()

        // Assert
        Assert.assertTrue(result is MIRACLSuccess)
        Assert.assertEquals(projectId, (result as MIRACLSuccess).value.projectId)
    }

    @Test
    fun testGetCrossDeviceSessionFromNotificationPayloadMissingPayloadEntry() = runBlocking {
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
    fun testAbortCrossDeviceSession() = runBlocking {
        // Arrange
        val qrCode = MIRACLService.obtainAccessId(projectId).qrURL
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
    fun testAbortCrossDeviceSessionEmptySessionId() = runBlocking {
        // Arrange
        val crossDeviceSession = CrossDeviceSession(
            sessionId = "",
            description = randomUuidString(),
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
            limitQuickCodeRegistration = Random.nextBoolean(),
            hash = randomUuidString()
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