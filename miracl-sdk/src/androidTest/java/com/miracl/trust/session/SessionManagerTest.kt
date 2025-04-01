package com.miracl.trust.session

import android.net.Uri
import com.miracl.trust.BuildConfig
import com.miracl.trust.MIRACLError
import com.miracl.trust.MIRACLSuccess
import com.miracl.trust.network.ApiRequestExecutor
import com.miracl.trust.network.ApiSettings
import com.miracl.trust.network.HttpsURLConnectionRequestExecutor
import com.miracl.trust.util.json.KotlinxSerializationJsonUtil
import com.miracl.trust.utilities.AccessIdResponse
import com.miracl.trust.utilities.MIRACLService
import com.miracl.trust.utilities.randomPinLength
import com.miracl.trust.utilities.randomUuidString
import kotlinx.coroutines.runBlocking
import org.junit.Assert
import org.junit.Before
import org.junit.Test
import kotlin.random.Random

class SessionManagerTest {
    private val projectId = BuildConfig.CUV_PROJECT_ID

    private lateinit var sessionManager: SessionManager

    @Before
    fun setUp() = runBlocking {
        val httpRequestExecutor = HttpsURLConnectionRequestExecutor(10, 10)
        val apiSettings = ApiSettings(BuildConfig.BASE_URL)
        val apiRequestExecutor =
            ApiRequestExecutor(httpRequestExecutor, KotlinxSerializationJsonUtil)

        val sessionApi =
            SessionApiManager(apiRequestExecutor, KotlinxSerializationJsonUtil, apiSettings)
        sessionManager = SessionManager(sessionApi)
    }

    @Test
    fun testGetSessionDetailsAppLink() = runBlocking {
        // Arrange
        val appLink = Uri.parse(getQRCode().qrURL)

        // Act
        val result = sessionManager.getSessionDetailsFromAppLink(appLink)

        // Assert
        Assert.assertTrue(result is MIRACLSuccess)
        Assert.assertEquals(projectId, (result as MIRACLSuccess).value.projectId)
    }

    @Test
    fun testGetSessionDetailsForInvalidAppLink() = runBlocking {
        // Arrange
        val appLink = Uri.parse("")

        // Act
        val result = sessionManager.getSessionDetailsFromAppLink(appLink)

        // Assert
        Assert.assertTrue(result is MIRACLError)
        Assert.assertEquals(
            AuthenticationSessionException.InvalidAppLink,
            (result as MIRACLError).value
        )
    }

    @Test
    fun testGetSessionDetailsForInvalidAccessId() = runBlocking {
        // Arrange
        val qrCode = "https://mcl.mpin.io#InvalidAccessId"
        val appLink = Uri.parse(qrCode)

        // Act
        val result = sessionManager.getSessionDetailsFromAppLink(appLink)

        // Assert
        Assert.assertTrue(result is MIRACLError)
        Assert.assertTrue((result as MIRACLError).value is AuthenticationSessionException.GetAuthenticationSessionDetailsFail)
    }

    @Test
    fun testGetSessionDetailsQRCode() = runBlocking {
        // Arrange
        val qrCode = getQRCode().qrURL

        // Act
        val result = sessionManager.getSessionDetailsFromQRCode(qrCode)

        // Assert
        Assert.assertTrue(result is MIRACLSuccess)
        Assert.assertEquals(projectId, (result as MIRACLSuccess).value.projectId)
    }

    @Test
    fun testGetSessionDetailsQRCodeMissingURLFragment() = runBlocking {
        // Arrange
        val qrCode = "https://mcl.mpin.io"

        // Act
        val result = sessionManager.getSessionDetailsFromQRCode(qrCode)

        // Assert
        Assert.assertTrue(result is MIRACLError)
        Assert.assertEquals(
            AuthenticationSessionException.InvalidQRCode,
            (result as MIRACLError).value
        )
    }

    @Test
    fun testGetSessionDetailsNotificationPayload() = runBlocking {
        // Arrange
        val qrCode = getQRCode().qrURL
        val payload = mapOf(SessionManager.PUSH_NOTIFICATION_QR_URL to qrCode)

        // Act
        val result = sessionManager.getSessionDetailsFromNotificationPayload(payload)

        // Assert
        Assert.assertTrue(result is MIRACLSuccess)
        Assert.assertEquals(projectId, (result as MIRACLSuccess).value.projectId)
    }

    @Test
    fun testGetSessionDetailsFromNotificationPayloadMissingPayloadEntry() = runBlocking {
        // Arrange
        val payload = mapOf<String, String>()

        // Act
        val result = sessionManager.getSessionDetailsFromNotificationPayload(payload)

        // Assert
        Assert.assertTrue(result is MIRACLError)
        Assert.assertEquals(
            AuthenticationSessionException.InvalidNotificationPayload,
            (result as MIRACLError).value
        )
    }

    @Test
    fun testAbortSession() = runBlocking {
        // Arrange
        val qrCode = getQRCode().qrURL
        val getSessionDetailsResult = sessionManager.getSessionDetailsFromQRCode(qrCode)
        val sessionDetails = (getSessionDetailsResult as MIRACLSuccess).value

        // Act
        val result = sessionManager.abortSession(sessionDetails)

        // Assert
        Assert.assertTrue(result is MIRACLSuccess)
    }

    @Test
    fun testAbortSessionEmptyAccessId() = runBlocking {
        // Arrange
        val authenticationSessionDetails = AuthenticationSessionDetails(
            accessId = "",
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
            limitQuickCodeRegistration = Random.nextBoolean()
        )

        // Act
        val result = sessionManager.abortSession(authenticationSessionDetails)

        // Assert
        Assert.assertTrue(result is MIRACLError)
        Assert.assertEquals(
            AuthenticationSessionException.InvalidSessionDetails,
            (result as MIRACLError).value
        )
    }

    private suspend fun getQRCode(): AccessIdResponse {
        return MIRACLService.obtainAccessId(projectId)
    }
}