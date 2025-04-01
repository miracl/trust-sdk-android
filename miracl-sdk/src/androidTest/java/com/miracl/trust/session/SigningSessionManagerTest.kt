package com.miracl.trust.session

import android.net.Uri
import com.miracl.trust.BuildConfig
import com.miracl.trust.MIRACLError
import com.miracl.trust.MIRACLSuccess
import com.miracl.trust.network.ApiRequestExecutor
import com.miracl.trust.network.ApiSettings
import com.miracl.trust.network.HttpsURLConnectionRequestExecutor
import com.miracl.trust.util.json.KotlinxSerializationJsonUtil
import com.miracl.trust.utilities.MIRACLService
import com.miracl.trust.utilities.SigningSessionCreateResponse
import com.miracl.trust.utilities.USER_ID
import com.miracl.trust.utilities.randomPinLength
import com.miracl.trust.utilities.randomUuidString
import kotlinx.coroutines.runBlocking
import org.junit.Assert
import org.junit.Before
import org.junit.Test
import kotlin.random.Random

class SigningSessionManagerTest {
    private val projectId = BuildConfig.CUV_PROJECT_ID

    private lateinit var signingSessionManager: SigningSessionManager

    @Before
    fun setUp() = runBlocking {
        val httpRequestExecutor = HttpsURLConnectionRequestExecutor(10, 10)
        val apiSettings = ApiSettings(BuildConfig.BASE_URL)
        val apiRequestExecutor =
            ApiRequestExecutor(httpRequestExecutor, KotlinxSerializationJsonUtil)

        val signingSessionApi =
            SigningSessionApiManager(apiRequestExecutor, KotlinxSerializationJsonUtil, apiSettings)
        signingSessionManager = SigningSessionManager(signingSessionApi)
    }

    @Test
    fun testGetSigningSessionDetailsAppLink() = runBlocking {
        // Arrange
        val hash = randomUuidString()
        val description = randomUuidString()
        val appLink = Uri.parse(createSigningSession(hash, description).qrURL)

        // Act
        val result = signingSessionManager.getSigningSessionDetailsFromAppLink(appLink)

        // Assert
        Assert.assertTrue(result is MIRACLSuccess)
        Assert.assertEquals(hash, (result as MIRACLSuccess).value.signingHash)
        Assert.assertEquals(description, result.value.signingDescription)
        Assert.assertEquals(projectId, result.value.projectId)
    }

    @Test
    fun testGetSigningSessionDetailsForInvalidAppLink() = runBlocking {
        // Arrange
        val appLink = Uri.parse("")

        // Act
        val result = signingSessionManager.getSigningSessionDetailsFromAppLink(appLink)

        // Assert
        Assert.assertTrue(result is MIRACLError)
        Assert.assertEquals(
            SigningSessionException.InvalidAppLink,
            (result as MIRACLError).value
        )
    }

    @Test
    fun testGetSigningSessionDetailsForInvalidAccessId() = runBlocking {
        // Arrange
        val qrCode = "https://mcl.mpin.io/dvs/#invalidSessionId"
        val appLink = Uri.parse(qrCode)

        // Act
        val result = signingSessionManager.getSigningSessionDetailsFromAppLink(appLink)

        // Assert
        Assert.assertTrue(result is MIRACLError)
        val exception = (result as MIRACLError).value
        Assert.assertTrue(exception is SigningSessionException.InvalidSigningSession)
    }

    @Test
    fun testGetSigningSessionDetailsQRCode() = runBlocking {
        // Arrange
        val hash = randomUuidString()
        val description = randomUuidString()
        val qrCode = createSigningSession(hash, description).qrURL

        // Act
        val result = signingSessionManager.getSigningSessionDetailsFromQRCode(qrCode)

        // Assert
        Assert.assertTrue(result is MIRACLSuccess)
        Assert.assertEquals(hash, (result as MIRACLSuccess).value.signingHash)
        Assert.assertEquals(description, result.value.signingDescription)
        Assert.assertEquals(projectId, result.value.projectId)
    }

    @Test
    fun testGetSigningSessionDetailsQRCodeMissingURLFragment() = runBlocking {
        // Arrange
        val qrCode = "https://mcl.mpin.io/dvs"

        // Act
        val result = signingSessionManager.getSigningSessionDetailsFromQRCode(qrCode)

        // Assert
        Assert.assertTrue(result is MIRACLError)
        Assert.assertEquals(
            SigningSessionException.InvalidQRCode,
            (result as MIRACLError).value
        )
    }

    @Test
    fun testAbortSigningSession() = runBlocking {
        // Arrange
        val qrCode = createSigningSession().qrURL
        val getSigningSessionDetailsResult =
            signingSessionManager.getSigningSessionDetailsFromQRCode(qrCode)

        Assert.assertTrue(getSigningSessionDetailsResult is MIRACLSuccess)
        val signingSessionDetails = (getSigningSessionDetailsResult as MIRACLSuccess).value

        // Act
        val result = signingSessionManager.abortSigningSession(signingSessionDetails)

        // Assert
        Assert.assertTrue(result is MIRACLSuccess)
    }

    @Test
    fun testAbortSigningSessionInvalidSessionId() = runBlocking {
        // Arrange
        val signingSessionDetails = SigningSessionDetails(
            sessionId = "invalidSessionId",
            signingHash = randomUuidString(),
            signingDescription = randomUuidString(),
            status = SigningSessionStatus.Active,
            expireTime = 0,
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
        val result = signingSessionManager.abortSigningSession(signingSessionDetails)

        // Assert
        Assert.assertTrue(result is MIRACLError)
        Assert.assertEquals(
            SigningSessionException.InvalidSigningSession,
            (result as MIRACLError).value
        )
    }

    private fun createSigningSession(
        hash: String = randomUuidString(),
        description: String = randomUuidString()
    ): SigningSessionCreateResponse {
        return MIRACLService.createSigningSession(
            projectId,
            USER_ID,
            hash,
            description
        )
    }
}