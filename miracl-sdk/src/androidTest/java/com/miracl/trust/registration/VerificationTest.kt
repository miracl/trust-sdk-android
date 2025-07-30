package com.miracl.trust.registration

import android.net.Uri
import androidx.test.platform.app.InstrumentationRegistry
import com.miracl.trust.BuildConfig
import com.miracl.trust.MIRACLError
import com.miracl.trust.MIRACLResult
import com.miracl.trust.MIRACLSuccess
import com.miracl.trust.MIRACLTrust
import com.miracl.trust.authentication.AuthenticationException
import com.miracl.trust.configuration.Configuration
import com.miracl.trust.delegate.PinProvider
import com.miracl.trust.model.User
import com.miracl.trust.session.AuthenticationSessionDetails
import com.miracl.trust.session.AuthenticationSessionException
import com.miracl.trust.session.CrossDeviceSession
import com.miracl.trust.session.CrossDeviceSessionException
import com.miracl.trust.util.secondsSince1970
import com.miracl.trust.utilities.GmailService
import com.miracl.trust.utilities.MIRACLService
import com.miracl.trust.utilities.USER_ID
import com.miracl.trust.utilities.generateWrongPin
import com.miracl.trust.utilities.getUnixTime
import com.miracl.trust.utilities.randomNumericPin
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.runTest
import org.junit.Assert
import org.junit.Before
import org.junit.Test
import java.net.URL
import java.util.Date
import java.util.UUID

class VerificationTest {
    private val projectId = BuildConfig.CUV_PROJECT_ID
    private val clientId = BuildConfig.CUV_CLIENT_ID
    private val clientSecret = BuildConfig.CUV_CLIENT_SECRET

    private val dvProjectId = BuildConfig.DV_PROJECT_ID
    private val evcProjectId = BuildConfig.ECV_PROJECT_ID

    private val testCoroutineDispatcher = StandardTestDispatcher()

    private lateinit var miraclTrust: MIRACLTrust

    @Before
    fun setUp() = runBlocking {
        val configuration = Configuration.Builder(dvProjectId)
            .platformUrl(BuildConfig.BASE_URL)
            .coroutineContext(testCoroutineDispatcher)
            .build()

        MIRACLTrust.configure(InstrumentationRegistry.getInstrumentation().context, configuration)
        miraclTrust = MIRACLTrust.getInstance()
        miraclTrust.resultHandlerDispatcher = testCoroutineDispatcher
    }

    @Test
    fun testDefaultVerification() {
        // Send verification email
        val addressParts = USER_ID.split("@")
        val email = "${addressParts[0]}+${UUID.randomUUID()}@${addressParts[1]}"

        var sendEmailResult: MIRACLResult<VerificationResponse, VerificationException>? = null
        val timestamp = getUnixTime()
        miraclTrust.sendVerificationEmail(email) { sendEmailResult = it }
        testCoroutineDispatcher.scheduler.advanceUntilIdle()
        Assert.assertTrue(sendEmailResult is MIRACLSuccess)

        // Fetch the verification URL from the email
        val context = InstrumentationRegistry.getInstrumentation().context
        val verificationUrl = GmailService.getVerificationUrl(context, USER_ID, email, timestamp)
        Assert.assertNotNull(verificationUrl)

        // Get activation token
        var result: MIRACLResult<ActivationTokenResponse, ActivationTokenException>? = null
        miraclTrust.getActivationToken(Uri.parse(verificationUrl)) { result = it }
        testCoroutineDispatcher.scheduler.advanceUntilIdle()
        Assert.assertTrue(result is MIRACLSuccess)
        Assert.assertEquals(email, (result as MIRACLSuccess).value.userId)
    }

    @Test
    fun testDefaultVerificationBackoff() {
        // Send verification email
        val addressParts = USER_ID.split("@")
        val email = "${addressParts[0]}+${UUID.randomUUID()}@${addressParts[1]}"

        var sendEmailResult: MIRACLResult<VerificationResponse, VerificationException>? = null
        miraclTrust.sendVerificationEmail(email) { sendEmailResult = it }
        testCoroutineDispatcher.scheduler.advanceUntilIdle()
        Assert.assertTrue(sendEmailResult is MIRACLSuccess)

        // Send second verification email
        miraclTrust.sendVerificationEmail(email) { sendEmailResult = it }
        testCoroutineDispatcher.scheduler.advanceUntilIdle()
        Assert.assertTrue(sendEmailResult is MIRACLError)
        val verificationError = (sendEmailResult as MIRACLError)
        Assert.assertTrue((verificationError.value is VerificationException.RequestBackoff))
    }

    @Test
    fun testDefaultVerificationWithSessionDetails() = runBlocking {
        // Send verification email
        val addressParts = USER_ID.split("@")
        val email = "${addressParts[0]}+${UUID.randomUUID()}@${addressParts[1]}"

        val qrCode = MIRACLService.obtainAccessId(dvProjectId).qrURL
        var authenticationSessionDetailsResult:
                MIRACLResult<AuthenticationSessionDetails, AuthenticationSessionException>? = null
        miraclTrust.getAuthenticationSessionDetailsFromQRCode(qrCode) { result ->
            authenticationSessionDetailsResult = result
        }
        testCoroutineDispatcher.scheduler.advanceUntilIdle()

        Assert.assertTrue(authenticationSessionDetailsResult is MIRACLSuccess)
        val authenticationSessionDetails =
            (authenticationSessionDetailsResult as MIRACLSuccess).value

        var sendEmailResult: MIRACLResult<VerificationResponse, VerificationException>? = null
        val timestamp = getUnixTime()
        miraclTrust.sendVerificationEmail(
            userId = email,
            authenticationSessionDetails = authenticationSessionDetails
        ) { sendEmailResult = it }
        testCoroutineDispatcher.scheduler.advanceUntilIdle()
        Assert.assertTrue(sendEmailResult is MIRACLSuccess)

        // Fetch the verification URL from the email
        val context = InstrumentationRegistry.getInstrumentation().context
        val verificationUrl = GmailService.getVerificationUrl(context, USER_ID, email, timestamp)
        Assert.assertNotNull(verificationUrl)

        // Get activation token
        var result: MIRACLResult<ActivationTokenResponse, ActivationTokenException>? = null
        miraclTrust.getActivationToken(Uri.parse(verificationUrl)) { result = it }
        testCoroutineDispatcher.scheduler.advanceUntilIdle()
        Assert.assertTrue(result is MIRACLSuccess)
        val activationTokenResponse = (result as MIRACLSuccess).value
        Assert.assertEquals(email, activationTokenResponse.userId)
        Assert.assertEquals(authenticationSessionDetails.accessId, activationTokenResponse.accessId)
    }

    @Test
    fun testDefaultVerificationWithCrossDeviceSession() = runBlocking {
        // Send verification email
        val addressParts = USER_ID.split("@")
        val email = "${addressParts[0]}+${UUID.randomUUID()}@${addressParts[1]}"

        val qrCode = MIRACLService.obtainAccessId(dvProjectId).qrURL
        var crossDeviceSessionResult:
                MIRACLResult<CrossDeviceSession, CrossDeviceSessionException>? = null
        miraclTrust.getCrossDeviceSessionFromQRCode(qrCode) { result ->
            crossDeviceSessionResult = result
        }
        testCoroutineDispatcher.scheduler.advanceUntilIdle()

        Assert.assertTrue(crossDeviceSessionResult is MIRACLSuccess)
        val crossDeviceSession =
            (crossDeviceSessionResult as MIRACLSuccess).value

        var sendEmailResult: MIRACLResult<VerificationResponse, VerificationException>? = null
        val timestamp = getUnixTime()
        miraclTrust.sendVerificationEmail(
            userId = email,
            crossDeviceSession = crossDeviceSession
        ) { sendEmailResult = it }
        testCoroutineDispatcher.scheduler.advanceUntilIdle()
        Assert.assertTrue(sendEmailResult is MIRACLSuccess)

        // Fetch the verification URL from the email
        val context = InstrumentationRegistry.getInstrumentation().context
        val verificationUrl = GmailService.getVerificationUrl(context, USER_ID, email, timestamp)
        Assert.assertNotNull(verificationUrl)

        // Get activation token
        var result: MIRACLResult<ActivationTokenResponse, ActivationTokenException>? = null
        miraclTrust.getActivationToken(Uri.parse(verificationUrl)) { result = it }
        testCoroutineDispatcher.scheduler.advanceUntilIdle()
        Assert.assertTrue(result is MIRACLSuccess)
        val activationTokenResponse = (result as MIRACLSuccess).value
        Assert.assertEquals(email, activationTokenResponse.userId)
        Assert.assertEquals(crossDeviceSession.sessionId, activationTokenResponse.accessId)
    }

    @Test
    fun testDefaultVerificationWithMpinId() {
        // Send verification email
        val addressParts = USER_ID.split("@")
        val email = "${addressParts[0]}+${UUID.randomUUID()}@${addressParts[1]}"

        var sendEmailResult: MIRACLResult<VerificationResponse, VerificationException>? = null
        val timestamp = System.currentTimeMillis() / 1000
        miraclTrust.sendVerificationEmail(email) { sendEmailResult = it }
        testCoroutineDispatcher.scheduler.advanceUntilIdle()
        Assert.assertTrue(sendEmailResult is MIRACLSuccess)

        // Fetch the verification URL from the email
        val context = InstrumentationRegistry.getInstrumentation().context
        val verificationUrl = GmailService.getVerificationUrl(context, USER_ID, email, timestamp)
        Assert.assertNotNull(verificationUrl)

        // Get activation token
        var activationTokenResult: MIRACLResult<ActivationTokenResponse, ActivationTokenException>? =
            null
        miraclTrust.getActivationToken(Uri.parse(verificationUrl)) { activationTokenResult = it }
        testCoroutineDispatcher.scheduler.advanceUntilIdle()
        Assert.assertTrue(activationTokenResult is MIRACLSuccess)
        val activationTokenResponse = (activationTokenResult as MIRACLSuccess).value
        Assert.assertEquals(email, activationTokenResponse.userId)

        // Register
        var registerResult: MIRACLResult<User, RegistrationException>? = null
        miraclTrust.register(
            userId = email,
            activationToken = activationTokenResponse.activationToken,
            pinProvider = { pinConsumer -> pinConsumer.consume(randomNumericPin()) }
        ) { registerResult = it }
        testCoroutineDispatcher.scheduler.advanceUntilIdle()
        Assert.assertTrue(registerResult is MIRACLSuccess)

        // Prevent verification request backoff
        Thread.sleep(10000)

        // Send second verification email
        var result: MIRACLResult<VerificationResponse, VerificationException>? = null
        miraclTrust.sendVerificationEmail(email) { result = it }
        testCoroutineDispatcher.scheduler.advanceUntilIdle()
        Assert.assertTrue(result is MIRACLSuccess)
        Assert.assertEquals(EmailVerificationMethod.Link, (result as MIRACLSuccess).value.method)
    }

    @Test
    fun testEmailCodeVerification() {
        // Send verification email
        miraclTrust.setProjectId(evcProjectId)
        val addressParts = USER_ID.split("@")
        val email = "${addressParts[0]}+${UUID.randomUUID()}@${addressParts[1]}"

        var sendEmailResult: MIRACLResult<VerificationResponse, VerificationException>? = null
        val timestamp = System.currentTimeMillis() / 1000
        miraclTrust.sendVerificationEmail(email) { sendEmailResult = it }
        testCoroutineDispatcher.scheduler.advanceUntilIdle()
        Assert.assertTrue(sendEmailResult is MIRACLSuccess)

        // Fetch the verification code from the email
        val context = InstrumentationRegistry.getInstrumentation().context
        val code = GmailService.getVerificationCode(context, USER_ID, email, timestamp)
        Assert.assertNotNull(code)

        // Get activation token
        var result: MIRACLResult<ActivationTokenResponse, ActivationTokenException>? = null
        miraclTrust.getActivationToken(email, code!!) { result = it }
        testCoroutineDispatcher.scheduler.advanceUntilIdle()
        Assert.assertTrue(result is MIRACLSuccess)
        Assert.assertEquals(email, (result as MIRACLSuccess).value.userId)
    }

    @Test
    fun testEmailCodeVerificationWithMpinId() {
        // Send verification email
        miraclTrust.setProjectId(evcProjectId)
        val addressParts = USER_ID.split("@")
        val email = "${addressParts[0]}+${UUID.randomUUID()}@${addressParts[1]}"

        var sendEmailResult: MIRACLResult<VerificationResponse, VerificationException>? = null
        val timestamp = System.currentTimeMillis() / 1000
        miraclTrust.sendVerificationEmail(email) { sendEmailResult = it }
        testCoroutineDispatcher.scheduler.advanceUntilIdle()
        Assert.assertTrue(sendEmailResult is MIRACLSuccess)

        // Fetch the verification URL from the email
        val context = InstrumentationRegistry.getInstrumentation().context
        val code = GmailService.getVerificationCode(context, USER_ID, email, timestamp)
        Assert.assertNotNull(code)

        // Get activation token
        var activationTokenResult:
                MIRACLResult<ActivationTokenResponse, ActivationTokenException>? = null
        miraclTrust.getActivationToken(email, code!!) { activationTokenResult = it }
        testCoroutineDispatcher.scheduler.advanceUntilIdle()
        Assert.assertTrue(activationTokenResult is MIRACLSuccess)
        val activationTokenResponse = (activationTokenResult as MIRACLSuccess).value
        Assert.assertEquals(email, activationTokenResponse.userId)

        // Register
        var registerResult: MIRACLResult<User, RegistrationException>? = null
        miraclTrust.register(
            userId = email,
            activationToken = activationTokenResponse.activationToken,
            pinProvider = { pinConsumer -> pinConsumer.consume(randomNumericPin()) }
        ) { registerResult = it }
        testCoroutineDispatcher.scheduler.advanceUntilIdle()
        Assert.assertTrue(registerResult is MIRACLSuccess)

        // Prevent verification request backoff
        Thread.sleep(10000)

        // Send second verification email
        var result: MIRACLResult<VerificationResponse, VerificationException>? = null
        miraclTrust.sendVerificationEmail(email) { result = it }
        testCoroutineDispatcher.scheduler.advanceUntilIdle()
        Assert.assertTrue(result is MIRACLSuccess)
        Assert.assertEquals(EmailVerificationMethod.Code, (result as MIRACLSuccess).value.method)
    }

    @Test
    fun testEmailCodeVerificationWithoutMpinId() = runTest {
        // Send verification email
        miraclTrust.setProjectId(evcProjectId)
        val addressParts = USER_ID.split("@")
        val email = "${addressParts[0]}+${UUID.randomUUID()}@${addressParts[1]}"

        val timestamp = System.currentTimeMillis() / 1000
        var sendEmailResult: MIRACLResult<VerificationResponse, VerificationException>? = null
        miraclTrust.sendVerificationEmail(email) { sendEmailResult = it }
        testCoroutineDispatcher.scheduler.advanceUntilIdle()
        Assert.assertTrue(sendEmailResult is MIRACLSuccess)

        // Fetch the verification URL from the email
        val context = InstrumentationRegistry.getInstrumentation().context
        val code = GmailService.getVerificationCode(context, USER_ID, email, timestamp)
        Assert.assertNotNull(code)

        // Get activation token
        var activationTokenReponse:
                MIRACLResult<ActivationTokenResponse, ActivationTokenException>? = null
        miraclTrust.getActivationToken(email, code!!) { activationTokenReponse = it }
        testCoroutineDispatcher.scheduler.advanceUntilIdle()
        Assert.assertTrue(activationTokenReponse is MIRACLSuccess)
        val activationTokenResponse = (activationTokenReponse as MIRACLSuccess).value
        Assert.assertEquals(email, activationTokenResponse.userId)

        // Register
        var registerResult: MIRACLResult<User, RegistrationException>? = null
        miraclTrust.register(
            userId = email,
            activationToken = activationTokenResponse.activationToken,
            pinProvider = { pinConsumer -> pinConsumer.consume(randomNumericPin()) }
        ) { registerResult = it }
        testCoroutineDispatcher.scheduler.advanceUntilIdle()
        Assert.assertTrue(registerResult is MIRACLSuccess)

        // Remove user
        val user = (registerResult as MIRACLSuccess).value
        miraclTrust.delete(user)

        // Prevent verification request backoff
        Thread.sleep(10000)

        // Send second verification email
        var result: MIRACLResult<VerificationResponse, VerificationException>? = null
        miraclTrust.sendVerificationEmail(email) { result = it }
        testCoroutineDispatcher.scheduler.advanceUntilIdle()
        Assert.assertTrue(result is MIRACLSuccess)
        Assert.assertEquals(EmailVerificationMethod.Link, (result as MIRACLSuccess).value.method)
    }

    @Test
    fun testEmailCodeVerificationWithRevokedMpinId() {
        // Send verification email
        miraclTrust.setProjectId(evcProjectId)
        val addressParts = USER_ID.split("@")
        val email = "${addressParts[0]}+${UUID.randomUUID()}@${addressParts[1]}"

        var sendEmailResult: MIRACLResult<VerificationResponse, VerificationException>? = null
        val timestamp = System.currentTimeMillis() / 1000
        miraclTrust.sendVerificationEmail(email) { sendEmailResult = it }
        testCoroutineDispatcher.scheduler.advanceUntilIdle()
        Assert.assertTrue(sendEmailResult is MIRACLSuccess)

        // Fetch the verification URL from the email
        val context = InstrumentationRegistry.getInstrumentation().context
        val code = GmailService.getVerificationCode(context, USER_ID, email, timestamp)
        Assert.assertNotNull(code)

        // Get activation token
        var activationTokenReponse:
                MIRACLResult<ActivationTokenResponse, ActivationTokenException>? = null
        miraclTrust.getActivationToken(email, code!!) { activationTokenReponse = it }
        testCoroutineDispatcher.scheduler.advanceUntilIdle()
        Assert.assertTrue(activationTokenReponse is MIRACLSuccess)
        val activationTokenResponse = (activationTokenReponse as MIRACLSuccess).value
        Assert.assertEquals(email, activationTokenResponse.userId)

        // Register
        val pin = randomNumericPin()
        val pinProvider = PinProvider { it.consume(pin) }
        var registerResult: MIRACLResult<User, RegistrationException>? = null
        miraclTrust.register(
            userId = email,
            activationToken = activationTokenResponse.activationToken,
            pinProvider = pinProvider
        ) { registerResult = it }
        testCoroutineDispatcher.scheduler.advanceUntilIdle()
        Assert.assertTrue(registerResult is MIRACLSuccess)

        // Revoke user
        val user = (registerResult as MIRACLSuccess).value
        revokeUser(user, pin)

        // Prevent verification request backoff
        Thread.sleep(10000)

        // Send second verification email
        var result: MIRACLResult<VerificationResponse, VerificationException>? = null
        miraclTrust.sendVerificationEmail(email) { result = it }
        testCoroutineDispatcher.scheduler.advanceUntilIdle()
        Assert.assertTrue(result is MIRACLSuccess)
        Assert.assertEquals(EmailVerificationMethod.Code, (result as MIRACLSuccess).value.method)
    }

    @Test
    fun testCustomVerification() = runBlocking {
        // Get verification URL
        val verificationUrl = MIRACLService.getVerificationUrl(clientId, clientSecret, USER_ID)
        Assert.assertNotNull(verificationUrl)

        // Get activation token
        var result: MIRACLResult<ActivationTokenResponse, ActivationTokenException>? = null
        miraclTrust.getActivationToken(Uri.parse(verificationUrl)) { result = it }
        testCoroutineDispatcher.scheduler.advanceUntilIdle()
        Assert.assertTrue(result is MIRACLSuccess)
        val activationTokenResponse = (result as MIRACLSuccess).value
        Assert.assertEquals(USER_ID, activationTokenResponse.userId)
        Assert.assertEquals(projectId, activationTokenResponse.projectId)
    }

    @Test
    fun testCustomVerificationWithSessionDetails() = runBlocking {
        val qrCode = MIRACLService.obtainAccessId(projectId).qrURL
        var authenticationSessionDetailsResult:
                MIRACLResult<AuthenticationSessionDetails, AuthenticationSessionException>? = null

        miraclTrust.getAuthenticationSessionDetailsFromQRCode(qrCode) { result ->
            authenticationSessionDetailsResult = result
        }
        testCoroutineDispatcher.scheduler.advanceUntilIdle()

        Assert.assertTrue(authenticationSessionDetailsResult is MIRACLSuccess)
        val accessId =
            (authenticationSessionDetailsResult as MIRACLSuccess).value.accessId

        // Get verification URL
        val verificationUrl =
            MIRACLService.getVerificationUrl(clientId, clientSecret, USER_ID, accessId)
        Assert.assertNotNull(verificationUrl)

        // Get activation token
        var result: MIRACLResult<ActivationTokenResponse, ActivationTokenException>? = null
        miraclTrust.getActivationToken(Uri.parse(verificationUrl)) { result = it }
        testCoroutineDispatcher.scheduler.advanceUntilIdle()
        Assert.assertTrue(result is MIRACLSuccess)
        val activationTokenResponse = (result as MIRACLSuccess).value
        Assert.assertEquals(USER_ID, activationTokenResponse.userId)
        Assert.assertEquals(accessId, activationTokenResponse.accessId)
        Assert.assertEquals(projectId, activationTokenResponse.projectId)
    }

    @Test
    fun testCustomVerificationExpiredVerificationCode() = runBlocking {
        // Get verification URL
        val expirationMillis = 5000L
        val expiration = Date(Date().time + expirationMillis).secondsSince1970()
        val accessId = URL(MIRACLService.obtainAccessId(projectId).qrURL).ref
        val verificationUrl =
            MIRACLService.getVerificationUrl(clientId, clientSecret, USER_ID, accessId, expiration)
        Assert.assertNotNull(verificationUrl)

        Thread.sleep(expirationMillis + 1000)

        // Get activation token
        var result: MIRACLResult<ActivationTokenResponse, ActivationTokenException>? = null
        miraclTrust.getActivationToken(Uri.parse(verificationUrl)) { result = it }
        testCoroutineDispatcher.scheduler.advanceUntilIdle()
        Assert.assertTrue(result is MIRACLError)

        val exception = (result as MIRACLError).value
        Assert.assertTrue(exception is ActivationTokenException.UnsuccessfulVerification)
        val verificationException = (exception as ActivationTokenException.UnsuccessfulVerification)
        Assert.assertEquals(
            projectId,
            verificationException.activationTokenErrorResponse?.projectId
        )
        Assert.assertEquals(USER_ID, verificationException.activationTokenErrorResponse?.userId)
        Assert.assertEquals(accessId, verificationException.activationTokenErrorResponse?.accessId)
    }

    @Test
    fun testCustomVerificationInvalidVerificationCode() = runBlocking {
        // Get verification URL
        val verificationUrl = MIRACLService.getVerificationUrl(clientId, clientSecret, USER_ID)
        Assert.assertNotNull(verificationUrl)

        val verificationUri = Uri.parse(verificationUrl)
        val invalidActivationCode = "invalidActivationCode"
        val invalidVerificationUrl =
            Uri.Builder().scheme(verificationUri.scheme).authority(verificationUri.authority)
                .path(verificationUri.path)
                .appendQueryParameter("user_id", USER_ID)
                .appendQueryParameter("code", invalidActivationCode).build().toString()

        // Get activation token
        var result: MIRACLResult<ActivationTokenResponse, ActivationTokenException>? = null
        miraclTrust.getActivationToken(Uri.parse(invalidVerificationUrl)) { result = it }
        testCoroutineDispatcher.scheduler.advanceUntilIdle()
        Assert.assertTrue(result is MIRACLError)

        val exception = (result as MIRACLError).value
        Assert.assertTrue(exception is ActivationTokenException.UnsuccessfulVerification)
    }

    @Test
    fun testConfirmationFailOnEmptyUserId() {
        // Arrange
        val verificationUri =
            Uri.parse("${BuildConfig.BASE_URL}/verification/confirmation?code=testCode")

        // Act
        var result: MIRACLResult<ActivationTokenResponse, ActivationTokenException>? = null
        miraclTrust.getActivationToken(verificationUri) { result = it }
        testCoroutineDispatcher.scheduler.advanceUntilIdle()

        // Assert
        Assert.assertTrue(result is MIRACLError)
        Assert.assertEquals(
            ActivationTokenException.EmptyUserId,
            (result as MIRACLError).value
        )
    }

    @Test
    fun testConfirmationFailOnInvalidCode() {
        // Arrange
        val verificationUri =
            Uri.parse("${BuildConfig.BASE_URL}/verification/confirmation?user_id=$USER_ID&code=invalidCode")

        // Act
        var result: MIRACLResult<ActivationTokenResponse, ActivationTokenException>? = null
        miraclTrust.getActivationToken(verificationUri) { result = it }
        testCoroutineDispatcher.scheduler.advanceUntilIdle()

        // Assert
        Assert.assertTrue(result is MIRACLError)
        Assert.assertTrue(
            (result as MIRACLError).value is ActivationTokenException.UnsuccessfulVerification
        )
    }

    @Test
    fun testConfirmationFailOnEmptyCode() {
        // Arrange
        val verificationUri =
            Uri.parse("${BuildConfig.BASE_URL}/verification/confirmation?user_id=asd@dsa.asd")

        // Act
        var result: MIRACLResult<ActivationTokenResponse, ActivationTokenException>? = null
        miraclTrust.getActivationToken(verificationUri) { result = it }
        testCoroutineDispatcher.scheduler.advanceUntilIdle()

        // Assert
        Assert.assertTrue(result is MIRACLError)
        Assert.assertEquals(
            ActivationTokenException.EmptyVerificationCode,
            (result as MIRACLError).value
        )
    }

    private fun revokeUser(user: User, pin: String) = runTest {
        val wrongPinProvider = PinProvider { it.consume(generateWrongPin(pin)) }
        var authenticateResult: MIRACLResult<String, AuthenticationException>? = null
        miraclTrust.authenticate(user, wrongPinProvider) { authenticateResult = it }
        testCoroutineDispatcher.scheduler.advanceUntilIdle()
        Assert.assertTrue(authenticateResult is MIRACLError)
        Assert.assertEquals(
            AuthenticationException.UnsuccessfulAuthentication,
            (authenticateResult as MIRACLError).value
        )

        miraclTrust.authenticate(user, wrongPinProvider) { authenticateResult = it }
        testCoroutineDispatcher.scheduler.advanceUntilIdle()
        Assert.assertTrue(authenticateResult is MIRACLError)
        Assert.assertEquals(
            AuthenticationException.UnsuccessfulAuthentication,
            (authenticateResult as MIRACLError).value
        )

        miraclTrust.authenticate(user, wrongPinProvider) { authenticateResult = it }
        testCoroutineDispatcher.scheduler.advanceUntilIdle()
        Assert.assertTrue(authenticateResult is MIRACLError)
        Assert.assertEquals(
            AuthenticationException.Revoked,
            (authenticateResult as MIRACLError).value
        )

        Assert.assertTrue(miraclTrust.getUser(user.userId)!!.revoked)
    }
}