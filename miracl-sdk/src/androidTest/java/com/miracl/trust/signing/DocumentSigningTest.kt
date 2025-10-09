package com.miracl.trust.signing

import android.content.Context
import android.os.Build
import androidx.room.Room
import androidx.test.core.app.ApplicationProvider
import com.miracl.trust.BuildConfig
import com.miracl.trust.MIRACLError
import com.miracl.trust.MIRACLSuccess
import com.miracl.trust.authentication.AuthenticationApiManager
import com.miracl.trust.authentication.Authenticator
import com.miracl.trust.crypto.Crypto
import com.miracl.trust.delegate.PinProvider
import com.miracl.trust.model.User
import com.miracl.trust.network.ApiRequestExecutor
import com.miracl.trust.network.ApiSettings
import com.miracl.trust.network.HttpsURLConnectionRequestExecutor
import com.miracl.trust.registration.RegistrationApiManager
import com.miracl.trust.registration.Registrator
import com.miracl.trust.session.CrossDeviceSession
import com.miracl.trust.session.CrossDeviceSessionApiManager
import com.miracl.trust.session.CrossDeviceSessionManager
import com.miracl.trust.session.IdentityType
import com.miracl.trust.session.SessionApiManager
import com.miracl.trust.session.SigningSessionApiManager
import com.miracl.trust.session.SigningSessionDetails
import com.miracl.trust.session.SigningSessionManager
import com.miracl.trust.session.SigningSessionStatus
import com.miracl.trust.session.VerificationMethod
import com.miracl.trust.storage.room.RoomUserStorage
import com.miracl.trust.storage.room.UserDatabase
import com.miracl.trust.util.json.KotlinxSerializationJsonUtil
import com.miracl.trust.util.secondsSince1970
import com.miracl.trust.util.toUser
import com.miracl.trust.utilities.MIRACLService
import com.miracl.trust.utilities.USER_ID
import com.miracl.trust.utilities.USER_PIN_LENGTH
import com.miracl.trust.utilities.WRONG_FORMAT_PIN
import com.miracl.trust.utilities.generateWrongPin
import com.miracl.trust.utilities.randomNumericPin
import com.miracl.trust.utilities.randomPinLength
import com.miracl.trust.utilities.randomUuidString
import kotlinx.coroutines.runBlocking
import org.junit.Assert
import org.junit.Before
import org.junit.Test
import kotlin.random.Random

class DocumentSigningTest {
    companion object {
        private val HASH_RANGE = 1..10
    }

    private val projectId = BuildConfig.CUV_PROJECT_ID
    private val projectUrl = BuildConfig.CUV_PROJECT_URL
    private val clientId = BuildConfig.CUV_CLIENT_ID
    private val clientSecret = BuildConfig.CUV_CLIENT_SECRET

    private lateinit var userStorage: RoomUserStorage
    private lateinit var signingSessionManager: SigningSessionManager
    private lateinit var crossDeviceSessionManager: CrossDeviceSessionManager
    private lateinit var documentSigner: DocumentSigner

    private lateinit var pin: String
    private lateinit var pinProvider: PinProvider
    private lateinit var user: User

    @Before
    fun setUp() = runBlocking {
        val httpRequestExecutor = HttpsURLConnectionRequestExecutor(10, 10)
        val apiSettings = ApiSettings(projectUrl)
        val apiRequestExecutor =
            ApiRequestExecutor(httpRequestExecutor, KotlinxSerializationJsonUtil)

        val crypto = Crypto()

        val context = ApplicationProvider.getApplicationContext<Context>()
        val userDatabase = Room.inMemoryDatabaseBuilder(context, UserDatabase::class.java).build()
        userStorage = RoomUserStorage(userDatabase)

        val signingSessionApi =
            SigningSessionApiManager(apiRequestExecutor, KotlinxSerializationJsonUtil, apiSettings)
        signingSessionManager = SigningSessionManager(signingSessionApi)

        val crossDeviceSessionApi = CrossDeviceSessionApiManager(
            apiRequestExecutor,
            KotlinxSerializationJsonUtil,
            apiSettings
        )
        crossDeviceSessionManager = CrossDeviceSessionManager(crossDeviceSessionApi)

        val sessionApi =
            SessionApiManager(apiRequestExecutor, KotlinxSerializationJsonUtil, apiSettings)

        val registrationApi =
            RegistrationApiManager(apiRequestExecutor, KotlinxSerializationJsonUtil, apiSettings)
        val registrator = Registrator(registrationApi, crypto, userStorage)

        val authenticationApi =
            AuthenticationApiManager(apiRequestExecutor, KotlinxSerializationJsonUtil, apiSettings)
        val authenticator =
            Authenticator(authenticationApi, sessionApi, crypto, registrator, userStorage)
        documentSigner = DocumentSigner(
            crypto,
            authenticator,
            userStorage,
            signingSessionApi,
            crossDeviceSessionApi
        )

        pin = randomNumericPin()
        pinProvider = PinProvider { pinConsumer -> pinConsumer.consume(pin) }
        val activationToken =
            MIRACLService.obtainActivationToken(projectUrl, clientId, clientSecret, USER_ID)

        val registrationResult = registrator.register(
            userId = USER_ID,
            projectId = projectId,
            activationToken = activationToken,
            pinProvider = pinProvider,
            deviceName = Build.MODEL,
            pushNotificationsToken = null
        )
        Assert.assertTrue(registrationResult is MIRACLSuccess)

        user = (registrationResult as MIRACLSuccess).value
    }

    @Test
    fun testSuccessfulDocumentSigning() = runBlocking {
        // Sign
        val result = documentSigner.sign(
            message = randomHash(),
            user = user,
            pinProvider = pinProvider,
            deviceName = Build.MODEL
        )
        Assert.assertTrue(result is MIRACLSuccess)

        // Verify the signature
        val signingResult = (result as MIRACLSuccess).value
        val signatureVerified = MIRACLService.verifySignature(
            projectId = projectId,
            projectUrl = projectUrl,
            clientId = clientId,
            clientSecret = clientSecret,
            signature = signingResult.signature,
            timestamp = signingResult.timestamp.secondsSince1970()
        )
        Assert.assertTrue(signatureVerified)
    }

    @Test
    fun testSuccessfulDocumentSigningWithSigningSessionDetails() = runBlocking {
        // Sign
        val signingSessionDetails = createSigningSession()
        val result = documentSigner.sign(
            message = signingSessionDetails.signingHash.toByteArray(),
            user = user,
            pinProvider = pinProvider,
            deviceName = Build.MODEL,
            signingSessionDetails = signingSessionDetails
        )
        Assert.assertTrue(result is MIRACLSuccess)

        // Verify the signature
        val signingResult = (result as MIRACLSuccess).value
        val signatureVerified = MIRACLService.verifySignature(
            projectId = projectId,
            projectUrl = projectUrl,
            clientId = clientId,
            clientSecret = clientSecret,
            signature = signingResult.signature,
            timestamp = signingResult.timestamp.secondsSince1970()
        )
        Assert.assertTrue(signatureVerified)
    }

    @Test
    fun testSuccessfulDocumentSigningWithCrossDeviceSession() = runBlocking {
        // Arrange
        val crossDeviceSession = createCrossDeviceSession()

        // Act
        val result = documentSigner.sign(
            crossDeviceSession = crossDeviceSession,
            user = user,
            pinProvider = pinProvider,
            deviceName = Build.MODEL
        )

        // Assert
        Assert.assertTrue(result is MIRACLSuccess)
    }

    @Test
    fun testSigningFailOnEmptyMessage() = runBlocking {
        // Arrange
        val emptyMessage = "".toByteArray()

        // Act
        val signingResult = documentSigner.sign(
            message = emptyMessage,
            user = user,
            pinProvider = pinProvider,
            deviceName = Build.MODEL
        )

        // Assert
        Assert.assertTrue(signingResult is MIRACLError)
        Assert.assertEquals(SigningException.EmptyMessageHash, (signingResult as MIRACLError).value)
    }

    @Test
    fun testSigningFailOnEmptyPin() = runBlocking {
        // Arrange
        val emptyPinProvider = PinProvider { pinConsumer -> pinConsumer.consume(null) }

        // Act
        val signingResult = documentSigner.sign(
            message = randomHash(),
            user = user,
            pinProvider = emptyPinProvider,
            deviceName = Build.MODEL
        )

        // Assert
        Assert.assertTrue(signingResult is MIRACLError)
        Assert.assertEquals(SigningException.PinCancelled, (signingResult as MIRACLError).value)
    }

    @Test
    fun testSigningFailOnShorterPin() = runBlocking {
        // Arrange
        val shorterPinProvider = PinProvider { pinConsumer ->
            pinConsumer.consume(randomNumericPin(USER_PIN_LENGTH - 1))
        }

        // Act
        val signingResult = documentSigner.sign(
            message = randomHash(),
            user = user,
            pinProvider = shorterPinProvider,
            deviceName = Build.MODEL
        )

        // Assert
        Assert.assertTrue(signingResult is MIRACLError)
        Assert.assertEquals(SigningException.InvalidPin, (signingResult as MIRACLError).value)
    }

    @Test
    fun testSigningFailOnLongerPin() = runBlocking {
        // Arrange
        val longerPinProvider = PinProvider { pinConsumer ->
            pinConsumer.consume(randomNumericPin(USER_PIN_LENGTH + 1))
        }

        // Act
        val signingResult = documentSigner.sign(
            message = randomHash(),
            user = user,
            pinProvider = longerPinProvider,
            deviceName = Build.MODEL
        )

        // Assert
        Assert.assertTrue(signingResult is MIRACLError)
        Assert.assertEquals(SigningException.InvalidPin, (signingResult as MIRACLError).value)
    }

    @Test
    fun testSigningFailOnWrongFormatPin() = runBlocking {
        // Arrange
        val wrongFormatPinProvider = PinProvider { pinConsumer ->
            pinConsumer.consume(WRONG_FORMAT_PIN)
        }

        // Act
        val signingResult = documentSigner.sign(
            message = randomHash(),
            user = user,
            pinProvider = wrongFormatPinProvider,
            deviceName = Build.MODEL
        )

        // Assert
        Assert.assertTrue(signingResult is MIRACLError)
        Assert.assertEquals(SigningException.InvalidPin, (signingResult as MIRACLError).value)
    }

    @Test
    fun testSigningFailOnWrongPin() = runBlocking {
        // Arrange
        val wrongPinProvider = PinProvider { pinConsumer ->
            pinConsumer.consume(generateWrongPin(pin))
        }

        // Act
        val signingResult = documentSigner.sign(
            message = randomHash(),
            user = user,
            pinProvider = wrongPinProvider,
            deviceName = Build.MODEL
        )

        // Assert
        Assert.assertTrue(signingResult is MIRACLError)
        Assert.assertEquals(
            SigningException.UnsuccessfulAuthentication,
            (signingResult as MIRACLError).value
        )
    }

    @Test
    fun testSigningFailOnRevokedUser() = runBlocking {
        // Arrange
        val wrongPinProvider = PinProvider { pinConsumer ->
            pinConsumer.consume(generateWrongPin(pin))
        }

        var signingResult = documentSigner.sign(
            message = randomHash(),
            user = user,
            pinProvider = wrongPinProvider,
            deviceName = Build.MODEL
        )
        Assert.assertTrue(signingResult is MIRACLError)
        Assert.assertEquals(
            SigningException.UnsuccessfulAuthentication,
            (signingResult as MIRACLError).value
        )

        signingResult = documentSigner.sign(
            message = randomHash(),
            user = user,
            pinProvider = wrongPinProvider,
            deviceName = Build.MODEL
        )
        Assert.assertTrue(signingResult is MIRACLError)
        Assert.assertEquals(
            SigningException.UnsuccessfulAuthentication,
            (signingResult as MIRACLError).value
        )

        signingResult = documentSigner.sign(
            message = randomHash(),
            user = user,
            pinProvider = wrongPinProvider,
            deviceName = Build.MODEL
        )
        Assert.assertTrue(signingResult is MIRACLError)
        Assert.assertEquals(SigningException.Revoked, (signingResult as MIRACLError).value)

        user = userStorage.getUser(user.userId, user.projectId)!!.toUser()
        Assert.assertTrue(user.revoked)

        // Act
        signingResult = documentSigner.sign(
            message = randomHash(),
            user = user,
            pinProvider = pinProvider,
            deviceName = Build.MODEL
        )

        // Assert
        Assert.assertTrue(signingResult is MIRACLError)
        Assert.assertEquals(SigningException.Revoked, (signingResult as MIRACLError).value)
    }

    @Test
    fun testSigningInvalidSession() = runBlocking {
        // Arrange
        val invalidSigningSessionDetails = SigningSessionDetails(
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
            quickCodeEnabled = Random.nextBoolean()
        )

        // Act
        val signingResult = documentSigner.sign(
            "hash".toByteArray(),
            user,
            pinProvider,
            Build.MODEL,
            invalidSigningSessionDetails
        )

        // Assert
        Assert.assertTrue(signingResult is MIRACLError)
        Assert.assertEquals(
            SigningException.InvalidSigningSession,
            (signingResult as MIRACLError).value
        )
    }

    private suspend fun createSigningSession(
        hash: String = randomUuidString(),
        description: String = randomUuidString()
    ): SigningSessionDetails {
        val qrCode = MIRACLService.createSigningSession(
            projectId = projectId,
            projectUrl = projectUrl,
            userId = USER_ID,
            hash = hash,
            description = description
        ).qrURL

        val getSigningSessionDetailsResult =
            signingSessionManager.getSigningSessionDetailsFromQRCode(qrCode)
        Assert.assertTrue(getSigningSessionDetailsResult is MIRACLSuccess)

        return (getSigningSessionDetailsResult as MIRACLSuccess).value
    }

    private suspend fun createCrossDeviceSession(
        hash: String = randomUuidString(),
        description: String = randomUuidString()
    ): CrossDeviceSession {
        val qrCode = MIRACLService.obtainAccessId(
            projectId = projectId,
            projectUrl = projectUrl,
            userId = USER_ID,
            hash = hash,
            description = description
        ).qrURL

        val getSigningSessionDetailsResult =
            crossDeviceSessionManager.getCrossDeviceSessionFromQRCode(qrCode)
        Assert.assertTrue(getSigningSessionDetailsResult is MIRACLSuccess)

        return (getSigningSessionDetailsResult as MIRACLSuccess).value
    }

    private fun randomHash(): ByteArray =
        (HASH_RANGE)
            .map { Random.nextBytes(it) }
            .reduce { acc, bytes -> acc + bytes }
}