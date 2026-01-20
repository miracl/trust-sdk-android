package com.miracl.trust

import android.net.Uri
import com.miracl.trust.authentication.*
import com.miracl.trust.configuration.Configuration
import com.miracl.trust.configuration.ConfigurationException
import com.miracl.trust.delegate.PinProvider
import com.miracl.trust.delegate.ResultHandler
import com.miracl.trust.factory.ComponentFactory
import com.miracl.trust.model.*
import com.miracl.trust.network.HttpRequestExecutor
import com.miracl.trust.registration.*
import com.miracl.trust.session.*
import com.miracl.trust.signing.*
import com.miracl.trust.storage.UserDto
import com.miracl.trust.storage.UserStorageException
import com.miracl.trust.storage.UserStorage
import com.miracl.trust.util.log.Logger
import com.miracl.trust.util.log.LoggerConstants
import com.miracl.trust.util.secondsSince1970
import com.miracl.trust.util.toUserDto
import io.mockk.*
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.runTest
import org.junit.Assert
import org.junit.Before
import org.junit.Test
import java.util.*
import kotlin.random.Random
import kotlin.random.nextInt

@ExperimentalCoroutinesApi
class MIRACLTrustUnitTest {
    private val deviceName = randomUuidString()
    private val projectId = randomUuidString()
    private val projectUrl = "https://project.miracl.io"
    private val activationToken = randomUuidString()

    private val componentFactoryMock = mockk<ComponentFactory>()
    private val pinProviderMock = mockk<PinProvider>()
    private val userStorageMock = mockk<UserStorage>()
    private val registratorMock = mockk<RegistratorContract>()
    private val authenticatorMock = mockk<AuthenticatorContract>()
    private val documentSignerMock = mockk<DocumentSigner>()
    private val httpRequestExecutorMock = mockk<HttpRequestExecutor>()
    private val loggerMock = mockk<Logger>()
    private val verificatorMock = mockk<Verificator>()
    private val sessionManagerMock = mockk<SessionManagerContract>()
    private val signingSessionManagerMock = mockk<SigningSessionManagerContract>()
    private val crossDeviceSessionManagerMock = mockk<CrossDeviceSessionManagerContract>()

    private val testCoroutineDispatcher = StandardTestDispatcher()
    private lateinit var miraclTrust: MIRACLTrust

    init {
        // add environmental variable in order to load crypto lib without the need of instrumentation tests
        // and android specific environment
        System.setProperty(
            "java.library.path",
            "${System.getProperty("user.dir")}/build/intermediates/cmake/debug/obj/x86_64/"
        )
    }

    @Before
    fun setUp() {
        clearAllMocks()

        every { userStorageMock.loadStorage() } returns Unit

        setUpComponentFactoryMock()
        miraclTrust = configureMIRACLTrust()
    }

    @Test
    fun `is created on init when no exception is thrown on configure`() = runTest {
        // Arrange
        val config = createConfiguration()

        // Act
        MIRACLTrust.configure(
            context = mockk(),
            configuration = config
        )
        val sdk = MIRACLTrust.getInstance()

        // Assert
        Assert.assertTrue(sdk.getUsers().isEmpty())
    }

    @Test
    fun `is created on init when httpRequestExecutor is passed to the MIRACLTrust`() = runTest {
        // Arrange
        val config = Configuration.Builder(projectId, projectUrl)
            .deviceName(deviceName)
            .componentFactory(componentFactoryMock)
            .httpRequestExecutor(httpRequestExecutorMock)
            .userStorage(userStorageMock)
            .build()

        // Act
        MIRACLTrust.configure(
            context = mockk(),
            configuration = config
        )
        val sdk = MIRACLTrust.getInstance()

        // Assert
        Assert.assertTrue(sdk.getUsers().isEmpty())
    }

    @Test
    fun `setProjectId should update project settings`() {
        // Arrange
        val projectId = randomUuidString()

        // Act
        miraclTrust.setProjectId(projectId)

        // Assert
        Assert.assertEquals(projectId, miraclTrust.projectId)
    }

    @Test(expected = ConfigurationException.EmptyProjectId::class)
    fun `setProjectId throws when projectId is blank`() {
        // Arrange
        val projectId = "   "

        // Act
        miraclTrust.setProjectId(projectId)
    }

    @Test
    fun `updateProjectSettings should update project settings`() {
        // Arrange
        val projectId = randomUuidString()
        val projectUrl = "https://new-project.miracl.io"
        // Act
        miraclTrust.updateProjectSettings(projectId, projectUrl)

        // Assert
        Assert.assertEquals(projectId, miraclTrust.projectId)
    }

    @Test(expected = ConfigurationException.EmptyProjectId::class)
    fun `updateProjectSettings throws when projectId is blank`() {
        // Arrange
        val projectId = "   "
        val projectUrl = "https://new-project.miracl.io"

        // Act
        miraclTrust.updateProjectSettings(projectId, projectUrl)
    }

    @Test(expected = ConfigurationException.InvalidProjectUrl::class)
    fun `updateProjectSettings throws when projectUrl is blank`() {
        // Arrange
        val projectId = randomUuidString()
        val projectUrl = "   "

        // Act
        miraclTrust.updateProjectSettings(projectId, projectUrl)
    }

    @Test(expected = ConfigurationException.InvalidProjectUrl::class)
    fun `updateProjectSettings throws when projectUrl is invalid`() {
        // Arrange
        val projectId = randomUuidString()
        val projectUrl = "invalidProjectUrl"

        // Act
        miraclTrust.updateProjectSettings(projectId, projectUrl)
    }

    @Test
    fun `getAuthenticationSessionDetailsFromAppLink calls result handler with MIRACLSuccess when session details are retrieved`() {
        // Arrange
        val appLinkMock = mockkClass(Uri::class)
        val authenticationSessionDetails = mockkClass(AuthenticationSessionDetails::class)

        coEvery {
            sessionManagerMock.getSessionDetailsFromAppLink(appLinkMock)
        } returns MIRACLSuccess(authenticationSessionDetails)

        val resultHandlerMock =
            mockk<ResultHandler<AuthenticationSessionDetails, AuthenticationSessionException>>()
        every { resultHandlerMock.onResult(any()) } just runs

        // Act
        miraclTrust.getAuthenticationSessionDetailsFromAppLink(
            appLink = appLinkMock,
            resultHandler = resultHandlerMock
        )
        testCoroutineDispatcher.scheduler.advanceUntilIdle()

        // Assert
        val capturingSlot =
            CapturingSlot<MIRACLResult<AuthenticationSessionDetails, AuthenticationSessionException>>()
        coVerify { resultHandlerMock.onResult(capture(capturingSlot)) }

        Assert.assertTrue(capturingSlot.captured is MIRACLSuccess)
        Assert.assertEquals(
            authenticationSessionDetails,
            (capturingSlot.captured as MIRACLSuccess).value
        )
    }

    @Test
    fun `getAuthenticationSessionDetailsFromAppLink calls result handler with MIRACLError when session details retrieval was unsuccessful`() {
        // Arrange
        val appLinkMock = mockkClass(Uri::class)
        val exception = AuthenticationSessionException.GetAuthenticationSessionDetailsFail(null)

        coEvery {
            sessionManagerMock.getSessionDetailsFromAppLink(appLinkMock)
        } returns MIRACLError(exception)

        val resultHandlerMock =
            mockk<ResultHandler<AuthenticationSessionDetails, AuthenticationSessionException>>()
        every { resultHandlerMock.onResult(any()) } just runs

        // Act
        miraclTrust.getAuthenticationSessionDetailsFromAppLink(
            appLink = appLinkMock,
            resultHandler = resultHandlerMock
        )
        testCoroutineDispatcher.scheduler.advanceUntilIdle()

        // Assert
        val capturingSlot =
            CapturingSlot<MIRACLResult<AuthenticationSessionDetails, AuthenticationSessionException>>()
        coVerify { resultHandlerMock.onResult(capture(capturingSlot)) }

        Assert.assertTrue(capturingSlot.captured is MIRACLError)
        Assert.assertEquals(exception, (capturingSlot.captured as MIRACLError).value)
    }

    @Test
    fun `getAuthenticationSessionDetailsFromQRCode calls result handler with MIRACLSuccess when session details are retrieved`() {
        // Arrange
        val qrCode = "https://mcl.mpin.io#accessId"
        val authenticationSessionDetails = mockkClass(AuthenticationSessionDetails::class)

        coEvery {
            sessionManagerMock.getSessionDetailsFromQRCode(qrCode)
        } returns MIRACLSuccess(authenticationSessionDetails)

        val resultHandlerMock =
            mockk<ResultHandler<AuthenticationSessionDetails, AuthenticationSessionException>>()
        every { resultHandlerMock.onResult(any()) } just runs

        // Act
        miraclTrust.getAuthenticationSessionDetailsFromQRCode(
            qrCode = qrCode,
            resultHandler = resultHandlerMock
        )
        testCoroutineDispatcher.scheduler.advanceUntilIdle()

        // Assert
        val capturingSlot =
            CapturingSlot<MIRACLResult<AuthenticationSessionDetails, AuthenticationSessionException>>()
        coVerify { resultHandlerMock.onResult(capture(capturingSlot)) }

        Assert.assertTrue(capturingSlot.captured is MIRACLSuccess)
        Assert.assertEquals(
            authenticationSessionDetails,
            (capturingSlot.captured as MIRACLSuccess).value
        )
    }

    @Test
    fun `getAuthenticationSessionDetailsFromQRCode calls result handler with MIRACLError when session details retrieval was unsuccessful`() {
        // Arrange
        val qrCode = "https://mcl.mpin.io#accessId"
        val exception = AuthenticationSessionException.GetAuthenticationSessionDetailsFail(null)

        coEvery {
            sessionManagerMock.getSessionDetailsFromQRCode(qrCode)
        } returns MIRACLError(exception)

        val resultHandlerMock =
            mockk<ResultHandler<AuthenticationSessionDetails, AuthenticationSessionException>>()
        every { resultHandlerMock.onResult(any()) } just runs

        // Act
        miraclTrust.getAuthenticationSessionDetailsFromQRCode(
            qrCode = qrCode,
            resultHandler = resultHandlerMock
        )
        testCoroutineDispatcher.scheduler.advanceUntilIdle()

        // Assert
        val capturingSlot =
            CapturingSlot<MIRACLResult<AuthenticationSessionDetails, AuthenticationSessionException>>()
        coVerify { resultHandlerMock.onResult(capture(capturingSlot)) }

        Assert.assertTrue(capturingSlot.captured is MIRACLError)
        Assert.assertEquals(exception, (capturingSlot.captured as MIRACLError).value)
    }

    @Test
    fun `getAuthenticationSessionDetailsFromNotificationPayload calls result handler with MIRACLSuccess when session details are retrieved`() {
        // Arrange
        val payload = mapOf(
            SessionManager.PUSH_NOTIFICATION_QR_URL to "https://mcl.mpin.io/mobile-login/#accessId"
        )
        val authenticationSessionDetails = mockkClass(AuthenticationSessionDetails::class)

        coEvery {
            sessionManagerMock.getSessionDetailsFromNotificationPayload(payload)
        } returns MIRACLSuccess(authenticationSessionDetails)

        val resultHandlerMock =
            mockk<ResultHandler<AuthenticationSessionDetails, AuthenticationSessionException>>()
        every { resultHandlerMock.onResult(any()) } just runs

        // Act
        miraclTrust.getAuthenticationSessionDetailsFromNotificationPayload(
            payload = payload,
            resultHandler = resultHandlerMock
        )
        testCoroutineDispatcher.scheduler.advanceUntilIdle()

        // Assert
        val capturingSlot =
            CapturingSlot<MIRACLResult<AuthenticationSessionDetails, AuthenticationSessionException>>()
        coVerify { resultHandlerMock.onResult(capture(capturingSlot)) }

        Assert.assertTrue(capturingSlot.captured is MIRACLSuccess)
        Assert.assertEquals(
            authenticationSessionDetails,
            (capturingSlot.captured as MIRACLSuccess).value
        )
    }

    @Test
    fun `getAuthenticationSessionDetailsFromNotificationPayload calls result handler with MIRACLError when session details retrieval was unsuccessful`() {
        // Arrange
        val payload = mapOf(
            SessionManager.PUSH_NOTIFICATION_QR_URL to "https://mcl.mpin.io/mobile-login/#accessId"
        )
        val exception = AuthenticationSessionException.GetAuthenticationSessionDetailsFail(null)

        coEvery {
            sessionManagerMock.getSessionDetailsFromNotificationPayload(payload)
        } returns MIRACLError(exception)

        val resultHandlerMock =
            mockk<ResultHandler<AuthenticationSessionDetails, AuthenticationSessionException>>()
        every { resultHandlerMock.onResult(any()) } just runs

        // Act
        miraclTrust.getAuthenticationSessionDetailsFromNotificationPayload(
            payload = payload,
            resultHandler = resultHandlerMock
        )
        testCoroutineDispatcher.scheduler.advanceUntilIdle()

        // Assert
        val capturingSlot =
            CapturingSlot<MIRACLResult<AuthenticationSessionDetails, AuthenticationSessionException>>()
        coVerify { resultHandlerMock.onResult(capture(capturingSlot)) }

        Assert.assertTrue(capturingSlot.captured is MIRACLError)
        Assert.assertEquals(exception, (capturingSlot.captured as MIRACLError).value)
    }

    @Test
    fun `abortAuthenticationSession calls result handler with MIRACLSuccess when session abort was successful`() {
        // Arrange
        val authenticationSessionDetails = mockkClass(AuthenticationSessionDetails::class)

        coEvery {
            sessionManagerMock.abortSession(authenticationSessionDetails)
        } returns MIRACLSuccess(Unit)

        val resultHandlerMock =
            mockk<ResultHandler<Unit, AuthenticationSessionException>>()
        every { resultHandlerMock.onResult(any()) } just runs

        // Act
        miraclTrust.abortAuthenticationSession(
            authenticationSessionDetails = authenticationSessionDetails,
            resultHandler = resultHandlerMock
        )
        testCoroutineDispatcher.scheduler.advanceUntilIdle()

        // Assert
        val capturingSlot =
            CapturingSlot<MIRACLResult<Unit, AuthenticationSessionException>>()
        coVerify { resultHandlerMock.onResult(capture(capturingSlot)) }

        Assert.assertTrue(capturingSlot.captured is MIRACLSuccess)
    }

    @Test
    fun `abortAuthenticationSession calls result handler with MIRACLError when session abort was unsuccessful`() {
        // Arrange
        val authenticationSessionDetails = mockkClass(AuthenticationSessionDetails::class)
        val exception = AuthenticationSessionException.AbortSessionFail(null)

        coEvery {
            sessionManagerMock.abortSession(authenticationSessionDetails)
        } returns MIRACLError(exception)

        val resultHandlerMock =
            mockk<ResultHandler<Unit, AuthenticationSessionException>>()
        every { resultHandlerMock.onResult(any()) } just runs

        // Act
        miraclTrust.abortAuthenticationSession(
            authenticationSessionDetails = authenticationSessionDetails,
            resultHandler = resultHandlerMock
        )
        testCoroutineDispatcher.scheduler.advanceUntilIdle()

        // Assert
        val capturingSlot =
            CapturingSlot<MIRACLResult<Unit, AuthenticationSessionException>>()
        coVerify { resultHandlerMock.onResult(capture(capturingSlot)) }

        Assert.assertTrue(capturingSlot.captured is MIRACLError)
        Assert.assertEquals(exception, (capturingSlot.captured as MIRACLError).value)
    }


    @Test
    fun `getSigningSessionDetailsFromAppLink calls result handler with MIRACLSuccess when session details are retrieved`() {
        // Arrange
        val appLinkMock = mockkClass(Uri::class)
        val signingSessionDetails = mockkClass(SigningSessionDetails::class)

        coEvery {
            signingSessionManagerMock.getSigningSessionDetailsFromAppLink(appLinkMock)
        } returns MIRACLSuccess(signingSessionDetails)

        val resultHandlerMock =
            mockk<ResultHandler<SigningSessionDetails, SigningSessionException>>()
        every { resultHandlerMock.onResult(any()) } just runs

        // Act
        miraclTrust.getSigningSessionDetailsFromAppLink(
            appLink = appLinkMock,
            resultHandler = resultHandlerMock
        )
        testCoroutineDispatcher.scheduler.advanceUntilIdle()

        // Assert
        val capturingSlot =
            CapturingSlot<MIRACLResult<SigningSessionDetails, SigningSessionException>>()
        coVerify { resultHandlerMock.onResult(capture(capturingSlot)) }

        Assert.assertTrue(capturingSlot.captured is MIRACLSuccess)
        Assert.assertEquals(signingSessionDetails, (capturingSlot.captured as MIRACLSuccess).value)
    }

    @Test
    fun `getSigningSessionDetailsFromAppLink calls result handler with MIRACLError when session details retrieval was unsuccessful`() {
        // Arrange
        val appLinkMock = mockkClass(Uri::class)
        val exception = SigningSessionException.GetSigningSessionDetailsFail(null)

        coEvery {
            signingSessionManagerMock.getSigningSessionDetailsFromAppLink(appLinkMock)
        } returns MIRACLError(exception)

        val resultHandlerMock =
            mockk<ResultHandler<SigningSessionDetails, SigningSessionException>>()
        every { resultHandlerMock.onResult(any()) } just runs

        // Act
        miraclTrust.getSigningSessionDetailsFromAppLink(
            appLink = appLinkMock,
            resultHandler = resultHandlerMock
        )
        testCoroutineDispatcher.scheduler.advanceUntilIdle()

        // Assert
        val capturingSlot =
            CapturingSlot<MIRACLResult<SigningSessionDetails, SigningSessionException>>()
        coVerify { resultHandlerMock.onResult(capture(capturingSlot)) }

        Assert.assertTrue(capturingSlot.captured is MIRACLError)
        Assert.assertEquals(exception, (capturingSlot.captured as MIRACLError).value)
    }

    @Test
    fun `getSigningSessionDetailsFromQRCode calls result handler with MIRACLSuccess when session details are retrieved`() {
        // Arrange
        val qrCode = "https://mcl.mpin.io/dvs/#sessionId"
        val signingSessionDetails = mockkClass(SigningSessionDetails::class)

        coEvery {
            signingSessionManagerMock.getSigningSessionDetailsFromQRCode(qrCode)
        } returns MIRACLSuccess(signingSessionDetails)

        val resultHandlerMock =
            mockk<ResultHandler<SigningSessionDetails, SigningSessionException>>()
        every { resultHandlerMock.onResult(any()) } just runs

        // Act
        miraclTrust.getSigningSessionDetailsFromQRCode(
            qrCode = qrCode,
            resultHandler = resultHandlerMock
        )
        testCoroutineDispatcher.scheduler.advanceUntilIdle()

        // Assert
        val capturingSlot =
            CapturingSlot<MIRACLResult<SigningSessionDetails, SigningSessionException>>()
        coVerify { resultHandlerMock.onResult(capture(capturingSlot)) }

        Assert.assertTrue(capturingSlot.captured is MIRACLSuccess)
        Assert.assertEquals(signingSessionDetails, (capturingSlot.captured as MIRACLSuccess).value)
    }

    @Test
    fun `getSigningSessionDetailsFromQRCode calls result handler with MIRACLError when session details retrieval was unsuccessful`() {
        // Arrange
        val qrCode = "https://mcl.mpin.io/dvs/#sessionId"
        val exception = SigningSessionException.GetSigningSessionDetailsFail(null)

        coEvery {
            signingSessionManagerMock.getSigningSessionDetailsFromQRCode(qrCode)
        } returns MIRACLError(exception)

        val resultHandlerMock =
            mockk<ResultHandler<SigningSessionDetails, SigningSessionException>>()
        every { resultHandlerMock.onResult(any()) } just runs

        // Act
        miraclTrust.getSigningSessionDetailsFromQRCode(
            qrCode = qrCode,
            resultHandler = resultHandlerMock
        )
        testCoroutineDispatcher.scheduler.advanceUntilIdle()

        // Assert
        val capturingSlot =
            CapturingSlot<MIRACLResult<SigningSessionDetails, SigningSessionException>>()
        coVerify { resultHandlerMock.onResult(capture(capturingSlot)) }

        Assert.assertTrue(capturingSlot.captured is MIRACLError)
        Assert.assertEquals(exception, (capturingSlot.captured as MIRACLError).value)
    }

    @Test
    fun `abortSigningSession calls result handler with MIRACLSuccess when session abort is successful`() {
        // Arrange
        val signingSessionDetails = mockkClass(SigningSessionDetails::class)

        coEvery {
            signingSessionManagerMock.abortSigningSession(signingSessionDetails)
        } returns MIRACLSuccess(Unit)

        val resultHandlerMock = mockk<ResultHandler<Unit, SigningSessionException>>()
        every { resultHandlerMock.onResult(any()) } just runs

        // Act
        miraclTrust.abortSigningSession(signingSessionDetails, resultHandlerMock)
        testCoroutineDispatcher.scheduler.advanceUntilIdle()

        // Assert
        val capturingSlot = CapturingSlot<MIRACLResult<Unit, SigningSessionException>>()
        coVerify { resultHandlerMock.onResult(capture(capturingSlot)) }

        Assert.assertTrue(capturingSlot.captured is MIRACLSuccess)
    }

    @Test
    fun `abortSigningSession calls result handler with MIRACLError when session abort fails`() {
        // Arrange
        val signingSessionDetails = mockkClass(SigningSessionDetails::class)
        val exception = SigningSessionException.AbortSigningSessionFail(null)

        coEvery {
            signingSessionManagerMock.abortSigningSession(signingSessionDetails)
        } returns MIRACLError(exception)

        val resultHandlerMock = mockk<ResultHandler<Unit, SigningSessionException>>()
        every { resultHandlerMock.onResult(any()) } just runs

        // Act
        miraclTrust.abortSigningSession(signingSessionDetails, resultHandlerMock)
        testCoroutineDispatcher.scheduler.advanceUntilIdle()

        // Assert
        val capturingSlot = CapturingSlot<MIRACLResult<Unit, SigningSessionException>>()
        coVerify { resultHandlerMock.onResult(capture(capturingSlot)) }

        Assert.assertTrue(capturingSlot.captured is MIRACLError)
        Assert.assertEquals(exception, (capturingSlot.captured as MIRACLError).value)
    }

    @Test
    fun `getCrossDeviceSessionFromAppLink returns MIRACLSuccess when session is retrieved`() =
        runTest(testCoroutineDispatcher) {
            // Arrange
            val appLinkMock = mockkClass(Uri::class)
            val crossDeviceSession = createCrossDeviceSession()

            coEvery {
                crossDeviceSessionManagerMock.getCrossDeviceSessionFromAppLink(appLinkMock)
            } returns MIRACLSuccess(crossDeviceSession)

            // Act
            val result = miraclTrust.getCrossDeviceSessionFromAppLink(appLinkMock)

            // Assert
            Assert.assertTrue(result is MIRACLSuccess)
            Assert.assertEquals(crossDeviceSession, (result as MIRACLSuccess).value)
        }

    @Test
    fun `getCrossDeviceSessionFromAppLink returns MIRACLError when session details retrieval was unsuccessful`() =
        runTest(testCoroutineDispatcher) {
            // Arrange
            val appLinkMock = mockkClass(Uri::class)
            val exception = CrossDeviceSessionException.GetCrossDeviceSessionFail(null)

            coEvery {
                crossDeviceSessionManagerMock.getCrossDeviceSessionFromAppLink(appLinkMock)
            } returns MIRACLError(exception)

            // Act
            val result = miraclTrust.getCrossDeviceSessionFromAppLink(appLink = appLinkMock)

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertEquals(exception, (result as MIRACLError).value)
        }

    @Test
    fun `getCrossDeviceSessionFromAppLink calls result handler with MIRACLSuccess when session is retrieved`() {
        // Arrange
        val appLinkMock = mockkClass(Uri::class)
        val crossDeviceSession = createCrossDeviceSession()

        coEvery {
            crossDeviceSessionManagerMock.getCrossDeviceSessionFromAppLink(appLinkMock)
        } returns MIRACLSuccess(crossDeviceSession)

        val resultHandlerMock =
            mockk<ResultHandler<CrossDeviceSession, CrossDeviceSessionException>>()
        every { resultHandlerMock.onResult(any()) } just runs

        // Act
        miraclTrust.getCrossDeviceSessionFromAppLink(
            appLink = appLinkMock,
            resultHandler = resultHandlerMock
        )
        testCoroutineDispatcher.scheduler.advanceUntilIdle()

        // Assert
        val capturingSlot =
            CapturingSlot<MIRACLResult<CrossDeviceSession, CrossDeviceSessionException>>()
        coVerify { resultHandlerMock.onResult(capture(capturingSlot)) }

        Assert.assertTrue(capturingSlot.captured is MIRACLSuccess)
        Assert.assertEquals(
            crossDeviceSession,
            (capturingSlot.captured as MIRACLSuccess).value
        )
    }

    @Test
    fun `getCrossDeviceSessionFromAppLink calls result handler with MIRACLError when session details retrieval was unsuccessful`() {
        // Arrange
        val appLinkMock = mockkClass(Uri::class)
        val exception = CrossDeviceSessionException.GetCrossDeviceSessionFail(null)

        coEvery {
            crossDeviceSessionManagerMock.getCrossDeviceSessionFromAppLink(appLinkMock)
        } returns MIRACLError(exception)

        val resultHandlerMock =
            mockk<ResultHandler<CrossDeviceSession, CrossDeviceSessionException>>()
        every { resultHandlerMock.onResult(any()) } just runs

        // Act
        miraclTrust.getCrossDeviceSessionFromAppLink(
            appLink = appLinkMock,
            resultHandler = resultHandlerMock
        )
        testCoroutineDispatcher.scheduler.advanceUntilIdle()

        // Assert
        val capturingSlot =
            CapturingSlot<MIRACLResult<CrossDeviceSession, CrossDeviceSessionException>>()
        coVerify { resultHandlerMock.onResult(capture(capturingSlot)) }

        Assert.assertTrue(capturingSlot.captured is MIRACLError)
        Assert.assertEquals(exception, (capturingSlot.captured as MIRACLError).value)
    }

    @Test
    fun `getCrossDeviceSessionFromQRCode returns MIRACLSuccess when session details are retrieved`() =
        runTest(testCoroutineDispatcher) {
            // Arrange
            val qrCode = "https://mcl.mpin.io#accessId"
            val crossDeviceSession = createCrossDeviceSession()

            coEvery {
                crossDeviceSessionManagerMock.getCrossDeviceSessionFromQRCode(qrCode)
            } returns MIRACLSuccess(crossDeviceSession)

            // Act
            val result = miraclTrust.getCrossDeviceSessionFromQRCode(qrCode = qrCode)

            // Assert
            Assert.assertTrue(result is MIRACLSuccess)
            Assert.assertEquals(crossDeviceSession, (result as MIRACLSuccess).value)
        }

    @Test
    fun `getCrossDeviceSessionFromQRCode returns MIRACLError when session details retrieval was unsuccessful`() =
        runTest(testCoroutineDispatcher) {
            // Arrange
            val qrCode = "https://mcl.mpin.io#accessId"
            val exception = CrossDeviceSessionException.GetCrossDeviceSessionFail(null)

            coEvery {
                crossDeviceSessionManagerMock.getCrossDeviceSessionFromQRCode(qrCode)
            } returns MIRACLError(exception)

            // Act
            val result = miraclTrust.getCrossDeviceSessionFromQRCode(qrCode = qrCode)

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertEquals(exception, (result as MIRACLError).value)
        }

    @Test
    fun `getCrossDeviceSessionFromQRCode calls result handler with MIRACLSuccess when session details are retrieved`() {
        // Arrange
        val qrCode = "https://mcl.mpin.io#accessId"
        val crossDeviceSession = createCrossDeviceSession()

        coEvery {
            crossDeviceSessionManagerMock.getCrossDeviceSessionFromQRCode(qrCode)
        } returns MIRACLSuccess(crossDeviceSession)

        val resultHandlerMock =
            mockk<ResultHandler<CrossDeviceSession, CrossDeviceSessionException>>()
        every { resultHandlerMock.onResult(any()) } just runs

        // Act
        miraclTrust.getCrossDeviceSessionFromQRCode(
            qrCode = qrCode,
            resultHandler = resultHandlerMock
        )
        testCoroutineDispatcher.scheduler.advanceUntilIdle()

        // Assert
        val capturingSlot =
            CapturingSlot<MIRACLResult<CrossDeviceSession, CrossDeviceSessionException>>()
        coVerify { resultHandlerMock.onResult(capture(capturingSlot)) }

        Assert.assertTrue(capturingSlot.captured is MIRACLSuccess)
        Assert.assertEquals(
            crossDeviceSession,
            (capturingSlot.captured as MIRACLSuccess).value
        )
    }

    @Test
    fun `getCrossDeviceSessionFromQRCode calls result handler with MIRACLError when session details retrieval was unsuccessful`() {
        // Arrange
        val qrCode = "https://mcl.mpin.io#accessId"
        val exception = CrossDeviceSessionException.GetCrossDeviceSessionFail(null)

        coEvery {
            crossDeviceSessionManagerMock.getCrossDeviceSessionFromQRCode(qrCode)
        } returns MIRACLError(exception)

        val resultHandlerMock =
            mockk<ResultHandler<CrossDeviceSession, CrossDeviceSessionException>>()
        every { resultHandlerMock.onResult(any()) } just runs

        // Act
        miraclTrust.getCrossDeviceSessionFromQRCode(
            qrCode = qrCode,
            resultHandler = resultHandlerMock
        )
        testCoroutineDispatcher.scheduler.advanceUntilIdle()

        // Assert
        val capturingSlot =
            CapturingSlot<MIRACLResult<CrossDeviceSession, CrossDeviceSessionException>>()
        coVerify { resultHandlerMock.onResult(capture(capturingSlot)) }

        Assert.assertTrue(capturingSlot.captured is MIRACLError)
        Assert.assertEquals(exception, (capturingSlot.captured as MIRACLError).value)
    }

    @Test
    fun `getCrossDeviceSessionFromNotificationPayload returns MIRACLSuccess when session details are retrieved`() =
        runTest(testCoroutineDispatcher) {
            // Arrange
            val payload = mapOf(
                SessionManager.PUSH_NOTIFICATION_QR_URL to "https://mcl.mpin.io/mobile-login/#accessId"
            )
            val crossDeviceSession = createCrossDeviceSession()

            coEvery {
                crossDeviceSessionManagerMock.getCrossDeviceSessionFromNotificationPayload(payload)
            } returns MIRACLSuccess(crossDeviceSession)

            // Act
            val result = miraclTrust.getCrossDeviceSessionFromNotificationPayload(payload = payload)

            // Assert
            Assert.assertTrue(result is MIRACLSuccess)
            Assert.assertEquals(crossDeviceSession, (result as MIRACLSuccess).value)
        }

    @Test
    fun `getCrossDeviceSessionFromNotificationPayload returns MIRACLError when session details retrieval was unsuccessful`() =
        runTest(testCoroutineDispatcher) {
            // Arrange
            val payload = mapOf(
                CrossDeviceSessionManager.PUSH_NOTIFICATION_QR_URL to "https://mcl.mpin.io/mobile-login/#accessId"
            )
            val exception = CrossDeviceSessionException.GetCrossDeviceSessionFail(null)

            coEvery {
                crossDeviceSessionManagerMock.getCrossDeviceSessionFromNotificationPayload(payload)
            } returns MIRACLError(exception)

            // Act
            val result = miraclTrust.getCrossDeviceSessionFromNotificationPayload(payload = payload)

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertEquals(exception, (result as MIRACLError).value)
        }

    @Test
    fun `getCrossDeviceSessionFromNotificationPayload calls result handler with MIRACLSuccess when session details are retrieved`() {
        // Arrange
        val payload = mapOf(
            SessionManager.PUSH_NOTIFICATION_QR_URL to "https://mcl.mpin.io/mobile-login/#accessId"
        )
        val crossDeviceSession = createCrossDeviceSession()

        coEvery {
            crossDeviceSessionManagerMock.getCrossDeviceSessionFromNotificationPayload(payload)
        } returns MIRACLSuccess(crossDeviceSession)

        val resultHandlerMock =
            mockk<ResultHandler<CrossDeviceSession, CrossDeviceSessionException>>()
        every { resultHandlerMock.onResult(any()) } just runs

        // Act
        miraclTrust.getCrossDeviceSessionFromNotificationPayload(
            payload = payload,
            resultHandler = resultHandlerMock
        )
        testCoroutineDispatcher.scheduler.advanceUntilIdle()

        // Assert
        val capturingSlot =
            CapturingSlot<MIRACLResult<CrossDeviceSession, CrossDeviceSessionException>>()
        coVerify { resultHandlerMock.onResult(capture(capturingSlot)) }

        Assert.assertTrue(capturingSlot.captured is MIRACLSuccess)
        Assert.assertEquals(
            crossDeviceSession,
            (capturingSlot.captured as MIRACLSuccess).value
        )
    }

    @Test
    fun `getCrossDeviceSessionFromNotificationPayload calls result handler with MIRACLError when session details retrieval was unsuccessful`() {
        // Arrange
        val payload = mapOf(
            CrossDeviceSessionManager.PUSH_NOTIFICATION_QR_URL to "https://mcl.mpin.io/mobile-login/#accessId"
        )
        val exception = CrossDeviceSessionException.GetCrossDeviceSessionFail(null)

        coEvery {
            crossDeviceSessionManagerMock.getCrossDeviceSessionFromNotificationPayload(payload)
        } returns MIRACLError(exception)

        val resultHandlerMock =
            mockk<ResultHandler<CrossDeviceSession, CrossDeviceSessionException>>()
        every { resultHandlerMock.onResult(any()) } just runs

        // Act
        miraclTrust.getCrossDeviceSessionFromNotificationPayload(
            payload = payload,
            resultHandler = resultHandlerMock
        )
        testCoroutineDispatcher.scheduler.advanceUntilIdle()

        // Assert
        val capturingSlot =
            CapturingSlot<MIRACLResult<CrossDeviceSession, CrossDeviceSessionException>>()
        coVerify { resultHandlerMock.onResult(capture(capturingSlot)) }

        Assert.assertTrue(capturingSlot.captured is MIRACLError)
        Assert.assertEquals(exception, (capturingSlot.captured as MIRACLError).value)
    }

    @Test
    fun `abortCrossDeviceSession returns MIRACLSuccess when session abort was successful`() =
        runTest(testCoroutineDispatcher) {
            // Arrange
            val crossDeviceSession = createCrossDeviceSession()

            coEvery {
                crossDeviceSessionManagerMock.abortSession(crossDeviceSession)
            } returns MIRACLSuccess(Unit)

            // Act
            val result = miraclTrust.abortCrossDeviceSession(crossDeviceSession)

            // Assert
            Assert.assertTrue(result is MIRACLSuccess)
        }

    @Test
    fun `abortCrossDeviceSession returns MIRACLError when session abort was unsuccessful`() =
        runTest(testCoroutineDispatcher) {
            // Arrange
            val crossDeviceSession = createCrossDeviceSession()
            val exception = CrossDeviceSessionException.AbortCrossDeviceSessionFail(null)

            coEvery {
                crossDeviceSessionManagerMock.abortSession(crossDeviceSession)
            } returns MIRACLError(exception)

            // Act
            val result = miraclTrust.abortCrossDeviceSession(crossDeviceSession)

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertEquals(exception, (result as MIRACLError).value)
        }

    @Test
    fun `abortCrossDeviceSession calls result handler with MIRACLSuccess when session abort was successful`() {
        // Arrange
        val crossDeviceSession = createCrossDeviceSession()

        coEvery {
            crossDeviceSessionManagerMock.abortSession(crossDeviceSession)
        } returns MIRACLSuccess(Unit)

        val resultHandlerMock = mockk<ResultHandler<Unit, CrossDeviceSessionException>>()
        every { resultHandlerMock.onResult(any()) } just runs

        // Act
        miraclTrust.abortCrossDeviceSession(crossDeviceSession, resultHandlerMock)
        testCoroutineDispatcher.scheduler.advanceUntilIdle()

        // Assert
        val capturingSlot = CapturingSlot<MIRACLResult<Unit, CrossDeviceSessionException>>()
        coVerify { resultHandlerMock.onResult(capture(capturingSlot)) }

        Assert.assertTrue(capturingSlot.captured is MIRACLSuccess)
    }

    @Test
    fun `abortCrossDeviceSession calls result handler with MIRACLError when session abort was unsuccessful`() {
        // Arrange
        val crossDeviceSession = createCrossDeviceSession()
        val exception = CrossDeviceSessionException.AbortCrossDeviceSessionFail(null)

        coEvery {
            crossDeviceSessionManagerMock.abortSession(crossDeviceSession)
        } returns MIRACLError(exception)

        val resultHandlerMock = mockk<ResultHandler<Unit, CrossDeviceSessionException>>()
        every { resultHandlerMock.onResult(any()) } just runs

        // Act
        miraclTrust.abortCrossDeviceSession(crossDeviceSession, resultHandlerMock)
        testCoroutineDispatcher.scheduler.advanceUntilIdle()

        // Assert
        val capturingSlot = CapturingSlot<MIRACLResult<Unit, CrossDeviceSessionException>>()
        coVerify { resultHandlerMock.onResult(capture(capturingSlot)) }

        Assert.assertTrue(capturingSlot.captured is MIRACLError)
        Assert.assertEquals(exception, (capturingSlot.captured as MIRACLError).value)
    }

    @Test
    fun `sendVerificationEmail returns MIRACLSuccess when input is valid and verification was successful`() =
        runTest(testCoroutineDispatcher) {
            // Arrange
            val userId = randomUuidString()

            coEvery {
                verificatorMock.sendVerificationEmail(
                    userId,
                    projectId,
                    deviceName,
                    null
                )
            } returns MIRACLSuccess(
                VerificationResponse(
                    backoff = Random.nextLong(),
                    method = EmailVerificationMethod.Link
                )
            )

            // Act
            val result = miraclTrust.sendVerificationEmail(userId)

            // Assert
            Assert.assertTrue(result is MIRACLSuccess)
        }

    @Test
    fun `sendVerificationEmail returns MIRACLError when verification was unsuccessful`() =
        runTest(testCoroutineDispatcher) {
            // Arrange
            val userId = randomUuidString()
            val verificationException = VerificationException.VerificationFail()

            coEvery {
                verificatorMock.sendVerificationEmail(
                    userId,
                    projectId,
                    deviceName,
                    null
                )
            } returns MIRACLError(verificationException)
            // Act
            val result = miraclTrust.sendVerificationEmail(userId)

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertEquals(verificationException, (result as MIRACLError).value)
        }

    @Test
    fun `sendVerificationEmail calls result handler with MIRACLSuccess when input is valid and verification was successful`() {
        // Arrange
        val userId = randomUuidString()

        coEvery {
            verificatorMock.sendVerificationEmail(
                userId,
                projectId,
                deviceName,
                null
            )
        } returns MIRACLSuccess(
            VerificationResponse(
                backoff = Random.nextLong(),
                method = EmailVerificationMethod.Link
            )
        )

        val resultHandlerMock = mockk<ResultHandler<VerificationResponse, VerificationException>>()
        every { resultHandlerMock.onResult(any()) } just runs

        // Act
        miraclTrust.sendVerificationEmail(
            userId = userId,
            resultHandler = resultHandlerMock
        )
        testCoroutineDispatcher.scheduler.advanceUntilIdle()

        // Assert
        val capturingSlot =
            CapturingSlot<MIRACLResult<VerificationResponse, VerificationException>>()
        coVerify { resultHandlerMock.onResult(capture(capturingSlot)) }

        val result = capturingSlot.captured

        Assert.assertTrue(result is MIRACLSuccess)
    }

    @Test
    fun `sendVerificationEmail calls result handler with MIRACLError when verification was unsuccessful`() {
        // Arrange
        val userId = randomUuidString()
        val verificationException = VerificationException.VerificationFail()

        coEvery {
            verificatorMock.sendVerificationEmail(
                userId,
                projectId,
                deviceName,
                null
            )
        } returns MIRACLError(verificationException)

        val resultHandlerMock = mockk<ResultHandler<VerificationResponse, VerificationException>>()
        every { resultHandlerMock.onResult(any()) } just runs

        // Act
        miraclTrust.sendVerificationEmail(
            userId = userId,
            resultHandler = resultHandlerMock
        )
        testCoroutineDispatcher.scheduler.advanceUntilIdle()

        // Assert
        val capturingSlot =
            CapturingSlot<MIRACLResult<VerificationResponse, VerificationException>>()
        coVerify { resultHandlerMock.onResult(capture(capturingSlot)) }

        val result = capturingSlot.captured

        Assert.assertTrue(result is MIRACLError)
        Assert.assertEquals(verificationException, (result as MIRACLError).value)
    }

    @Test
    fun `sendVerificationEmail with authenticationSessionDetails calls result handler with MIRACLSuccess when input is valid and verification was successful`() {
        // Arrange
        val userId = randomUuidString()

        val authenticationSessionDetails = mockkClass(AuthenticationSessionDetails::class)

        coEvery {
            verificatorMock.sendVerificationEmail(
                userId,
                projectId,
                deviceName,
                authenticationSessionDetails
            )
        } returns MIRACLSuccess(
            VerificationResponse(
                backoff = Random.nextLong(),
                method = EmailVerificationMethod.Link
            )
        )

        val resultHandlerMock = mockk<ResultHandler<VerificationResponse, VerificationException>>()
        every { resultHandlerMock.onResult(any()) } just runs

        // Act
        miraclTrust.sendVerificationEmail(
            userId = userId,
            authenticationSessionDetails = authenticationSessionDetails,
            resultHandler = resultHandlerMock
        )
        testCoroutineDispatcher.scheduler.advanceUntilIdle()

        // Assert
        val capturingSlot =
            CapturingSlot<MIRACLResult<VerificationResponse, VerificationException>>()
        coVerify { resultHandlerMock.onResult(capture(capturingSlot)) }

        val result = capturingSlot.captured

        Assert.assertTrue(result is MIRACLSuccess)
    }

    @Test
    fun `sendVerificationEmail with authenticationSessionDetails calls result handler with MIRACLError when verification was unsuccessful`() {
        // Arrange
        val userId = randomUuidString()

        val authenticationSessionDetails = mockkClass(AuthenticationSessionDetails::class)

        val verificationException = VerificationException.VerificationFail()

        coEvery {
            verificatorMock.sendVerificationEmail(
                userId,
                projectId,
                deviceName,
                authenticationSessionDetails
            )
        } returns MIRACLError(verificationException)

        val resultHandlerMock = mockk<ResultHandler<VerificationResponse, VerificationException>>()
        every { resultHandlerMock.onResult(any()) } just runs

        // Act
        miraclTrust.sendVerificationEmail(
            userId = userId,
            authenticationSessionDetails = authenticationSessionDetails,
            resultHandler = resultHandlerMock
        )
        testCoroutineDispatcher.scheduler.advanceUntilIdle()

        // Assert
        val capturingSlot =
            CapturingSlot<MIRACLResult<VerificationResponse, VerificationException>>()
        coVerify { resultHandlerMock.onResult(capture(capturingSlot)) }

        val result = capturingSlot.captured

        Assert.assertTrue(result is MIRACLError)
        Assert.assertEquals(verificationException, (result as MIRACLError).value)
    }

    @Test
    fun `sendVerificationEmail with CrossDeviceSession returns MIRACLSuccess when input is valid and verification was successful`() =
        runTest(testCoroutineDispatcher) {
            // Arrange
            val userId = randomUuidString()
            val crossDeviceSession = createCrossDeviceSession()

            coEvery {
                verificatorMock.sendVerificationEmail(
                    userId = userId,
                    projectId = projectId,
                    deviceName = deviceName,
                    crossDeviceSession = crossDeviceSession
                )
            } returns MIRACLSuccess(
                VerificationResponse(
                    backoff = Random.nextLong(),
                    method = EmailVerificationMethod.Link
                )
            )

            // Act
            val result = miraclTrust.sendVerificationEmail(
                userId = userId,
                crossDeviceSession = crossDeviceSession
            )

            // Assert
            Assert.assertTrue(result is MIRACLSuccess)
        }

    @Test
    fun `sendVerificationEmail with CrossDeviceSession returns MIRACLError when verification was unsuccessful`() =
        runTest(testCoroutineDispatcher) {
            // Arrange
            val userId = randomUuidString()
            val crossDeviceSession = createCrossDeviceSession()
            val verificationException = VerificationException.VerificationFail()

            coEvery {
                verificatorMock.sendVerificationEmail(
                    userId = userId,
                    projectId = projectId,
                    deviceName = deviceName,
                    crossDeviceSession = crossDeviceSession
                )
            } returns MIRACLError(verificationException)

            // Act
            val result = miraclTrust.sendVerificationEmail(
                userId = userId,
                crossDeviceSession = crossDeviceSession
            )

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertEquals(verificationException, (result as MIRACLError).value)
        }

    @Test
    fun `sendVerificationEmail with CrossDeviceSession calls result handler with MIRACLSuccess when input is valid and verification was successful`() {
        // Arrange
        val userId = randomUuidString()

        val crossDeviceSession = createCrossDeviceSession()

        coEvery {
            verificatorMock.sendVerificationEmail(
                userId = userId,
                projectId = projectId,
                deviceName = deviceName,
                crossDeviceSession = crossDeviceSession
            )
        } returns MIRACLSuccess(
            VerificationResponse(
                backoff = Random.nextLong(),
                method = EmailVerificationMethod.Link
            )
        )

        val resultHandlerMock = mockk<ResultHandler<VerificationResponse, VerificationException>>()
        every { resultHandlerMock.onResult(any()) } just runs

        // Act
        miraclTrust.sendVerificationEmail(
            userId = userId,
            crossDeviceSession = crossDeviceSession,
            resultHandler = resultHandlerMock
        )
        testCoroutineDispatcher.scheduler.advanceUntilIdle()

        // Assert
        val capturingSlot =
            CapturingSlot<MIRACLResult<VerificationResponse, VerificationException>>()
        coVerify { resultHandlerMock.onResult(capture(capturingSlot)) }

        val result = capturingSlot.captured

        Assert.assertTrue(result is MIRACLSuccess)
    }

    @Test
    fun `sendVerificationEmail with CrossDeviceSession calls result handler with MIRACLError when verification was unsuccessful`() {
        // Arrange
        val userId = randomUuidString()

        val crossDeviceSession = createCrossDeviceSession()

        val verificationException = VerificationException.VerificationFail()

        coEvery {
            verificatorMock.sendVerificationEmail(
                userId = userId,
                projectId = projectId,
                deviceName = deviceName,
                crossDeviceSession = crossDeviceSession
            )
        } returns MIRACLError(verificationException)

        val resultHandlerMock = mockk<ResultHandler<VerificationResponse, VerificationException>>()
        every { resultHandlerMock.onResult(any()) } just runs

        // Act
        miraclTrust.sendVerificationEmail(
            userId = userId,
            crossDeviceSession = crossDeviceSession,
            resultHandler = resultHandlerMock
        )
        testCoroutineDispatcher.scheduler.advanceUntilIdle()

        // Assert
        val capturingSlot =
            CapturingSlot<MIRACLResult<VerificationResponse, VerificationException>>()
        coVerify { resultHandlerMock.onResult(capture(capturingSlot)) }

        val result = capturingSlot.captured

        Assert.assertTrue(result is MIRACLError)
        Assert.assertEquals(verificationException, (result as MIRACLError).value)
    }

    @Test
    fun `generateQuickCode returns MIRACLSuccess when QuickCode generation is successful`() =
        runTest(testCoroutineDispatcher) {
            // Arrange
            val user = mockk<User>()
            coEvery {
                verificatorMock.generateQuickCode(
                    user = user,
                    pinProvider = pinProviderMock,
                    deviceName = deviceName
                )
            } returns MIRACLSuccess(
                QuickCode(
                    code = randomUuidString(),
                    expireTime = Date().time,
                    ttlSeconds = Random.nextInt(1..9999)
                )
            )

            // Act
            val result = miraclTrust.generateQuickCode(
                user = user,
                pinProvider = pinProviderMock
            )

            // Assert
            Assert.assertTrue(result is MIRACLSuccess)
        }

    @Test
    fun `generateQuickCode returns MIRACLError when QuickCode generation failed`() =
        runTest(testCoroutineDispatcher) {
            // Arrange
            val quickCodeException = QuickCodeException.GenerationFail()
            coEvery {
                verificatorMock.generateQuickCode(
                    user = any(),
                    pinProvider = any(),
                    deviceName = any()
                )
            } returns MIRACLError(quickCodeException)

            val authenticationUser = mockk<User>()

            // Act
            val result = miraclTrust.generateQuickCode(
                user = authenticationUser,
                pinProvider = pinProviderMock
            )

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertEquals(quickCodeException, (result as MIRACLError).value)
        }

    @Test
    fun `generateQuickCode calls result handler with MIRACLSuccess when QuickCode generation is successful`() {
        // Arrange
        val user = mockk<User>()
        coEvery {
            verificatorMock.generateQuickCode(
                user = user,
                pinProvider = pinProviderMock,
                deviceName = deviceName
            )
        } returns MIRACLSuccess(
            QuickCode(
                code = randomUuidString(),
                expireTime = Date().time,
                ttlSeconds = Random.nextInt(1..9999)
            )
        )

        val resultHandlerMock = mockk<ResultHandler<QuickCode, QuickCodeException>>()
        every { resultHandlerMock.onResult(any()) } just runs

        // Act
        miraclTrust.generateQuickCode(
            user = user,
            pinProvider = pinProviderMock,
            resultHandler = resultHandlerMock
        )
        testCoroutineDispatcher.scheduler.advanceUntilIdle()

        // Assert
        val capturingSlot = CapturingSlot<MIRACLResult<QuickCode, QuickCodeException>>()
        coVerify { resultHandlerMock.onResult(capture(capturingSlot)) }

        Assert.assertTrue(capturingSlot.captured is MIRACLSuccess)
    }

    @Test
    fun `generateQuickCode calls result handler with MIRACLError when QuickCode generation failed`() {
        // Arrange
        val quickCodeException = QuickCodeException.GenerationFail()
        coEvery {
            verificatorMock.generateQuickCode(
                user = any(),
                pinProvider = any(),
                deviceName = any()
            )
        } returns MIRACLError(quickCodeException)

        val resultHandlerMock = mockk<ResultHandler<QuickCode, QuickCodeException>>()
        every { resultHandlerMock.onResult(any()) } just runs

        val authenticationUser = mockk<User>()

        // Act
        miraclTrust.generateQuickCode(
            user = authenticationUser,
            pinProvider = pinProviderMock,
            resultHandler = resultHandlerMock
        )
        testCoroutineDispatcher.scheduler.advanceUntilIdle()

        // Assert
        val capturingSlot = CapturingSlot<MIRACLResult<QuickCode, QuickCodeException>>()
        coVerify { resultHandlerMock.onResult(capture(capturingSlot)) }

        val result = capturingSlot.captured

        Assert.assertTrue(result is MIRACLError)
        Assert.assertEquals(quickCodeException, (result as MIRACLError).value)
    }

    @Test
    fun `getActivationToken with verification URI returns MIRACLSuccess containing the activation token, the userId and the accessId when input is valid and verification confirmation is successful`() =
        runTest(testCoroutineDispatcher) {
            // Arrange
            val accessId = randomUuidString()
            val userId = randomUuidString()
            val verifyUriMock = mockkClass(Uri::class)

            coEvery {
                verificatorMock.getActivationToken(verifyUriMock)
            } returns MIRACLSuccess(
                ActivationTokenResponse(projectId, accessId, userId, activationToken)
            )

            // Act
            val result = miraclTrust.getActivationToken(verifyUriMock)

            // Assert
            Assert.assertTrue(result is MIRACLSuccess)
            Assert.assertEquals(activationToken, (result as MIRACLSuccess).value.activationToken)
            Assert.assertEquals(userId, result.value.userId)
            Assert.assertEquals(accessId, result.value.accessId)
        }

    @Test
    fun `getActivationToken with verification URI returns MIRACLError when verification confirmation is unsuccessful`() =
        runTest(testCoroutineDispatcher) {
            // Arrange
            val verificationException = ActivationTokenException.GetActivationTokenFail()

            coEvery {
                verificatorMock.getActivationToken(any())
            } returns MIRACLError(verificationException)

            // Act
            val result = miraclTrust.getActivationToken(verificationUri = mockk())

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertEquals(verificationException, (result as MIRACLError).value)
        }

    @Test
    fun `getActivationToken with verification URI calls result handler with MIRACLSuccess containing the activation token, the userId and the accessId when input is valid and verification confirmation is successful`() {
        // Arrange
        val accessId = randomUuidString()
        val userId = randomUuidString()
        val verifyUriMock = mockkClass(Uri::class)

        coEvery {
            verificatorMock.getActivationToken(verifyUriMock)
        } returns MIRACLSuccess(
            ActivationTokenResponse(projectId, accessId, userId, activationToken)
        )

        val resultHandlerMock =
            mockk<ResultHandler<ActivationTokenResponse, ActivationTokenException>>()
        every { resultHandlerMock.onResult(any()) } just runs

        // Act
        miraclTrust.getActivationToken(
            verificationUri = verifyUriMock,
            resultHandler = resultHandlerMock
        )
        testCoroutineDispatcher.scheduler.advanceUntilIdle()

        // Assert
        val capturingSlot =
            CapturingSlot<MIRACLResult<ActivationTokenResponse, ActivationTokenException>>()
        coVerify { resultHandlerMock.onResult(capture(capturingSlot)) }

        val result = capturingSlot.captured

        Assert.assertTrue(result is MIRACLSuccess)
        Assert.assertEquals(activationToken, (result as MIRACLSuccess).value.activationToken)
        Assert.assertEquals(userId, result.value.userId)
        Assert.assertEquals(accessId, result.value.accessId)
    }

    @Test
    fun `getActivationToken with verification URI calls result handler with MIRACLError when verification confirmation is unsuccessful`() {
        // Arrange
        val verificationException = ActivationTokenException.GetActivationTokenFail()

        coEvery {
            verificatorMock.getActivationToken(any())
        } returns MIRACLError(verificationException)

        val resultHandlerMock =
            mockk<ResultHandler<ActivationTokenResponse, ActivationTokenException>>()
        every { resultHandlerMock.onResult(any()) } just runs

        // Act
        miraclTrust.getActivationToken(
            verificationUri = mockk(),
            resultHandler = resultHandlerMock
        )
        testCoroutineDispatcher.scheduler.advanceUntilIdle()

        // Assert
        val capturingSlot =
            CapturingSlot<MIRACLResult<ActivationTokenResponse, ActivationTokenException>>()
        coVerify { resultHandlerMock.onResult(capture(capturingSlot)) }

        val result = capturingSlot.captured

        Assert.assertTrue(result is MIRACLError)
        Assert.assertEquals(verificationException, (result as MIRACLError).value)
    }

    @Test
    fun `getActivationToken with verification code returns MIRACLSuccess containing the activation token, the userId and the accessId when input is valid and verification confirmation is successful`() =
        runTest(testCoroutineDispatcher) {
            // Arrange
            val accessId = randomUuidString()
            val userId = randomUuidString()
            val code = randomUuidString()

            coEvery {
                verificatorMock.getActivationToken(userId, code)
            } returns MIRACLSuccess(
                ActivationTokenResponse(projectId, accessId, userId, activationToken)
            )

            // Act
            val result = miraclTrust.getActivationToken(
                userId = userId,
                code = code
            )

            // Assert
            Assert.assertTrue(result is MIRACLSuccess)
            Assert.assertEquals(activationToken, (result as MIRACLSuccess).value.activationToken)
            Assert.assertEquals(userId, result.value.userId)
            Assert.assertEquals(accessId, result.value.accessId)
        }

    @Test
    fun `getActivationToken with verification code returns MIRACLError when verification confirmation is unsuccessful`() =
        runTest(testCoroutineDispatcher) {
            // Arrange
            val verificationException = ActivationTokenException.GetActivationTokenFail()

            coEvery {
                verificatorMock.getActivationToken(any(), any())
            } returns MIRACLError(verificationException)

            // Act
            val result = miraclTrust.getActivationToken(
                userId = randomUuidString(),
                code = randomUuidString()
            )

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertEquals(verificationException, (result as MIRACLError).value)
        }

    @Test
    fun `getActivationToken with verification code calls result handler with MIRACLSuccess containing the activation token, the userId and the accessId when input is valid and verification confirmation is successful`() {
        // Arrange
        val accessId = randomUuidString()
        val userId = randomUuidString()
        val code = randomUuidString()

        coEvery {
            verificatorMock.getActivationToken(userId, code)
        } returns MIRACLSuccess(
            ActivationTokenResponse(projectId, accessId, userId, activationToken)
        )

        val resultHandlerMock =
            mockk<ResultHandler<ActivationTokenResponse, ActivationTokenException>>()
        every { resultHandlerMock.onResult(any()) } just runs

        // Act
        miraclTrust.getActivationToken(
            userId = userId,
            code = code,
            resultHandler = resultHandlerMock
        )
        testCoroutineDispatcher.scheduler.advanceUntilIdle()

        // Assert
        val capturingSlot =
            CapturingSlot<MIRACLResult<ActivationTokenResponse, ActivationTokenException>>()
        coVerify { resultHandlerMock.onResult(capture(capturingSlot)) }

        val result = capturingSlot.captured

        Assert.assertTrue(result is MIRACLSuccess)
        Assert.assertEquals(activationToken, (result as MIRACLSuccess).value.activationToken)
        Assert.assertEquals(userId, result.value.userId)
        Assert.assertEquals(accessId, result.value.accessId)
    }

    @Test
    fun `getActivationToken with verification code calls result handler with MIRACLError when verification confirmation is unsuccessful`() {
        // Arrange
        val verificationException = ActivationTokenException.GetActivationTokenFail()

        coEvery {
            verificatorMock.getActivationToken(any(), any())
        } returns MIRACLError(verificationException)

        val resultHandlerMock =
            mockk<ResultHandler<ActivationTokenResponse, ActivationTokenException>>()
        every { resultHandlerMock.onResult(any()) } just runs

        // Act
        miraclTrust.getActivationToken(
            userId = randomUuidString(),
            code = randomUuidString(),
            resultHandler = resultHandlerMock
        )
        testCoroutineDispatcher.scheduler.advanceUntilIdle()

        // Assert
        val capturingSlot =
            CapturingSlot<MIRACLResult<ActivationTokenResponse, ActivationTokenException>>()
        coVerify { resultHandlerMock.onResult(capture(capturingSlot)) }

        val result = capturingSlot.captured

        Assert.assertTrue(result is MIRACLError)
        Assert.assertEquals(verificationException, (result as MIRACLError).value)
    }

    @Test
    fun `register returns MIRACLSuccess with value of registered user when input is valid and registration was successful`() =
        runTest(testCoroutineDispatcher) {
            // Arrange
            val userId = randomUuidString()
            val user = mockk<User>()

            coEvery {
                registratorMock.register(
                    userId = userId,
                    projectId,
                    activationToken = activationToken,
                    pinProvider = pinProviderMock,
                    deviceName = deviceName,
                    null
                )
            } returns MIRACLSuccess(value = user)
            every { userStorageMock.getUser(userId, projectId) } returns null

            // Act
            val result = miraclTrust.register(
                userId = userId,
                activationToken = activationToken,
                pinProvider = pinProviderMock
            )

            // Assert
            Assert.assertTrue(result is MIRACLSuccess)
        }

    @Test
    fun `register returns MIRACLError when registration fails`() =
        runTest(testCoroutineDispatcher) {
            // Arrange
            val userId = randomUuidString()
            val registrationException = RegistrationException.RegistrationFail(Exception())

            coEvery {
                registratorMock.register(
                    userId = any(),
                    projectId,
                    activationToken = activationToken,
                    pinProvider = any(),
                    deviceName = any(),
                    null
                )
            } returns MIRACLError(registrationException)

            // Act
            val result = miraclTrust.register(
                userId = userId,
                activationToken = activationToken,
                pinProvider = pinProviderMock
            )

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertEquals(registrationException, (result as MIRACLError).value)
        }

    @Test
    fun `register calls result handler with MIRACLSuccess with value of registered user when input is valid and registration was successful`() {
        // Arrange
        val userId = randomUuidString()
        val user = mockk<User>()

        coEvery {
            registratorMock.register(
                userId = userId,
                projectId,
                activationToken = activationToken,
                pinProvider = pinProviderMock,
                deviceName = deviceName,
                null
            )
        } returns MIRACLSuccess(value = user)
        every { userStorageMock.getUser(userId, projectId) } returns null

        val resultHandlerMock = mockk<ResultHandler<User, RegistrationException>>()
        every { resultHandlerMock.onResult(any()) } just runs

        // Act
        miraclTrust.register(
            userId = userId,
            activationToken = activationToken,
            pinProvider = pinProviderMock,
            resultHandler = resultHandlerMock
        )
        testCoroutineDispatcher.scheduler.advanceUntilIdle()

        // Assert
        val capturingSlot = CapturingSlot<MIRACLResult<User, RegistrationException>>()
        coVerify { resultHandlerMock.onResult(capture(capturingSlot)) }

        val result = capturingSlot.captured

        Assert.assertTrue(result is MIRACLSuccess)
    }

    @Test
    fun `register calls result handler with MIRACLSuccess when passed arguments have leading and trailing characters matching whitespace`() {
        // Arrange
        val actToken = randomUuidString()
        val userId = randomUuidString()
        val user = mockk<User>()

        coEvery {
            registratorMock.register(
                userId = any(),
                projectId,
                activationToken = actToken,
                pinProvider = any(),
                deviceName = any(),
                null
            )
        } returns MIRACLSuccess(value = user)

        val resultHandlerMock = mockk<ResultHandler<User, RegistrationException>>()
        every { resultHandlerMock.onResult(any()) } just runs

        // Act
        miraclTrust.register(
            userId = " $userId ",
            activationToken = actToken,
            pinProvider = pinProviderMock,
            resultHandler = resultHandlerMock
        )
        testCoroutineDispatcher.scheduler.advanceUntilIdle()

        // Assert
        val capturingSlot = CapturingSlot<MIRACLResult<User, RegistrationException>>()
        verify { resultHandlerMock.onResult(capture(capturingSlot)) }

        val result = capturingSlot.captured

        Assert.assertTrue(result is MIRACLSuccess)
    }

    @Test
    fun `register calls result handler with MIRACLError when registration fails`() {
        // Arrange
        val userId = randomUuidString()
        val registrationException = RegistrationException.RegistrationFail(Exception())

        coEvery {
            registratorMock.register(
                userId = any(),
                projectId,
                activationToken = activationToken,
                pinProvider = any(),
                deviceName = any(),
                null
            )
        } returns MIRACLError(registrationException)

        val resultHandlerMock = mockk<ResultHandler<User, RegistrationException>>()
        every { resultHandlerMock.onResult(any()) } just runs

        // Act
        miraclTrust.register(
            userId = userId,
            activationToken = activationToken,
            pinProvider = pinProviderMock,
            resultHandler = resultHandlerMock
        )
        testCoroutineDispatcher.scheduler.advanceUntilIdle()

        // Assert
        val capturingSlot = CapturingSlot<MIRACLResult<User, RegistrationException>>()
        coVerify { resultHandlerMock.onResult(capture(capturingSlot)) }

        val result = capturingSlot.captured

        Assert.assertTrue(result is MIRACLError)
        Assert.assertEquals(registrationException, (result as MIRACLError).value)
    }

    @Test
    fun `register is called only after sdk is configured and the input is valid`() {
        // Arrange
        val config = createConfiguration()

        MIRACLTrust.configure(
            context = mockk(),
            configuration = config
        )
        val sdk = MIRACLTrust.getInstance()
        sdk.resultHandlerDispatcher = testCoroutineDispatcher

        val userId = randomUuidString()
        val user = mockk<User>()

        coEvery {
            registratorMock.register(
                userId = any(),
                projectId,
                activationToken = activationToken,
                pinProvider = any(),
                deviceName = any(),
                null
            )
        } returns MIRACLSuccess(value = user)

        val resultHandlerMock = mockk<ResultHandler<User, RegistrationException>>()
        every { resultHandlerMock.onResult(any()) } just runs

        // Act
        sdk.register(
            userId = userId,
            activationToken = activationToken,
            pinProvider = pinProviderMock,
            resultHandler = resultHandlerMock
        )
        testCoroutineDispatcher.scheduler.advanceUntilIdle()

        // Assert
        val capturingSlot = CapturingSlot<MIRACLResult<User, RegistrationException>>()
        coVerify { resultHandlerMock.onResult(capture(capturingSlot)) }

        val result = capturingSlot.captured

        Assert.assertTrue(result is MIRACLSuccess)
        coVerifyOrder {
            componentFactoryMock.createRegistrator(any(), any())
            registratorMock.register(
                userId = any(),
                projectId,
                activationToken = activationToken,
                pinProvider = any(),
                deviceName = any(),
                null
            )
        }
    }

    @Test
    fun `authenticateWithAppLink returns a MIRACLSuccess when input is valid and user is authenticated`() =
        runTest(testCoroutineDispatcher) {
            // Arrange
            val authenticationUser = mockk<User>()
            val appLinkMock = mockkClass(Uri::class)
            coEvery {
                authenticatorMock.authenticateWithAppLink(
                    authenticationUser,
                    appLinkMock,
                    pinProviderMock,
                    arrayOf(AuthenticatorScopes.OIDC.value),
                    deviceName
                )
            } returns MIRACLSuccess(AuthenticateResponse(0, "", null, null))

            // Act
            val result = miraclTrust.authenticateWithAppLink(
                user = authenticationUser,
                appLink = appLinkMock,
                pinProvider = pinProviderMock
            )

            // Assert
            Assert.assertTrue(result is MIRACLSuccess)
        }

    @Test
    fun `authenticateWithAppLink returns a MIRACLError when authentication fails`() =
        runTest(testCoroutineDispatcher) {
            // Arrange
            val authenticationUser = mockk<User>()
            val appLinkMock = mockkClass(Uri::class)
            val authenticationException = AuthenticationException.AuthenticationFail()
            coEvery {
                authenticatorMock.authenticateWithAppLink(
                    authenticationUser,
                    appLinkMock,
                    pinProviderMock,
                    arrayOf(AuthenticatorScopes.OIDC.value),
                    deviceName
                )
            } returns MIRACLError(authenticationException)

            // Act
            val result = miraclTrust.authenticateWithAppLink(
                user = authenticationUser,
                appLink = appLinkMock,
                pinProvider = pinProviderMock
            )

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertEquals(authenticationException, (result as MIRACLError).value)
        }

    @Test
    fun `authenticateWithAppLink calls result handler with MIRACLSuccess when input is valid and user is authenticated`() {
        // Arrange
        val authenticationUser = mockk<User>()
        val appLinkMock = mockkClass(Uri::class)
        coEvery {
            authenticatorMock.authenticateWithAppLink(
                authenticationUser,
                appLinkMock,
                pinProviderMock,
                arrayOf(AuthenticatorScopes.OIDC.value),
                deviceName
            )
        } returns MIRACLSuccess(AuthenticateResponse(0, "", null, null))

        val resultHandlerMock = mockk<ResultHandler<Unit, AuthenticationException>>()
        every { resultHandlerMock.onResult(any()) } just runs

        // Act
        miraclTrust.authenticateWithAppLink(
            user = authenticationUser,
            appLink = appLinkMock,
            pinProvider = pinProviderMock,
            resultHandler = resultHandlerMock
        )
        testCoroutineDispatcher.scheduler.advanceUntilIdle()

        // Assert
        val capturingSlot = CapturingSlot<MIRACLResult<Unit, AuthenticationException>>()
        coVerify { resultHandlerMock.onResult(capture(capturingSlot)) }

        Assert.assertTrue(capturingSlot.captured is MIRACLSuccess)
    }

    @Test
    fun `authenticateWithAppLink calls result handler with MIRACLError when authentication fails`() {
        // Arrange
        val authenticationUser = mockk<User>()
        val appLinkMock = mockkClass(Uri::class)
        val authenticationException = AuthenticationException.AuthenticationFail()
        coEvery {
            authenticatorMock.authenticateWithAppLink(
                authenticationUser,
                appLinkMock,
                pinProviderMock,
                arrayOf(AuthenticatorScopes.OIDC.value),
                deviceName
            )
        } returns MIRACLError(authenticationException)

        val resultHandlerMock = mockk<ResultHandler<Unit, AuthenticationException>>()
        every { resultHandlerMock.onResult(any()) } just runs

        // Act
        miraclTrust.authenticateWithAppLink(
            user = authenticationUser,
            appLink = appLinkMock,
            pinProvider = pinProviderMock,
            resultHandler = resultHandlerMock
        )
        testCoroutineDispatcher.scheduler.advanceUntilIdle()

        // Assert
        val capturingSlot = CapturingSlot<MIRACLResult<Unit, AuthenticationException>>()
        coVerify { resultHandlerMock.onResult(capture(capturingSlot)) }

        val result = capturingSlot.captured

        Assert.assertTrue(result is MIRACLError)
        Assert.assertEquals(authenticationException, (result as MIRACLError).value)
    }

    @Test
    fun `authenticateWithQRCode returns a MIRACLSuccess when input is valid and user is authenticated`() =
        runTest(testCoroutineDispatcher) {
            // Arrange
            val authenticationUser = mockk<User>()
            val qrCode = "https://mcl.mpin.io/mobile-login/#accessId"
            coEvery {
                authenticatorMock.authenticateWithQRCode(
                    authenticationUser,
                    qrCode,
                    pinProviderMock,
                    arrayOf(AuthenticatorScopes.OIDC.value),
                    deviceName
                )
            } returns MIRACLSuccess(AuthenticateResponse(0, "", null, null))

            // Act
            val result = miraclTrust.authenticateWithQRCode(
                user = authenticationUser,
                qrCode = qrCode,
                pinProvider = pinProviderMock
            )

            // Assert
            Assert.assertTrue(result is MIRACLSuccess)
        }

    @Test
    fun `authenticateWithQRCode returns a MIRACLError when authentication fails`() =
        runTest(testCoroutineDispatcher) {
            // Arrange
            val authenticationUser = mockk<User>()
            val qrCode = "https://mcl.mpin.io/mobile-login/#accessId"
            val authenticationException = AuthenticationException.AuthenticationFail()
            coEvery {
                authenticatorMock.authenticateWithQRCode(
                    authenticationUser,
                    qrCode,
                    pinProviderMock,
                    arrayOf(AuthenticatorScopes.OIDC.value),
                    deviceName
                )
            } returns MIRACLError(authenticationException)

            // Act
            val result = miraclTrust.authenticateWithQRCode(
                user = authenticationUser,
                qrCode = qrCode,
                pinProvider = pinProviderMock
            )

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertEquals(authenticationException, (result as MIRACLError).value)
        }

    @Test
    fun `authenticateWithQRCode calls result handler with MIRACLSuccess when input is valid and user is authenticated`() {
        // Arrange
        val authenticationUser = mockk<User>()
        val qrCode = "https://mcl.mpin.io/mobile-login/#accessId"
        coEvery {
            authenticatorMock.authenticateWithQRCode(
                authenticationUser,
                qrCode,
                pinProviderMock,
                arrayOf(AuthenticatorScopes.OIDC.value),
                deviceName
            )
        } returns MIRACLSuccess(AuthenticateResponse(0, "", null, null))

        val resultHandlerMock = mockk<ResultHandler<Unit, AuthenticationException>>()
        every { resultHandlerMock.onResult(any()) } just runs

        // Act
        miraclTrust.authenticateWithQRCode(
            user = authenticationUser,
            qrCode = qrCode,
            pinProvider = pinProviderMock,
            resultHandler = resultHandlerMock
        )
        testCoroutineDispatcher.scheduler.advanceUntilIdle()

        // Assert
        val capturingSlot = CapturingSlot<MIRACLResult<Unit, AuthenticationException>>()
        coVerify { resultHandlerMock.onResult(capture(capturingSlot)) }

        Assert.assertTrue(capturingSlot.captured is MIRACLSuccess)
    }

    @Test
    fun `authenticateWithQRCode calls result handler with MIRACLError when authentication fails`() {
        // Arrange
        val authenticationUser = mockk<User>()
        val qrCode = "https://mcl.mpin.io/mobile-login/#accessId"
        val authenticationException = AuthenticationException.AuthenticationFail()
        coEvery {
            authenticatorMock.authenticateWithQRCode(
                authenticationUser,
                qrCode,
                pinProviderMock,
                arrayOf(AuthenticatorScopes.OIDC.value),
                deviceName
            )
        } returns MIRACLError(authenticationException)

        val resultHandlerMock = mockk<ResultHandler<Unit, AuthenticationException>>()
        every { resultHandlerMock.onResult(any()) } just runs

        // Act
        miraclTrust.authenticateWithQRCode(
            user = authenticationUser,
            qrCode = qrCode,
            pinProvider = pinProviderMock,
            resultHandler = resultHandlerMock
        )
        testCoroutineDispatcher.scheduler.advanceUntilIdle()

        // Assert
        val capturingSlot = CapturingSlot<MIRACLResult<Unit, AuthenticationException>>()
        coVerify { resultHandlerMock.onResult(capture(capturingSlot)) }

        val result = capturingSlot.captured

        Assert.assertTrue(result is MIRACLError)
        Assert.assertEquals(authenticationException, (result as MIRACLError).value)
    }

    @Test
    fun `authenticateWithNotificationPayload returns a MIRACLSuccess when input is valid and user is authenticated`() =
        runTest(testCoroutineDispatcher) {
            // Arrange
            val payload = mapOf(
                Authenticator.PUSH_NOTIFICATION_PROJECT_ID to projectId,
                Authenticator.PUSH_NOTIFICATION_USER_ID to randomUuidString(),
                Authenticator.PUSH_NOTIFICATION_QR_URL to "https://mcl.mpin.io/mobile-login/#accessId"
            )
            coEvery {
                authenticatorMock.authenticateWithNotificationPayload(
                    payload,
                    pinProviderMock,
                    arrayOf(AuthenticatorScopes.OIDC.value),
                    deviceName
                )
            } returns MIRACLSuccess(AuthenticateResponse(0, "", null, null))

            // Act
            val result = miraclTrust.authenticateWithNotificationPayload(
                payload = payload,
                pinProvider = pinProviderMock
            )

            // Assert
            Assert.assertTrue(result is MIRACLSuccess)
        }

    @Test
    fun `authenticateWithNotificationPayload returns a MIRACLError when authentication fails`() =
        runTest(testCoroutineDispatcher) {
            // Arrange
            val payload = mapOf(
                Authenticator.PUSH_NOTIFICATION_PROJECT_ID to projectId,
                Authenticator.PUSH_NOTIFICATION_USER_ID to randomUuidString(),
                Authenticator.PUSH_NOTIFICATION_QR_URL to "https://mcl.mpin.io/mobile-login/#accessId"
            )
            val authenticationException = AuthenticationException.AuthenticationFail()
            coEvery {
                authenticatorMock.authenticateWithNotificationPayload(
                    payload,
                    pinProviderMock,
                    arrayOf(AuthenticatorScopes.OIDC.value),
                    deviceName
                )
            } returns MIRACLError(authenticationException)

            // Act
            val result = miraclTrust.authenticateWithNotificationPayload(
                payload = payload,
                pinProvider = pinProviderMock
            )

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertEquals(authenticationException, (result as MIRACLError).value)
        }

    @Test
    fun `authenticateWithNotificationPayload calls result handler with MIRACLSuccess when input is valid and user is authenticated`() {
        // Arrange
        val payload = mapOf(
            Authenticator.PUSH_NOTIFICATION_PROJECT_ID to projectId,
            Authenticator.PUSH_NOTIFICATION_USER_ID to randomUuidString(),
            Authenticator.PUSH_NOTIFICATION_QR_URL to "https://mcl.mpin.io/mobile-login/#accessId"
        )
        coEvery {
            authenticatorMock.authenticateWithNotificationPayload(
                payload,
                pinProviderMock,
                arrayOf(AuthenticatorScopes.OIDC.value),
                deviceName
            )
        } returns MIRACLSuccess(AuthenticateResponse(0, "", null, null))

        val resultHandlerMock = mockk<ResultHandler<Unit, AuthenticationException>>()
        every { resultHandlerMock.onResult(any()) } just runs

        // Act
        miraclTrust.authenticateWithNotificationPayload(
            payload = payload,
            pinProvider = pinProviderMock,
            resultHandler = resultHandlerMock
        )
        testCoroutineDispatcher.scheduler.advanceUntilIdle()

        // Assert
        val capturingSlot = CapturingSlot<MIRACLResult<Unit, AuthenticationException>>()
        coVerify { resultHandlerMock.onResult(capture(capturingSlot)) }

        Assert.assertTrue(capturingSlot.captured is MIRACLSuccess)
    }

    @Test
    fun `authenticateWithNotificationPayload calls result handler with MIRACLError when authentication fails`() {
        // Arrange
        val payload = mapOf(
            Authenticator.PUSH_NOTIFICATION_PROJECT_ID to projectId,
            Authenticator.PUSH_NOTIFICATION_USER_ID to randomUuidString(),
            Authenticator.PUSH_NOTIFICATION_QR_URL to "https://mcl.mpin.io/mobile-login/#accessId"
        )
        val authenticationException = AuthenticationException.AuthenticationFail()
        coEvery {
            authenticatorMock.authenticateWithNotificationPayload(
                payload,
                pinProviderMock,
                arrayOf(AuthenticatorScopes.OIDC.value),
                deviceName
            )
        } returns MIRACLError(authenticationException)

        val resultHandlerMock = mockk<ResultHandler<Unit, AuthenticationException>>()
        every { resultHandlerMock.onResult(any()) } just runs

        // Act
        miraclTrust.authenticateWithNotificationPayload(
            payload = payload,
            pinProvider = pinProviderMock,
            resultHandler = resultHandlerMock
        )
        testCoroutineDispatcher.scheduler.advanceUntilIdle()

        // Assert
        val capturingSlot = CapturingSlot<MIRACLResult<Unit, AuthenticationException>>()
        coVerify { resultHandlerMock.onResult(capture(capturingSlot)) }

        val result = capturingSlot.captured

        Assert.assertTrue(result is MIRACLError)
        Assert.assertEquals(authenticationException, (result as MIRACLError).value)
    }

    @Test
    fun `authenticate returns a MIRACLSuccess when authentication is successful and there is jwt response`() =
        runTest(testCoroutineDispatcher) {
            // Arrange
            val authenticationUser = mockk<User>()
            coEvery {
                authenticatorMock.authenticate(
                    user = authenticationUser,
                    accessId = null,
                    pinProvider = pinProviderMock,
                    scope = arrayOf(AuthenticatorScopes.JWT.value),
                    deviceName = deviceName
                )
            } returns MIRACLSuccess(
                AuthenticateResponse(
                    status = 0,
                    message = "",
                    renewSecretResponse = null,
                    jwt = randomUuidString()
                )
            )

            // Act
            val result = miraclTrust.authenticate(
                user = authenticationUser,
                pinProvider = pinProviderMock
            )

            // Assert
            Assert.assertTrue(result is MIRACLSuccess)
        }

    @Test
    fun `authenticate returns a MIRACLError when authentication failed`() =
        runTest(testCoroutineDispatcher) {
            // Arrange
            val authenticationException = AuthenticationException.AuthenticationFail()
            coEvery {
                authenticatorMock.authenticate(
                    user = any(),
                    accessId = any(),
                    pinProvider = any(),
                    scope = any(),
                    deviceName = any()
                )
            } returns MIRACLError(authenticationException)

            val authenticationUser = mockk<User>()

            // Act
            val result = miraclTrust.authenticate(
                user = authenticationUser,
                pinProvider = pinProviderMock
            )

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertEquals(authenticationException, (result as MIRACLError).value)
        }

    @Test
    fun `authenticate returns a MIRACLError when there is no jwt in the response`() =
        runTest(testCoroutineDispatcher) {
            // Arrange
            coEvery {
                authenticatorMock.authenticate(
                    user = any(),
                    accessId = any(),
                    pinProvider = any(),
                    scope = any(),
                    deviceName = any()
                )
            } returns MIRACLSuccess(
                AuthenticateResponse(
                    status = 0,
                    message = "",
                    renewSecretResponse = null,
                    jwt = null
                )
            )
            val authenticationUser = mockk<User>()

            // Act
            val result = miraclTrust.authenticate(
                user = authenticationUser,
                pinProvider = pinProviderMock
            )

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertTrue((result as MIRACLError).value is AuthenticationException.AuthenticationFail)
        }

    @Test
    fun `authenticate calls result handler with MIRACLSuccess when authentication is successful and there is jwt response`() {
        // Arrange
        val authenticationUser = mockk<User>()
        coEvery {
            authenticatorMock.authenticate(
                user = authenticationUser,
                accessId = null,
                pinProvider = pinProviderMock,
                scope = arrayOf(AuthenticatorScopes.JWT.value),
                deviceName = deviceName
            )
        } returns MIRACLSuccess(
            AuthenticateResponse(
                status = 0,
                message = "",
                renewSecretResponse = null,
                jwt = randomUuidString()
            )
        )

        val resultHandlerMock = mockk<ResultHandler<String, AuthenticationException>>()
        every { resultHandlerMock.onResult(any()) } just runs

        // Act
        miraclTrust.authenticate(
            user = authenticationUser,
            pinProvider = pinProviderMock,
            resultHandler = resultHandlerMock
        )
        testCoroutineDispatcher.scheduler.advanceUntilIdle()

        // Assert
        val capturingSlot = CapturingSlot<MIRACLResult<String, AuthenticationException>>()
        coVerify { resultHandlerMock.onResult(capture(capturingSlot)) }

        Assert.assertTrue(capturingSlot.captured is MIRACLSuccess)
    }

    @Test
    fun `authenticate calls result handler with MIRACLError when authentication failed`() {
        // Arrange
        val authenticationException = AuthenticationException.AuthenticationFail()
        coEvery {
            authenticatorMock.authenticate(
                user = any(),
                accessId = any(),
                pinProvider = any(),
                scope = any(),
                deviceName = any()
            )
        } returns MIRACLError(authenticationException)

        val resultHandlerMock = mockk<ResultHandler<String, AuthenticationException>>()
        every { resultHandlerMock.onResult(any()) } just runs

        val authenticationUser = mockk<User>()

        // Act
        miraclTrust.authenticate(
            user = authenticationUser,
            pinProvider = pinProviderMock,
            resultHandler = resultHandlerMock
        )
        testCoroutineDispatcher.scheduler.advanceUntilIdle()

        // Assert
        val capturingSlot = CapturingSlot<MIRACLResult<String, AuthenticationException>>()
        coVerify { resultHandlerMock.onResult(capture(capturingSlot)) }

        val result = capturingSlot.captured

        Assert.assertTrue(result is MIRACLError)
        Assert.assertEquals(authenticationException, (result as MIRACLError).value)
    }

    @Test
    fun `authenticate calls result handler with MIRACLError when there is no jwt in the response`() {
        // Arrange
        coEvery {
            authenticatorMock.authenticate(
                user = any(),
                accessId = any(),
                pinProvider = any(),
                scope = any(),
                deviceName = any()
            )
        } returns MIRACLSuccess(
            AuthenticateResponse(
                status = 0,
                message = "",
                renewSecretResponse = null,
                jwt = null
            )
        )

        val resultHandlerMock = mockk<ResultHandler<String, AuthenticationException>>()
        every { resultHandlerMock.onResult(any()) } just runs

        val authenticationUser = mockk<User>()

        // Act
        miraclTrust.authenticate(
            user = authenticationUser,
            pinProvider = pinProviderMock,
            resultHandler = resultHandlerMock
        )
        testCoroutineDispatcher.scheduler.advanceUntilIdle()

        // Assert
        val capturingSlot = CapturingSlot<MIRACLResult<String, AuthenticationException>>()
        coVerify { resultHandlerMock.onResult(capture(capturingSlot)) }

        val result = capturingSlot.captured
        Assert.assertTrue(result is MIRACLError)
        Assert.assertTrue((result as MIRACLError).value is AuthenticationException.AuthenticationFail)
    }

    @Test
    fun `authenticate with CrossDeviceSession returns a MIRACLSuccess when input is valid and user is authenticated`() =
        runTest(testCoroutineDispatcher) {
            // Arrange
            val authenticationUser = mockk<User>()
            val crossDeviceSession = createCrossDeviceSession()
            coEvery {
                authenticatorMock.authenticateWithCrossDeviceSession(
                    authenticationUser,
                    crossDeviceSession,
                    pinProviderMock,
                    arrayOf(AuthenticatorScopes.OIDC.value),
                    deviceName
                )
            } returns MIRACLSuccess(AuthenticateResponse(0, "", null, null))

            // Act
            val result = miraclTrust.authenticate(
                user = authenticationUser,
                crossDeviceSession = crossDeviceSession,
                pinProvider = pinProviderMock
            )

            // Assert
            Assert.assertTrue(result is MIRACLSuccess)
        }

    @Test
    fun `authenticate with CrossDeviceSession returns a MIRACLError when authentication fails`() =
        runTest(testCoroutineDispatcher) {
            // Arrange
            val authenticationUser = mockk<User>()
            val crossDeviceSession = createCrossDeviceSession()
            val authenticationException = AuthenticationException.AuthenticationFail()
            coEvery {
                authenticatorMock.authenticateWithCrossDeviceSession(
                    authenticationUser,
                    crossDeviceSession,
                    pinProviderMock,
                    arrayOf(AuthenticatorScopes.OIDC.value),
                    deviceName
                )
            } returns MIRACLError(authenticationException)

            // Act
            val result = miraclTrust.authenticate(
                user = authenticationUser,
                crossDeviceSession = crossDeviceSession,
                pinProvider = pinProviderMock
            )

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertEquals(authenticationException, (result as MIRACLError).value)
        }

    @Test
    fun `authenticate with CrossDeviceSession calls result handler with MIRACLSuccess when input is valid and user is authenticated`() {
        // Arrange
        val authenticationUser = mockk<User>()
        val crossDeviceSession = createCrossDeviceSession()
        coEvery {
            authenticatorMock.authenticateWithCrossDeviceSession(
                authenticationUser,
                crossDeviceSession,
                pinProviderMock,
                arrayOf(AuthenticatorScopes.OIDC.value),
                deviceName
            )
        } returns MIRACLSuccess(AuthenticateResponse(0, "", null, null))

        val resultHandlerMock = mockk<ResultHandler<Unit, AuthenticationException>>()
        every { resultHandlerMock.onResult(any()) } just runs

        // Act
        miraclTrust.authenticate(
            user = authenticationUser,
            crossDeviceSession = crossDeviceSession,
            pinProvider = pinProviderMock,
            resultHandler = resultHandlerMock
        )
        testCoroutineDispatcher.scheduler.advanceUntilIdle()

        // Assert
        val capturingSlot = CapturingSlot<MIRACLResult<Unit, AuthenticationException>>()
        coVerify { resultHandlerMock.onResult(capture(capturingSlot)) }

        Assert.assertTrue(capturingSlot.captured is MIRACLSuccess)
    }

    @Test
    fun `authenticate with CrossDeviceSession calls result handler with MIRACLError when authentication fails`() {
        // Arrange
        val authenticationUser = mockk<User>()
        val crossDeviceSession = createCrossDeviceSession()
        val authenticationException = AuthenticationException.AuthenticationFail()
        coEvery {
            authenticatorMock.authenticateWithCrossDeviceSession(
                authenticationUser,
                crossDeviceSession,
                pinProviderMock,
                arrayOf(AuthenticatorScopes.OIDC.value),
                deviceName
            )
        } returns MIRACLError(authenticationException)

        val resultHandlerMock = mockk<ResultHandler<Unit, AuthenticationException>>()
        every { resultHandlerMock.onResult(any()) } just runs

        // Act
        miraclTrust.authenticate(
            user = authenticationUser,
            crossDeviceSession = crossDeviceSession,
            pinProvider = pinProviderMock,
            resultHandler = resultHandlerMock
        )
        testCoroutineDispatcher.scheduler.advanceUntilIdle()

        // Assert
        val capturingSlot = CapturingSlot<MIRACLResult<Unit, AuthenticationException>>()
        coVerify { resultHandlerMock.onResult(capture(capturingSlot)) }

        val result = capturingSlot.captured

        Assert.assertTrue(result is MIRACLError)
        Assert.assertEquals(authenticationException, (result as MIRACLError).value)
    }

    @Test
    fun `getUsers returns list of users when there are registered users`() = runTest {
        // Arrange
        val userDtos = listOf(createRandomUser().toUserDto(), createRandomUser().toUserDto())

        every { userStorageMock.all() } returns userDtos

        // Act
        val users = miraclTrust.getUsers()

        // Assert
        assertUsersEqualDtos(users, userDtos)
    }

    @Test
    fun `getUsers returns empty list when there aren't registered users`() = runTest {
        // Arrange
        val userDtos = listOf<UserDto>()
        every { userStorageMock.all() } returns userDtos

        // Act
        val users = miraclTrust.getUsers()

        // Assert
        Assert.assertTrue(users.isEmpty())
    }

    @Test(expected = UserStorageException::class)
    fun `getUsers should wrap and rethrow the exception thrown by the userStorage`() = runTest {
        // Arrange
        every {
            userStorageMock.all()
        } throws Exception()

        // Act
        miraclTrust.getUsers()
    }

    @Test
    fun `getUsers with callback returns list of users when there are registered users`() {
        // Arrange
        val userDtos = listOf(createRandomUser().toUserDto(), createRandomUser().toUserDto())
        every { userStorageMock.all() } returns userDtos

        val resultHandlerMock = mockk<ResultHandler<List<User>, UserStorageException>>()
        every { resultHandlerMock.onResult(any()) } just runs

        // Act
        miraclTrust.getUsers(resultHandlerMock)
        testCoroutineDispatcher.scheduler.advanceUntilIdle()

        // Assert
        val capturingSlot = CapturingSlot<MIRACLResult<List<User>, UserStorageException>>()
        coVerify { resultHandlerMock.onResult(capture(capturingSlot)) }

        val result = capturingSlot.captured
        Assert.assertTrue(result is MIRACLSuccess)
        assertUsersEqualDtos((result as MIRACLSuccess).value, userDtos)
    }

    @Test
    fun `getUsers with callback returns null when there aren't registered users`() {
        // Arrange
        val userDtos = listOf<UserDto>()
        every { userStorageMock.all() } returns userDtos

        val resultHandlerMock = mockk<ResultHandler<List<User>, UserStorageException>>()
        every { resultHandlerMock.onResult(any()) } just runs

        // Act
        miraclTrust.getUsers(resultHandlerMock)
        testCoroutineDispatcher.scheduler.advanceUntilIdle()

        // Assert
        val capturingSlot = CapturingSlot<MIRACLResult<List<User>, UserStorageException>>()
        coVerify { resultHandlerMock.onResult(capture(capturingSlot)) }

        val result = capturingSlot.captured
        Assert.assertTrue(result is MIRACLSuccess)
        Assert.assertTrue((result as MIRACLSuccess).value.isEmpty())
    }

    @Test
    fun `getUsers with callback returns error when userStorage throws exception`() {
        // Arrange
        val exception = Exception()
        every { userStorageMock.all() } throws exception

        val resultHandlerMock = mockk<ResultHandler<List<User>, UserStorageException>>()
        every { resultHandlerMock.onResult(any()) } just runs

        // Act
        miraclTrust.getUsers(resultHandlerMock)
        testCoroutineDispatcher.scheduler.advanceUntilIdle()

        // Assert
        val capturingSlot = CapturingSlot<MIRACLResult<List<User>, UserStorageException>>()
        coVerify { resultHandlerMock.onResult(capture(capturingSlot)) }

        val result = capturingSlot.captured
        Assert.assertTrue(result is MIRACLError)
        Assert.assertEquals(exception, (result as MIRACLError).value.cause)
    }

    @Test
    fun `getUser returns User when there is a user with the given userId`() = runTest {
        // Arrange
        val userId = randomUuidString()
        val userDto = createRandomUser().toUserDto()

        every { userStorageMock.getUser(userId, projectId) } returns userDto

        // Act
        val user = miraclTrust.getUser(userId)

        // Assert
        assertUserEqualsDto(user, userDto)
    }

    @Test
    fun `getUser returns null when there isn't a user with the given userId`() = runTest {
        // Arrange
        val userId = randomUuidString()

        every { userStorageMock.getUser(userId, projectId) } returns null

        // Act
        val user = miraclTrust.getUser(userId)

        // Assert
        Assert.assertNull(user)
    }

    @Test(expected = UserStorageException::class)
    fun `getUser should wrap and rethrow the exception thrown by the userStorage`() = runTest {
        // Arrange
        every {
            userStorageMock.getUser(any(), any())
        } throws Exception()

        // Act
        miraclTrust.getUser(randomUuidString())
    }

    @Test
    fun `getUser with callback returns User when there is a user with the given userId`() {
        // Arrange
        val userId = randomUuidString()
        val userDto = createRandomUser().toUserDto()

        every { userStorageMock.getUser(userId, projectId) } returns userDto

        val resultHandlerMock = mockk<ResultHandler<User?, UserStorageException>>()
        every { resultHandlerMock.onResult(any()) } just runs

        // Act
        miraclTrust.getUser(userId, resultHandlerMock)
        testCoroutineDispatcher.scheduler.advanceUntilIdle()

        // Assert
        val capturingSlot = CapturingSlot<MIRACLResult<User?, UserStorageException>>()
        coVerify { resultHandlerMock.onResult(capture(capturingSlot)) }

        val result = capturingSlot.captured
        Assert.assertTrue(result is MIRACLSuccess)

        val user = (result as MIRACLSuccess).value
        assertUserEqualsDto(user, userDto)
    }

    @Test
    fun `getUser with callback returns null when there isn't a user with the given userId`() {
        // Arrange
        val userId = randomUuidString()

        every { userStorageMock.getUser(userId, projectId) } returns null

        val resultHandlerMock = mockk<ResultHandler<User?, UserStorageException>>()
        every { resultHandlerMock.onResult(any()) } just runs

        // Act
        miraclTrust.getUser(userId, resultHandlerMock)
        testCoroutineDispatcher.scheduler.advanceUntilIdle()

        // Assert
        val capturingSlot = CapturingSlot<MIRACLResult<User?, UserStorageException>>()
        coVerify { resultHandlerMock.onResult(capture(capturingSlot)) }

        val result = capturingSlot.captured
        Assert.assertTrue(result is MIRACLSuccess)
        Assert.assertNull((result as MIRACLSuccess).value)
    }

    @Test
    fun `getUser with callback returns error when userStorage throws exception`() {
        // Arrange
        val userId = randomUuidString()

        val exception = Exception()
        every { userStorageMock.getUser(userId, projectId) } throws exception

        val resultHandlerMock = mockk<ResultHandler<User?, UserStorageException>>()
        every { resultHandlerMock.onResult(any()) } just runs

        // Act
        miraclTrust.getUser(userId, resultHandlerMock)
        testCoroutineDispatcher.scheduler.advanceUntilIdle()

        // Assert
        val capturingSlot = CapturingSlot<MIRACLResult<User?, UserStorageException>>()
        coVerify { resultHandlerMock.onResult(capture(capturingSlot)) }

        val result = capturingSlot.captured
        Assert.assertTrue(result is MIRACLError)
        Assert.assertEquals(exception, (result as MIRACLError).value.cause)
    }

    @Test
    fun `delete user should call userStorage with correct user value`() = runTest {
        // Arrange
        val user = createRandomUser()
        every {
            userStorageMock.delete(any())
        } just runs

        // Act
        miraclTrust.delete(user)

        // Assert
        verify { userStorageMock.delete(any()) }
    }

    @Test(expected = UserStorageException::class)
    fun `delete user should wrap and rethrow the exception thrown by the userStorage`() = runTest {
        // Arrange
        every {
            userStorageMock.delete(any())
        } throws Exception()

        // Act
        miraclTrust.delete(mockk())
    }

    @Test
    fun `delete user with callback should call userStorage with correct user value`() {
        // Arrange
        val user = createRandomUser()
        every {
            userStorageMock.delete(any())
        } just runs

        val resultHandlerMock = mockk<ResultHandler<Unit, UserStorageException>>()
        every { resultHandlerMock.onResult(any()) } just runs

        // Act
        miraclTrust.delete(user, resultHandlerMock)
        testCoroutineDispatcher.scheduler.advanceUntilIdle()

        // Assert
        verify { userStorageMock.delete(any()) }

        val capturingSlot = CapturingSlot<MIRACLResult<Unit, UserStorageException>>()
        coVerify { resultHandlerMock.onResult(capture(capturingSlot)) }

        val result = capturingSlot.captured
        Assert.assertTrue(result is MIRACLSuccess)
    }

    @Test
    fun `delete user with callback returns error when userStorage throws exception`() {
        // Arrange
        val exception = Exception()
        every {
            userStorageMock.delete(any())
        } throws exception

        val resultHandlerMock = mockk<ResultHandler<Unit, UserStorageException>>()
        every { resultHandlerMock.onResult(any()) } just runs

        // Act
        miraclTrust.delete(createRandomUser(), resultHandlerMock)
        testCoroutineDispatcher.scheduler.advanceUntilIdle()

        // Assert
        val capturingSlot = CapturingSlot<MIRACLResult<Unit, UserStorageException>>()
        coVerify { resultHandlerMock.onResult(capture(capturingSlot)) }

        val result = capturingSlot.captured
        Assert.assertTrue(result is MIRACLError)
        Assert.assertEquals(exception, (result as MIRACLError).value.cause)
    }

    @Test
    fun `sign returns MIRACLSuccess on success`() =
        runTest(testCoroutineDispatcher) {
            // Arrange
            val signingResult = SigningResult(
                signature = Signature(
                    mpinId = randomHexString(),
                    U = randomHexString(),
                    V = randomHexString(),
                    publicKey = randomHexString(),
                    dtas = randomUuidString(),
                    hash = randomHexString(),
                    timestamp = Date().secondsSince1970()
                ), timestamp = Date()
            )
            coEvery {
                documentSignerMock.sign(
                    message = any(),
                    user = any(),
                    pinProvider = any(),
                    deviceName = any()
                )
            } returns MIRACLSuccess(signingResult)

            // Act
            val result = miraclTrust.sign(
                message = randomByteArray(),
                user = mockk(),
                pinProvider = pinProviderMock
            )

            // Assert
            Assert.assertTrue(result is MIRACLSuccess)
            Assert.assertEquals(signingResult, (result as MIRACLSuccess).value)
        }

    @Test
    fun `sign returns MIRACLError on fail`() =
        runTest(testCoroutineDispatcher) {
            // Arrange
            val signingException = SigningException.SigningFail()
            coEvery {
                documentSignerMock.sign(
                    message = any(),
                    user = any(),
                    pinProvider = any(),
                    deviceName = any()
                )
            } returns MIRACLError(signingException)

            // Act
            val result = miraclTrust.sign(
                message = randomByteArray(),
                user = mockk(),
                pinProvider = pinProviderMock
            )

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertEquals(signingException, (result as MIRACLError).value)
        }

    @Test
    fun `sign passes the MIRACLSuccess to result handler on success`() {
        // Arrange
        val signingResult = SigningResult(
            signature = Signature(
                mpinId = randomHexString(),
                U = randomHexString(),
                V = randomHexString(),
                publicKey = randomHexString(),
                dtas = randomUuidString(),
                hash = randomHexString(),
                timestamp = Date().secondsSince1970()
            ), timestamp = Date()
        )
        coEvery {
            documentSignerMock.sign(
                message = any(),
                user = any(),
                pinProvider = any(),
                deviceName = any()
            )
        } returns MIRACLSuccess(signingResult)

        val resultHandlerMock = mockk<ResultHandler<SigningResult, SigningException>>()
        every { resultHandlerMock.onResult(any()) } just runs

        // Act
        miraclTrust.sign(
            message = randomByteArray(),
            user = mockk(),
            pinProvider = pinProviderMock,
            resultHandler = resultHandlerMock
        )
        testCoroutineDispatcher.scheduler.advanceUntilIdle()

        // Assert
        val capturingSlot = CapturingSlot<MIRACLResult<SigningResult, SigningException>>()
        coVerify { resultHandlerMock.onResult(capture(capturingSlot)) }

        val captured = capturingSlot.captured

        Assert.assertTrue(captured is MIRACLSuccess)
        Assert.assertEquals(signingResult, (captured as MIRACLSuccess).value)
    }

    @Test
    fun `sign passes the MIRACLError to result handler on fail`() {
        // Arrange
        val signingException = SigningException.SigningFail()
        coEvery {
            documentSignerMock.sign(
                message = any(),
                user = any(),
                pinProvider = any(),
                deviceName = any()
            )
        } returns MIRACLError(signingException)

        val resultHandlerMock = mockk<ResultHandler<SigningResult, SigningException>>()
        every { resultHandlerMock.onResult(any()) } just runs

        // Act
        miraclTrust.sign(
            message = randomByteArray(),
            user = mockk(),
            pinProvider = pinProviderMock,
            resultHandler = resultHandlerMock
        )
        testCoroutineDispatcher.scheduler.advanceUntilIdle()

        // Assert
        val capturingSlot = CapturingSlot<MIRACLResult<SigningResult, SigningException>>()
        coVerify { resultHandlerMock.onResult(capture(capturingSlot)) }

        val captured = capturingSlot.captured

        Assert.assertTrue(captured is MIRACLError)
        Assert.assertEquals(signingException, (captured as MIRACLError).value)
    }

    @Test
    fun `sign with signingSessionDetails passes the MIRACLSuccess to result handler on success`() {
        // Arrange
        val signingSessionDetails = mockkClass(SigningSessionDetails::class)
        val signingResult = SigningResult(
            signature = Signature(
                mpinId = randomHexString(),
                U = randomHexString(),
                V = randomHexString(),
                publicKey = randomHexString(),
                dtas = randomUuidString(),
                hash = randomHexString(),
                timestamp = Date().secondsSince1970()
            ), timestamp = Date()
        )
        coEvery {
            documentSignerMock.sign(
                message = any(),
                user = any(),
                pinProvider = any(),
                deviceName = any(),
                signingSessionDetails = any()
            )
        } returns MIRACLSuccess(signingResult)

        val resultHandlerMock = mockk<ResultHandler<SigningResult, SigningException>>()
        every { resultHandlerMock.onResult(any()) } just runs

        // Act
        miraclTrust.sign(
            message = randomByteArray(),
            user = mockk(),
            signingSessionDetails = signingSessionDetails,
            pinProvider = pinProviderMock,
            resultHandler = resultHandlerMock
        )
        testCoroutineDispatcher.scheduler.advanceUntilIdle()

        // Assert
        val capturingSlot = CapturingSlot<MIRACLResult<SigningResult, SigningException>>()
        coVerify { resultHandlerMock.onResult(capture(capturingSlot)) }

        val captured = capturingSlot.captured

        Assert.assertTrue(captured is MIRACLSuccess)
        Assert.assertEquals(signingResult, (captured as MIRACLSuccess).value)
    }

    @Test
    fun `Sign with signingSessionDetails passes the MIRACLError to result handler on fail`() {
        // Arrange
        val signingSessionDetails = mockkClass(SigningSessionDetails::class)
        val signingException = SigningException.SigningFail()
        coEvery {
            documentSignerMock.sign(
                message = any(),
                user = any(),
                pinProvider = any(),
                deviceName = any(),
                signingSessionDetails = any()
            )
        } returns MIRACLError(signingException)

        val resultHandlerMock = mockk<ResultHandler<SigningResult, SigningException>>()
        every { resultHandlerMock.onResult(any()) } just runs

        // Act
        miraclTrust.sign(
            message = randomByteArray(),
            user = mockk(),
            signingSessionDetails = signingSessionDetails,
            pinProvider = pinProviderMock,
            resultHandler = resultHandlerMock
        )
        testCoroutineDispatcher.scheduler.advanceUntilIdle()

        // Assert
        val capturingSlot = CapturingSlot<MIRACLResult<SigningResult, SigningException>>()
        coVerify { resultHandlerMock.onResult(capture(capturingSlot)) }

        val captured = capturingSlot.captured

        Assert.assertTrue(captured is MIRACLError)
        Assert.assertEquals(signingException, (captured as MIRACLError).value)
    }

    @Test
    fun `sign with CrossDeviceSession returns MIRACLSuccess on success`() =
        runTest(testCoroutineDispatcher) {
            // Arrange
            val crossDeviceSession = createCrossDeviceSession()
            coEvery {
                documentSignerMock.sign(
                    crossDeviceSession = any(),
                    user = any(),
                    pinProvider = any(),
                    deviceName = any()
                )
            } returns MIRACLSuccess(Unit)

            // Act
            val result = miraclTrust.sign(
                crossDeviceSession = crossDeviceSession,
                user = mockk(),
                pinProvider = pinProviderMock
            )

            // Assert
            Assert.assertTrue(result is MIRACLSuccess)
        }

    @Test
    fun `sign with CrossDeviceSession returns MIRACLError on fail`() =
        runTest(testCoroutineDispatcher) {
            // Arrange
            val crossDeviceSession = createCrossDeviceSession()
            val signingException = SigningException.SigningFail()
            coEvery {
                documentSignerMock.sign(
                    crossDeviceSession = any(),
                    user = any(),
                    pinProvider = any(),
                    deviceName = any(),
                )
            } returns MIRACLError(signingException)

            // Act
            val result = miraclTrust.sign(
                crossDeviceSession = crossDeviceSession,
                user = mockk(),
                pinProvider = pinProviderMock
            )

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertEquals(signingException, (result as MIRACLError).value)
        }

    @Test
    fun `sign with CrossDeviceSession passes the MIRACLSuccess to result handler on success`() {
        // Arrange
        val crossDeviceSession = createCrossDeviceSession()
        coEvery {
            documentSignerMock.sign(
                crossDeviceSession = any(),
                user = any(),
                pinProvider = any(),
                deviceName = any()
            )
        } returns MIRACLSuccess(Unit)

        val resultHandlerMock = mockk<ResultHandler<Unit, SigningException>>()
        every { resultHandlerMock.onResult(any()) } just runs

        // Act
        miraclTrust.sign(
            crossDeviceSession = crossDeviceSession,
            user = mockk(),
            pinProvider = pinProviderMock,
            resultHandler = resultHandlerMock
        )
        testCoroutineDispatcher.scheduler.advanceUntilIdle()

        // Assert
        val capturingSlot = CapturingSlot<MIRACLResult<Unit, SigningException>>()
        coVerify { resultHandlerMock.onResult(capture(capturingSlot)) }

        val captured = capturingSlot.captured

        Assert.assertTrue(captured is MIRACLSuccess)
    }

    @Test
    fun `sign with CrossDeviceSession passes the MIRACLError to result handler on fail`() {
        // Arrange
        val crossDeviceSession = createCrossDeviceSession()
        val signingException = SigningException.SigningFail()
        coEvery {
            documentSignerMock.sign(
                crossDeviceSession = any(),
                user = any(),
                pinProvider = any(),
                deviceName = any(),
            )
        } returns MIRACLError(signingException)

        val resultHandlerMock = mockk<ResultHandler<Unit, SigningException>>()
        every { resultHandlerMock.onResult(any()) } just runs

        // Act
        miraclTrust.sign(
            crossDeviceSession = crossDeviceSession,
            user = mockk(),
            pinProvider = pinProviderMock,
            resultHandler = resultHandlerMock
        )
        testCoroutineDispatcher.scheduler.advanceUntilIdle()

        // Assert
        val capturingSlot = CapturingSlot<MIRACLResult<Unit, SigningException>>()
        coVerify { resultHandlerMock.onResult(capture(capturingSlot)) }

        val captured = capturingSlot.captured

        Assert.assertTrue(captured is MIRACLError)
        Assert.assertEquals(signingException, (captured as MIRACLError).value)
    }

    @Test
    fun `logger should call logError on error`() {
        // Arrange
        every { loggerMock.error(any(), any()) } just runs

        val config = Configuration.Builder(this.projectId, this.projectUrl)
            .deviceName(this.deviceName)
            .componentFactory(componentFactoryMock)
            .userStorage(userStorageMock)
            .logger(loggerMock)
            .coroutineContext(testCoroutineDispatcher)
            .build()

        val resultHandlerMock: ResultHandler<User, RegistrationException> = mockk()
        every { resultHandlerMock.onResult(any()) } just runs

        MIRACLTrust.configure(
            context = mockk(),
            configuration = config
        )
        val sdk = MIRACLTrust.getInstance()
        sdk.resultHandlerDispatcher = testCoroutineDispatcher

        val registrationException = RegistrationException.RegistrationFail(Exception())
        coEvery {
            registratorMock.register(
                "",
                any(),
                any(),
                any(),
                any(),
                null
            )
        } returns MIRACLError(
            registrationException
        )

        // Act
        sdk.register("", "", {}, null, resultHandlerMock)
        testCoroutineDispatcher.scheduler.advanceUntilIdle()

        // Assert
        verify {
            loggerMock.error(
                any(),
                LoggerConstants.FLOW_ERROR.format(registrationException)
            )
        }
    }

    private fun createConfiguration(): Configuration {
        return Configuration.Builder(projectId, projectUrl)
            .deviceName(deviceName)
            .componentFactory(componentFactoryMock)
            .userStorage(userStorageMock)
            .coroutineContext(testCoroutineDispatcher)
            .build()
    }

    private fun setUpComponentFactoryMock() {
        every {
            componentFactoryMock.createVerificator(any(), any(), any())
        } returns verificatorMock
        every {
            componentFactoryMock.createRegistrator(
                registrationApi = any(),
                userStorage = any()
            )
        } returns registratorMock
        every {
            componentFactoryMock.createAuthenticator(
                authenticationApi = any(),
                sessionApi = any(),
                registrator = any(),
                userStorage = any()
            )
        } returns authenticatorMock
        every {
            componentFactoryMock.createDocumentSigner(
                any(),
                any(),
                any(),
                any()
            )
        } returns documentSignerMock
        every {
            userStorageMock.all()
        } returns listOf()
        every {
            componentFactoryMock.createSessionManager(any())
        } returns sessionManagerMock
        every {
            componentFactoryMock.createSigningSessionManager(any())
        } returns signingSessionManagerMock
        every {
            componentFactoryMock.createCrossDeviceSessionManager(any())
        } returns crossDeviceSessionManagerMock
    }

    private fun configureMIRACLTrust(configuration: Configuration = createConfiguration()): MIRACLTrust {
        MIRACLTrust.configure(
            context = mockk(),
            configuration = configuration
        )

        return MIRACLTrust.getInstance().apply {
            resultHandlerDispatcher = testCoroutineDispatcher
        }
    }

    private fun createCrossDeviceSession(
        sessionId: String = randomUuidString(),
        description: String = randomUuidString(),
        userId: String = randomUuidString(),
        projectId: String = this.projectId,
        projectName: String = randomUuidString(),
        projectLogoUrl: String = randomUuidString(),
        pinLength: Int = randomPinLength(),
        verificationMethod: VerificationMethod = VerificationMethod.FullCustom,
        verificationUrl: String = randomUuidString(),
        verificationCustomText: String = randomUuidString(),
        identityType: IdentityType = IdentityType.Email,
        identityTypeLabel: String = randomUuidString(),
        quickCodeEnabled: Boolean = Random.nextBoolean(),
        hash: String = randomHexString()
    ) = CrossDeviceSession(
        sessionId = sessionId,
        sessionDescription = description,
        userId = userId,
        projectId = projectId,
        projectName = projectName,
        projectLogoUrl = projectLogoUrl,
        pinLength = pinLength,
        verificationMethod = verificationMethod,
        verificationUrl = verificationUrl,
        verificationCustomText = verificationCustomText,
        identityType = identityType,
        identityTypeLabel = identityTypeLabel,
        quickCodeEnabled = quickCodeEnabled,
        signingHash = hash,
    )
}
