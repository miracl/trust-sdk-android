package com.miracl.trust.registration

import com.miracl.trust.MIRACLError
import com.miracl.trust.MIRACLSuccess
import com.miracl.trust.crypto.Crypto
import com.miracl.trust.crypto.CryptoException
import com.miracl.trust.crypto.SigningKeyPair
import com.miracl.trust.crypto.SupportedEllipticCurves
import com.miracl.trust.delegate.PinProvider
import com.miracl.trust.model.User
import com.miracl.trust.randomByteArray
import com.miracl.trust.randomHexString
import com.miracl.trust.randomNumericPin
import com.miracl.trust.randomPinLength
import com.miracl.trust.randomUuidString
import com.miracl.trust.storage.UserStorage
import com.miracl.trust.util.hexStringToByteArray
import com.miracl.trust.util.toHexString
import com.miracl.trust.util.toSHA256
import io.mockk.*
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.runTest
import org.junit.Assert
import org.junit.Before
import org.junit.Test
import java.io.IOException
import kotlin.random.Random

@ExperimentalCoroutinesApi
class RegistratorUnitTest {
    private val userId = randomUuidString()
    private val projectId = randomUuidString()
    private val deviceName = randomUuidString()
    private val pin = randomNumericPin(randomPinLength())
    private val pinProvider = PinProvider { it.consume(pin) }

    private val registrationApiMock = mockk<RegistrationApiManager>()
    private val cryptoMock = mockk<Crypto>()
    private val userStorageMock = mockk<UserStorage>()

    private lateinit var registrator: Registrator

    @Before
    fun resetMocks() {
        clearAllMocks()
        setUpRegistrationApiMock()
        setUpCryptoMock()

        registrator = Registrator(registrationApiMock, cryptoMock, userStorageMock)
    }

    @Test
    fun `register should return MIRACLSuccess with user`() =
        runTest {
            // Arrange
            val registratorSpy = spyk(registrator)
            val activationToken = randomUuidString()
            val pushNotificationToken = randomUuidString()
            val mpinId = randomHexString()

            val registerRequestCapturingSlot = CapturingSlot<RegisterRequestBody>()
            val registerResponse =
                RegisterResponse(
                    mpinId = mpinId,
                    projectId = projectId,
                    regOTT = randomUuidString()
                )
            coEvery {
                registrationApiMock.executeRegisterRequest(
                    capture(registerRequestCapturingSlot),
                    projectId
                )
            } returns MIRACLSuccess(value = registerResponse)

            val signingKeyPair = SigningKeyPair(randomByteArray(), randomByteArray())
            coEvery {
                cryptoMock.generateSigningKeyPair()
            } returns MIRACLSuccess(signingKeyPair)

            val dtas = randomUuidString()
            val signatureResponse = SignatureResponse(
                clientSecret2Url = randomUuidString(),
                dvsClientSecretShare = randomHexString(),
                dtas = dtas,
                curve = SupportedEllipticCurves.BN254CX.name
            )
            coEvery {
                registrationApiMock.executeSignatureRequest(
                    mpinId = mpinId,
                    regOTT = registerResponse.regOTT,
                    publicKey = signingKeyPair.publicKey.toHexString()
                )
            } returns MIRACLSuccess(value = signatureResponse)

            // Act
            registratorSpy.register(
                userId = userId,
                projectId = projectId,
                activationToken = activationToken,
                pinProvider = pinProvider,
                deviceName = deviceName,
                pushNotificationsToken = pushNotificationToken
            )

            // Assert
            coVerify {
                registratorSpy.finishRegistration(
                    userId = userId,
                    projectId = projectId,
                    mpinId = mpinId,
                    signingKeyPair = signingKeyPair,
                    clientSecretShare = signatureResponse.dvsClientSecretShare,
                    clientSecret2Url = signatureResponse.clientSecret2Url,
                    dtas = dtas,
                    pinProvider = pinProvider
                )
            }

            val registerRequestBody = registerRequestCapturingSlot.captured
            Assert.assertEquals(userId, registerRequestBody.userId)
            Assert.assertEquals(deviceName, registerRequestBody.deviceName)
            Assert.assertEquals(activationToken, registerRequestBody.activationToken)
            Assert.assertEquals(pushNotificationToken, registerRequestBody.pushToken)
        }

    @Test
    fun `register should return MIRACLError when userId is empty`() =
        runTest {
            // Arrange
            val emptyUserId = ""
            val activationToken = randomUuidString()

            // Act
            val actualResult = registrator.register(
                userId = emptyUserId,
                projectId = projectId,
                activationToken = activationToken,
                pinProvider = pinProvider,
                deviceName = deviceName,
                null
            )

            // Assert
            Assert.assertTrue(actualResult is MIRACLError)
            Assert.assertEquals(
                RegistrationException.EmptyUserId,
                (actualResult as MIRACLError).value
            )
        }

    @Test
    fun `register should return MIRACLError when activationToken is empty`() =
        runTest {
            // Arrange
            val activationToken = ""

            // Act
            val actualResult = registrator.register(
                userId = userId,
                projectId = projectId,
                activationToken = activationToken,
                pinProvider = pinProvider,
                deviceName = deviceName,
                null
            )

            // Assert
            Assert.assertTrue(actualResult is MIRACLError)
            Assert.assertTrue((actualResult as MIRACLError).value is RegistrationException.EmptyActivationToken)
        }

    @Test
    fun `register should return MIRACLError when executeRegisterRequest returns MIRACLError`() =
        runTest {
            // Arrange
            val activationToken = randomUuidString()

            val registrationException = RegistrationException.RegistrationFail(IOException())
            coEvery {
                registrationApiMock.executeRegisterRequest(any(), any())
            } returns MIRACLError(value = registrationException)

            // Act
            val actualResult = registrator.register(
                userId = userId,
                projectId = projectId,
                activationToken = activationToken,
                pinProvider = pinProvider,
                deviceName = deviceName,
                null
            )

            // Assert
            Assert.assertTrue(actualResult is MIRACLError)
            Assert.assertEquals(registrationException, (actualResult as MIRACLError).value)
        }

    @Test
    fun `register should return MIRACLError when executeRegisterRequest return different project ID`() =
        runTest {
            // Arrange
            val differentProjectId = randomUuidString()
            val activationToken = randomUuidString()

            val registerResponse =
                RegisterResponse(
                    mpinId = randomUuidString(),
                    projectId = differentProjectId,
                    regOTT = randomUuidString()
                )
            coEvery {
                registrationApiMock.executeRegisterRequest(any(), any())
            } returns MIRACLSuccess(value = registerResponse)

            // Act
            val actualResult = registrator.register(
                userId = userId,
                projectId = projectId,
                activationToken = activationToken,
                pinProvider = pinProvider,
                deviceName = deviceName,
                null
            )

            // Assert
            Assert.assertTrue(actualResult is MIRACLError)
            Assert.assertEquals(
                RegistrationException.ProjectMismatch,
                (actualResult as MIRACLError).value
            )
        }

    @Test
    fun `register should return MIRACLError when executeSignatureRequest returns MIRACLError`() =
        runTest {
            // Arrange
            val activationToken = randomUuidString()
            val registrationException = RegistrationException.RegistrationFail(IOException())

            coEvery {
                registrationApiMock.executeSignatureRequest(any(), any(), any())
            } returns MIRACLError(value = registrationException)

            setUpCryptoMock()

            // Act
            val actualResult = registrator.register(
                userId = userId,
                projectId = projectId,
                activationToken = activationToken,
                pinProvider = pinProvider,
                deviceName = deviceName,
                null
            )

            // Assert
            Assert.assertTrue(actualResult is MIRACLError)
            Assert.assertEquals(registrationException, (actualResult as MIRACLError).value)
        }

    @Test
    fun `register should return MIRACLError when executeSignatureRequest throws exception`() =
        runTest {
            // Arrange
            val activationToken = randomUuidString()
            val exception = Exception()

            coEvery {
                registrationApiMock.executeSignatureRequest(any(), any(), any())
            } throws exception

            setUpCryptoMock()

            // Act
            val actualResult = registrator.register(
                userId = userId,
                projectId = projectId,
                activationToken = activationToken,
                pinProvider = pinProvider,
                deviceName = deviceName,
                null
            )

            // Assert
            Assert.assertTrue(actualResult is MIRACLError)
            Assert.assertTrue((actualResult as MIRACLError).value is RegistrationException.RegistrationFail)
            Assert.assertEquals(exception, actualResult.value.cause)
        }

    @Test
    fun `register should return MIRACLError when curve from signatureResponse is not supported by the Crypto`() =
        runTest {
            // Arrange
            val activationToken = randomUuidString()
            val signatureResponse = SignatureResponse(
                clientSecret2Url = randomUuidString(),
                dvsClientSecretShare = randomUuidString(),
                dtas = randomUuidString(),
                curve = "unsupported curve"
            )
            coEvery {
                registrationApiMock.executeSignatureRequest(any(), any(), any())
            } returns MIRACLSuccess(value = signatureResponse)

            setUpCryptoMock()

            // Act
            val actualResult = registrator.register(
                userId = userId,
                projectId = projectId,
                activationToken = activationToken,
                pinProvider = pinProvider,
                deviceName = deviceName,
                null
            )

            // Assert
            Assert.assertTrue(actualResult is MIRACLError)
            Assert.assertEquals(
                RegistrationException.UnsupportedEllipticCurve,
                (actualResult as MIRACLError).value
            )
        }

    @Test
    fun `register should return MIRACLError when finishRegistration returns MIRACLError`() =
        runTest {
            // Arrange
            val activationToken = randomUuidString()

            val cryptoException = CryptoException.GetSigningClientTokenError()
            coEvery {
                cryptoMock.getSigningClientToken(
                    clientSecretShare1 = any(),
                    clientSecretShare2 = any(),
                    privateKey = any(),
                    signingMpinId = any(),
                    pin = any()
                )
            } returns MIRACLError(cryptoException)

            // Act
            val actualResult = registrator.register(
                userId = userId,
                projectId = projectId,
                activationToken = activationToken,
                pinProvider = pinProvider,
                deviceName = deviceName,
                null
            )

            // Assert
            Assert.assertTrue(actualResult is MIRACLError)
            Assert.assertTrue((actualResult as MIRACLError).value is RegistrationException.RegistrationFail)
            Assert.assertEquals(cryptoException, actualResult.value.cause)
        }

    @Test
    fun `finishRegistration should return MIRACLSuccess with user`() =
        runTest {
            // Arrange
            val mpinId = randomHexString()
            val hashOfMpinId = mpinId.hexStringToByteArray().toSHA256()

            val dtas = randomUuidString()
            val clientSecret2Url = randomUuidString()
            val clientSecretShare = randomHexString()

            val signingKeyPair = SigningKeyPair(randomByteArray(), randomByteArray())

            val clientSecretShare2Response = createDVSClientSecret2Response()
            coEvery {
                registrationApiMock.executeDVSClientSecret2Request(clientSecret2Url, projectId)
            } returns MIRACLSuccess(value = clientSecretShare2Response)

            val expectedToken = randomByteArray()
            coEvery {
                cryptoMock.getSigningClientToken(
                    clientSecretShare.hexStringToByteArray(),
                    clientSecretShare2Response.dvsClientSecret.hexStringToByteArray(),
                    signingKeyPair.privateKey,
                    mpinId.hexStringToByteArray() + signingKeyPair.publicKey,
                    pin.toInt()
                )
            } returns MIRACLSuccess(
                value = expectedToken
            )
            every { userStorageMock.getUser(userId, projectId) } returns null
            every { userStorageMock.add(ofType(User::class)) } just runs

            // Act
            val actualResult = registrator.finishRegistration(
                userId,
                projectId,
                mpinId,
                signingKeyPair,
                clientSecretShare,
                clientSecret2Url,
                dtas,
                pinProvider
            )

            // Assert
            Assert.assertTrue(actualResult is MIRACLSuccess)

            val user = (actualResult as MIRACLSuccess).value

            Assert.assertEquals(userId, user.userId)
            Assert.assertFalse(user.revoked)
            Assert.assertEquals(pin.length, user.pinLength)
            Assert.assertArrayEquals(mpinId.hexStringToByteArray(), user.mpinId)
            Assert.assertArrayEquals(expectedToken, user.token)
            Assert.assertEquals(dtas, user.dtas)
            Assert.assertEquals(signingKeyPair.publicKey, user.publicKey)
            Assert.assertEquals(hashOfMpinId, user.hashedMpinId)

            val userCapturingSlot = CapturingSlot<User>()
            verify { userStorageMock.add(capture(userCapturingSlot)) }
            Assert.assertEquals(user, userCapturingSlot.captured)
        }

    @Test
    fun `finishRegistration should return MIRACLError when could not save user to user storage`() =
        runTest {
            // Arrange
            val registerResponse = createRegisterResponse()
            val signatureResponse = createSignatureResponse()

            every { userStorageMock.getUser(userId, projectId) } returns null

            val exception = Exception()
            every { userStorageMock.add(ofType(User::class)) } throws exception

            // Act
            val actualResult = registrator.finishRegistration(
                userId,
                projectId,
                registerResponse.mpinId,
                createSigningKeyPair(),
                signatureResponse.dvsClientSecretShare,
                signatureResponse.clientSecret2Url,
                signatureResponse.dtas,
                pinProvider
            )

            // Assert
            Assert.assertTrue(actualResult is MIRACLError)
            Assert.assertTrue((actualResult as MIRACLError).value is RegistrationException.RegistrationFail)
            Assert.assertEquals(exception, actualResult.value.cause)
        }

    @Test
    fun `finishRegistration should return MIRACLError when mpinId is not a valid hexString`() =
        runTest {
            // Arrange
            val invalidMpinId = "invalid mpinId"
            val registerResponse = RegisterResponse(
                mpinId = invalidMpinId,
                projectId = projectId,
                regOTT = randomUuidString()
            )
            val signatureResponse = createSignatureResponse()

            // Act
            val actualResult = registrator.finishRegistration(
                userId,
                projectId,
                registerResponse.mpinId,
                createSigningKeyPair(),
                signatureResponse.dvsClientSecretShare,
                signatureResponse.clientSecret2Url,
                signatureResponse.dtas,
                pinProvider
            )

            // Assert
            Assert.assertTrue(actualResult is MIRACLError)
            Assert.assertTrue((actualResult as MIRACLError).value is RegistrationException.RegistrationFail)
            Assert.assertTrue(actualResult.value.cause is NumberFormatException)
        }

    @Test
    fun `finishRegistration should return MIRACLError when executeDVSClientSecret2Request request returns MIRACLError`() =
        runTest {
            // Arrange
            val registerResponse = createRegisterResponse()
            val signatureResponse = createSignatureResponse()

            val registrationException = RegistrationException.RegistrationFail(IOException())
            coEvery {
                registrationApiMock.executeDVSClientSecret2Request(any(), any())
            } returns MIRACLError(registrationException)

            // Act
            val actualResult = registrator.finishRegistration(
                userId,
                projectId,
                registerResponse.mpinId,
                createSigningKeyPair(),
                signatureResponse.dvsClientSecretShare,
                signatureResponse.clientSecret2Url,
                signatureResponse.dtas,
                pinProvider
            )

            // Assert
            Assert.assertTrue(actualResult is MIRACLError)
            Assert.assertEquals(registrationException, (actualResult as MIRACLError).value)
        }

    @Test
    fun `finishRegistration should return MIRACLError when client secret share1 is not a valid hexString`() =
        runTest {
            // Arrange
            val registerResponse = createRegisterResponse()
            val invalidSecretShare1 = "invalid css1"
            val signatureResponse = SignatureResponse(
                clientSecret2Url = randomUuidString(),
                dvsClientSecretShare = invalidSecretShare1,
                dtas = randomUuidString(),
                curve = SupportedEllipticCurves.BN254CX.name
            )

            // Act
            val actualResult = registrator.finishRegistration(
                userId,
                projectId,
                registerResponse.mpinId,
                createSigningKeyPair(),
                signatureResponse.dvsClientSecretShare,
                signatureResponse.clientSecret2Url,
                signatureResponse.dtas,
                pinProvider
            )

            // Assert
            Assert.assertTrue(actualResult is MIRACLError)
            Assert.assertTrue((actualResult as MIRACLError).value is RegistrationException.RegistrationFail)
            Assert.assertTrue(actualResult.value.cause is NumberFormatException)
        }

    @Test
    fun `finishRegistration should return MIRACLError when entering the pin was canceled`() {
        runTest {
            // Arrange
            val mpinId = randomHexString()
            val signatureResponse = createSignatureResponse()

            // Act
            val actualResult = registrator.finishRegistration(
                userId,
                projectId,
                mpinId,
                createSigningKeyPair(),
                signatureResponse.dvsClientSecretShare,
                signatureResponse.clientSecret2Url,
                signatureResponse.dtas,
            ) { it.consume(null) }

            // Assert
            Assert.assertTrue(actualResult is MIRACLError)
            Assert.assertTrue((actualResult as MIRACLError).value is RegistrationException.PinCancelled)
        }
    }

    @Test
    fun `finishRegistration should return MIRACLError when passed pin is less than 4 digits`() {
        runTest {
            // Arrange
            val pin = randomNumericPin(length = 3)
            val mpinId = randomHexString()
            val signatureResponse = createSignatureResponse()

            // Act
            val actualResult = registrator.finishRegistration(
                userId,
                projectId,
                mpinId,
                createSigningKeyPair(),
                signatureResponse.dvsClientSecretShare,
                signatureResponse.clientSecret2Url,
                signatureResponse.dtas,
            ) { it.consume(pin) }

            // Assert
            Assert.assertTrue(actualResult is MIRACLError)
            Assert.assertTrue((actualResult as MIRACLError).value is RegistrationException.InvalidPin)
        }
    }

    @Test
    fun `finishRegistration should return MIRACLError when passed pin is more than 6 digits`() {
        runTest {
            // Arrange
            val pin = randomNumericPin(7)
            val mpinId = randomHexString()
            val signatureResponse = createSignatureResponse()

            // Act
            val actualResult = registrator.finishRegistration(
                userId,
                projectId,
                mpinId,
                createSigningKeyPair(),
                signatureResponse.dvsClientSecretShare,
                signatureResponse.clientSecret2Url,
                signatureResponse.dtas,
            ) { it.consume(pin) }

            // Assert
            Assert.assertTrue(actualResult is MIRACLError)
            Assert.assertTrue((actualResult as MIRACLError).value is RegistrationException.InvalidPin)
        }
    }

    @Test
    fun `finishRegistration should return MIRACLError when passed pin cannot be parsed to integer`() {
        runTest {
            // Arrange
            val pin = "a" + randomNumericPin(randomPinLength()).substring(1)
            val mpinId = randomHexString()
            val signatureResponse = createSignatureResponse()

            // Act
            val actualResult = registrator.finishRegistration(
                userId,
                projectId,
                mpinId,
                createSigningKeyPair(),
                signatureResponse.dvsClientSecretShare,
                signatureResponse.clientSecret2Url,
                signatureResponse.dtas,
            ) { it.consume(pin) }

            // Assert
            Assert.assertTrue(actualResult is MIRACLError)
            Assert.assertTrue((actualResult as MIRACLError).value is RegistrationException.InvalidPin)
        }
    }

    @Test
    fun `finishRegistration should return MIRACLError when getClientToken returns MIRACLError`() =
        runTest {
            // Arrange
            val cryptoException = CryptoException.GetClientTokenError()
            coEvery {
                cryptoMock.getSigningClientToken(
                    clientSecretShare1 = any(),
                    clientSecretShare2 = any(),
                    privateKey = any(),
                    signingMpinId = any(),
                    pin = any()
                )
            } returns MIRACLError(cryptoException)

            // Act
            val actualResult = registrator.finishRegistration(
                userId,
                projectId = projectId,
                randomHexString(),
                createSigningKeyPair(),
                randomHexString(),
                randomUuidString(),
                randomUuidString(),
                pinProvider
            )

            // Assert
            Assert.assertTrue(actualResult is MIRACLError)
            Assert.assertTrue((actualResult as MIRACLError).value is RegistrationException.RegistrationFail)
            Assert.assertEquals(cryptoException, actualResult.value.cause)
        }

    @Test
    fun `finishRegistration should return MIRACLError when dvs client secret share2 is not a valid hexString`() =
        runTest {
            // Arrange
            val registerResponse = createRegisterResponse()
            val signatureResponse = createSignatureResponse()

            val invalidSecretShare2 = "invalid css2"
            val clientSecretShare2Response = DVSClientSecret2Response(
                dvsClientSecret = invalidSecretShare2
            )
            coEvery {
                registrationApiMock.executeDVSClientSecret2Request(any(), any())
            } returns MIRACLSuccess(value = clientSecretShare2Response)

            // Act
            val actualResult = registrator.finishRegistration(
                userId,
                projectId,
                registerResponse.mpinId,
                createSigningKeyPair(),
                signatureResponse.dvsClientSecretShare,
                signatureResponse.clientSecret2Url,
                signatureResponse.dtas,
                pinProvider
            )

            // Assert
            Assert.assertTrue(actualResult is MIRACLError)
            Assert.assertTrue((actualResult as MIRACLError).value is RegistrationException.RegistrationFail)
            Assert.assertTrue(actualResult.value.cause is NumberFormatException)
        }

    @Test
    fun `finishRegistration should update existing user`() =
        runTest {
            // Arrange
            val mpinId = randomHexString()
            val hashOfMpinId = mpinId.hexStringToByteArray().toSHA256()
            val signingKeyPair = createSigningKeyPair()
            val signatureResponse = createSignatureResponse()

            val expectedToken = randomByteArray()
            coEvery {
                cryptoMock.getSigningClientToken(
                    clientSecretShare1 = any(),
                    clientSecretShare2 = any(),
                    privateKey = any(),
                    signingMpinId = any(),
                    pin = any()
                )
            } returns MIRACLSuccess(
                value = expectedToken
            )

            every { userStorageMock.getUser(userId, projectId) } returns createUser()
            every { userStorageMock.update(ofType(User::class)) } just runs

            // Act
            val actualResult = registrator.finishRegistration(
                userId,
                projectId,
                mpinId,
                signingKeyPair,
                signatureResponse.dvsClientSecretShare,
                signatureResponse.clientSecret2Url,
                signatureResponse.dtas,
                pinProvider
            )

            // Assert
            Assert.assertTrue(actualResult is MIRACLSuccess)
            Assert.assertEquals(userId, (actualResult as MIRACLSuccess).value.userId)

            val capturingSlot = CapturingSlot<User>()
            verify { userStorageMock.update(capture(capturingSlot)) }
            val user = capturingSlot.captured

            Assert.assertEquals(userId, user.userId)
            Assert.assertEquals(projectId, user.projectId)
            Assert.assertEquals(pin.length, user.pinLength)
            Assert.assertArrayEquals(mpinId.hexStringToByteArray(), user.mpinId)
            Assert.assertArrayEquals(expectedToken, user.token)
            Assert.assertEquals(signatureResponse.dtas, user.dtas)
            Assert.assertEquals(signingKeyPair.publicKey, user.publicKey)
            Assert.assertEquals(hashOfMpinId, user.hashedMpinId)
        }

    @Test
    fun `finishRegistration should return MIRACLError when could not update existing user`() =
        runTest {
            // Arrange
            every { userStorageMock.getUser(userId, projectId) } returns createUser()

            val exception = Exception()
            every { userStorageMock.update(ofType(User::class)) } throws exception

            // Act
            val actualResult = registrator.finishRegistration(
                userId,
                projectId,
                randomHexString(),
                createSigningKeyPair(),
                randomHexString(),
                randomUuidString(),
                randomUuidString(),
                pinProvider
            )

            // Assert
            Assert.assertTrue(actualResult is MIRACLError)
            Assert.assertTrue((actualResult as MIRACLError).value is RegistrationException.RegistrationFail)
            Assert.assertEquals(exception, actualResult.value.cause)
        }

    private fun createUser() = User(
        userId = userId,
        projectId = projectId,
        revoked = Random.nextBoolean(),
        pinLength = randomPinLength(),
        mpinId = randomByteArray(),
        token = randomByteArray(),
        dtas = randomUuidString(),
        publicKey = randomByteArray()
    )

    private fun createRegisterResponse() =
        RegisterResponse(
            mpinId = randomHexString(),
            projectId = projectId,
            regOTT = randomUuidString()
        )

    private fun createSignatureResponse() =
        SignatureResponse(
            clientSecret2Url = randomUuidString(),
            dvsClientSecretShare = randomHexString(),
            dtas = randomUuidString(),
            curve = SupportedEllipticCurves.BN254CX.name
        )

    private fun createDVSClientSecret1Response() =
        DVSClientSecret1Response(
            dvsClientSecretShare = randomHexString(),
            clientSecret2Url = randomUuidString(),
            curve = SupportedEllipticCurves.BN254CX.name,
            dtas = randomUuidString(),
            mpinId = randomHexString()
        )

    private fun createDVSClientSecret2Response() =
        DVSClientSecret2Response(
            dvsClientSecret = randomHexString()
        )

    private fun setUpRegistrationApiMock() {
        val registerResponse = createRegisterResponse()
        coEvery {
            registrationApiMock.executeRegisterRequest(any(), any())
        } returns MIRACLSuccess(value = registerResponse)

        val signatureResponse = createSignatureResponse()
        coEvery {
            registrationApiMock.executeSignatureRequest(any(), any(), any())
        } returns MIRACLSuccess(value = signatureResponse)

        val clientSecretShare1Response = createDVSClientSecret1Response()
        coEvery {
            registrationApiMock.executeDVSClientSecret1Request(any(), any(), any())
        } returns MIRACLSuccess(value = clientSecretShare1Response)

        val clientSecretShare2Response = createDVSClientSecret2Response()
        coEvery {
            registrationApiMock.executeDVSClientSecret2Request(any(), any())
        } returns MIRACLSuccess(value = clientSecretShare2Response)
    }

    private fun createSigningKeyPair() = SigningKeyPair(randomByteArray(), randomByteArray())

    private fun setUpCryptoMock(
        keyPair: SigningKeyPair = createSigningKeyPair()
    ) {
        coEvery {
            cryptoMock.generateSigningKeyPair()
        } returns MIRACLSuccess(keyPair)

        coEvery {
            cryptoMock.getSigningClientToken(
                clientSecretShare1 = any(),
                clientSecretShare2 = any(),
                privateKey = any(),
                signingMpinId = any(),
                pin = any(),
            )
        } returns MIRACLSuccess(value = randomByteArray())
    }
}