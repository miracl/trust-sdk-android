package com.miracl.trust.registration

import com.miracl.trust.MIRACLError
import com.miracl.trust.MIRACLSuccess
import com.miracl.trust.assertUserEqualsDto
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
import com.miracl.trust.storage.UserDto
import com.miracl.trust.storage.UserStorage
import com.miracl.trust.util.hexStringToByteArray
import com.miracl.trust.util.toHexString
import com.miracl.trust.util.toSHA256
import com.miracl.trust.util.toUserDto
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
            val dtas = randomUuidString()

            val registerRequestCapturingSlot = CapturingSlot<RegisterRequestBody>()
            val registerResponse =
                RegisterResponse(
                    mpinId = mpinId,
                    projectId = projectId,
                    dtas = dtas,
                    curve = SupportedEllipticCurves.BN254CX.name,
                    secretUrls = listOf(randomUuidString(), randomUuidString())
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
                    secretUrls = registerResponse.secretUrls,
                    dtas = dtas,
                    pinProvider = pinProvider
                )
            }

            val registerRequestBody = registerRequestCapturingSlot.captured
            Assert.assertEquals(userId, registerRequestBody.userId)
            Assert.assertEquals(deviceName, registerRequestBody.deviceName)
            Assert.assertEquals(activationToken, registerRequestBody.activationToken)
            Assert.assertEquals(pushNotificationToken, registerRequestBody.pushToken)
            Assert.assertEquals(
                signingKeyPair.publicKey.toHexString(),
                registerRequestBody.publicKey
            )
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
    fun `register should return MIRACLError when generateSigningKeyPair returns MIRACLError`() =
        runTest {
            // Arrange
            val activationToken = randomUuidString()

            val cryptoException = CryptoException.GenerateSigningKeyPairError()
            coEvery {
                cryptoMock.generateSigningKeyPair()
            } returns MIRACLError(value = cryptoException)

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
                    dtas = randomUuidString(),
                    curve = SupportedEllipticCurves.BN254CX.name,
                    secretUrls = listOf(randomUuidString(), randomUuidString())
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
    fun `register should return MIRACLError when curve from registerResponse is not supported by the Crypto`() =
        runTest {
            // Arrange
            val activationToken = randomUuidString()

            val registerResponse =
                RegisterResponse(
                    mpinId = randomUuidString(),
                    projectId = projectId,
                    dtas = randomUuidString(),
                    curve = "unsupported curve",
                    secretUrls = listOf(randomUuidString(), randomUuidString())
                )
            coEvery {
                registrationApiMock.executeRegisterRequest(any(), any())
            } returns MIRACLSuccess(value = registerResponse)

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
            val secretUrls = listOf(randomUuidString(), randomUuidString())

            val signingKeyPair = SigningKeyPair(randomByteArray(), randomByteArray())

            val clientSecretShare1Response = createDVSClientSecretResponse()
            coEvery {
                registrationApiMock.executeDVSClientSecretRequest(secretUrls[0])
            } returns MIRACLSuccess(value = clientSecretShare1Response)

            val clientSecretShare2Response = createDVSClientSecretResponse()
            coEvery {
                registrationApiMock.executeDVSClientSecretRequest(secretUrls[1])
            } returns MIRACLSuccess(value = clientSecretShare2Response)

            val expectedToken = randomByteArray()
            coEvery {
                cryptoMock.getSigningClientToken(
                    clientSecretShare1Response.dvsClientSecret.hexStringToByteArray(),
                    clientSecretShare2Response.dvsClientSecret.hexStringToByteArray(),
                    signingKeyPair.privateKey,
                    mpinId.hexStringToByteArray() + signingKeyPair.publicKey,
                    pin.toInt()
                )
            } returns MIRACLSuccess(
                value = expectedToken
            )
            every { userStorageMock.getUser(userId, projectId) } returns null
            every { userStorageMock.add(ofType(UserDto::class)) } just runs

            // Act
            val actualResult = registrator.finishRegistration(
                userId,
                projectId,
                mpinId,
                signingKeyPair,
                secretUrls,
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

            val userCapturingSlot = CapturingSlot<UserDto>()
            verify { userStorageMock.add(capture(userCapturingSlot)) }
            assertUserEqualsDto(user, userCapturingSlot.captured)
        }

    @Test
    fun `finishRegistration should return MIRACLError when could not save user to user storage`() =
        runTest {
            // Arrange
            val registerResponse = createRegisterResponse()

            every { userStorageMock.getUser(userId, projectId) } returns null

            val exception = Exception()
            every { userStorageMock.add(ofType(UserDto::class)) } throws exception

            // Act
            val actualResult = registrator.finishRegistration(
                userId,
                projectId,
                registerResponse.mpinId,
                createSigningKeyPair(),
                registerResponse.secretUrls,
                registerResponse.dtas,
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
                dtas = randomUuidString(),
                curve = SupportedEllipticCurves.BN254CX.name,
                secretUrls = listOf(randomUuidString(), randomUuidString())
            )

            // Act
            val actualResult = registrator.finishRegistration(
                userId,
                projectId,
                registerResponse.mpinId,
                createSigningKeyPair(),
                registerResponse.secretUrls,
                registerResponse.dtas,
                pinProvider
            )

            // Assert
            Assert.assertTrue(actualResult is MIRACLError)
            Assert.assertTrue((actualResult as MIRACLError).value is RegistrationException.RegistrationFail)
            Assert.assertTrue(actualResult.value.cause is NumberFormatException)
        }

    @Test
    fun `finishRegistration should return MIRACLError when executeDVSClientSecretRequest request returns MIRACLError`() =
        runTest {
            // Arrange
            val registerResponse = createRegisterResponse()

            val registrationException = RegistrationException.RegistrationFail(IOException())
            coEvery {
                registrationApiMock.executeDVSClientSecretRequest(any())
            } returns MIRACLError(registrationException)

            // Act
            val actualResult = registrator.finishRegistration(
                userId,
                projectId,
                registerResponse.mpinId,
                createSigningKeyPair(),
                registerResponse.secretUrls,
                registerResponse.dtas,
                pinProvider
            )

            // Assert
            Assert.assertTrue(actualResult is MIRACLError)
            Assert.assertEquals(registrationException, (actualResult as MIRACLError).value)
        }

    @Test
    fun `finishRegistration should return MIRACLError when entering the pin was canceled`() {
        runTest {
            // Arrange
            val mpinId = randomHexString()
            val registerResponse = createRegisterResponse()

            // Act
            val actualResult = registrator.finishRegistration(
                userId,
                projectId,
                mpinId,
                createSigningKeyPair(),
                registerResponse.secretUrls,
                registerResponse.dtas,
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
            val registerResponse = createRegisterResponse()

            // Act
            val actualResult = registrator.finishRegistration(
                userId,
                projectId,
                mpinId,
                createSigningKeyPair(),
                registerResponse.secretUrls,
                registerResponse.dtas,
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
            val registerResponse = createRegisterResponse()

            // Act
            val actualResult = registrator.finishRegistration(
                userId,
                projectId,
                mpinId,
                createSigningKeyPair(),
                registerResponse.secretUrls,
                registerResponse.dtas,
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
            val registerResponse = createRegisterResponse()

            // Act
            val actualResult = registrator.finishRegistration(
                userId,
                projectId,
                mpinId,
                createSigningKeyPair(),
                registerResponse.secretUrls,
                registerResponse.dtas,
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
                listOf(randomHexString(), randomHexString()),
                randomUuidString(),
                pinProvider
            )

            // Assert
            Assert.assertTrue(actualResult is MIRACLError)
            Assert.assertTrue((actualResult as MIRACLError).value is RegistrationException.RegistrationFail)
            Assert.assertEquals(cryptoException, actualResult.value.cause)
        }

    @Test
    fun `finishRegistration should return MIRACLError when dvs client secret share is not a valid hexString`() =
        runTest {
            // Arrange
            val registerResponse = createRegisterResponse()

            val invalidSecretShare = "invalid css"
            val clientSecretShareResponse = DVSClientSecretResponse(
                dvsClientSecret = invalidSecretShare
            )
            coEvery {
                registrationApiMock.executeDVSClientSecretRequest(any())
            } returns MIRACLSuccess(value = clientSecretShareResponse)

            // Act
            val actualResult = registrator.finishRegistration(
                userId,
                projectId,
                registerResponse.mpinId,
                createSigningKeyPair(),
                registerResponse.secretUrls,
                registerResponse.dtas,
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
            val signingKeyPair = createSigningKeyPair()
            val registerResponse = createRegisterResponse()

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

            every { userStorageMock.getUser(userId, projectId) } returns createUser().toUserDto()
            every { userStorageMock.update(ofType(UserDto::class)) } just runs

            // Act
            val actualResult = registrator.finishRegistration(
                userId,
                projectId,
                mpinId,
                signingKeyPair,
                registerResponse.secretUrls,
                registerResponse.dtas,
                pinProvider
            )

            // Assert
            Assert.assertTrue(actualResult is MIRACLSuccess)
            Assert.assertEquals(userId, (actualResult as MIRACLSuccess).value.userId)

            val capturingSlot = CapturingSlot<UserDto>()
            verify { userStorageMock.update(capture(capturingSlot)) }
            val user = capturingSlot.captured

            Assert.assertEquals(userId, user.userId)
            Assert.assertEquals(projectId, user.projectId)
            Assert.assertEquals(pin.length, user.pinLength)
            Assert.assertArrayEquals(mpinId.hexStringToByteArray(), user.mpinId)
            Assert.assertArrayEquals(expectedToken, user.token)
            Assert.assertEquals(registerResponse.dtas, user.dtas)
            Assert.assertEquals(signingKeyPair.publicKey, user.publicKey)
        }

    @Test
    fun `finishRegistration should return MIRACLError when could not update existing user`() =
        runTest {
            // Arrange
            every { userStorageMock.getUser(userId, projectId) } returns createUser().toUserDto()

            val exception = Exception()
            every { userStorageMock.update(ofType(UserDto::class)) } throws exception

            // Act
            val actualResult = registrator.finishRegistration(
                userId,
                projectId,
                randomHexString(),
                createSigningKeyPair(),
                listOf(randomHexString(), randomHexString()),
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
            dtas = randomUuidString(),
            curve = SupportedEllipticCurves.BN254CX.name,
            secretUrls = listOf(randomUuidString(), randomUuidString())
        )

    private fun createDVSClientSecretResponse() =
        DVSClientSecretResponse(
            dvsClientSecret = randomHexString()
        )

    private fun setUpRegistrationApiMock() {
        val registerResponse = createRegisterResponse()
        coEvery {
            registrationApiMock.executeRegisterRequest(any(), any())
        } returns MIRACLSuccess(value = registerResponse)

        val clientSecretShare2Response = createDVSClientSecretResponse()
        coEvery {
            registrationApiMock.executeDVSClientSecretRequest(any())
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