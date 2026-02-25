package com.miracl.trust.signing

import com.miracl.trust.MIRACLError
import com.miracl.trust.MIRACLSuccess
import com.miracl.trust.authentication.AuthenticationException
import com.miracl.trust.authentication.AuthenticatorContract
import com.miracl.trust.authentication.AuthenticatorScopes
import com.miracl.trust.copy
import com.miracl.trust.crypto.Crypto
import com.miracl.trust.crypto.CryptoException
import com.miracl.trust.crypto.SigningResult
import com.miracl.trust.delegate.PinProvider
import com.miracl.trust.model.User
import com.miracl.trust.randomByteArray
import com.miracl.trust.randomHexString
import com.miracl.trust.randomNumericPin
import com.miracl.trust.randomPinLength
import com.miracl.trust.randomUuidString
import com.miracl.trust.session.CrossDeviceSession
import com.miracl.trust.session.CrossDeviceSessionApi
import com.miracl.trust.storage.UserStorage
import com.miracl.trust.util.hexStringToByteArray
import com.miracl.trust.util.toHexString
import com.miracl.trust.util.toUserDto
import io.mockk.CapturingSlot
import io.mockk.clearAllMocks
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.mockk
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.runTest
import org.junit.Assert
import org.junit.Before
import org.junit.Test

@ExperimentalCoroutinesApi
class DocumentSignerUnitTest {
    private val userId = randomUuidString()
    private val pinLength = randomPinLength()
    private val pin = randomNumericPin(pinLength)
    private val mpinId = randomByteArray()
    private val token = randomByteArray()
    private val publicKey = randomByteArray()
    private val dtas = randomUuidString()
    private val deviceName = randomUuidString()
    private val projectId = randomUuidString()

    private val cryptoMock = mockk<Crypto>()
    private val authenticatorContractMock = mockk<AuthenticatorContract>()
    private val pinProviderMock = PinProvider { it.consume(pin) }
    private val userStorageMock = mockk<UserStorage>()
    private val crossDeviceSessionApiMock = mockk<CrossDeviceSessionApi>()

    @Before
    fun resetMocks() {
        clearAllMocks()
        coEvery { userStorageMock.getUser(any(), any()) } returns createSigningUser().toUserDto()
    }

    @Test
    fun `sign should return MIRACLSuccess with Signature as a result on success`() =
        runTest {
            // Arrange
            val message = randomByteArray()
            val signingUser = createSigningUser()

            coEvery {
                authenticatorContractMock.authenticate(
                    signingUser,
                    null,
                    any(),
                    arrayOf(AuthenticatorScopes.SIGNING_AUTHENTICATION.value),
                    deviceName
                )
            } returns MIRACLSuccess(mockk())

            val u = randomByteArray()
            val v = randomByteArray()
            coEvery {
                cryptoMock.sign(
                    message,
                    mpinId.plus(publicKey),
                    token,
                    any(),
                    pin.toInt()
                )
            } returns MIRACLSuccess(SigningResult(u, v))

            val documentSigner =
                DocumentSigner(
                    cryptoMock,
                    authenticatorContractMock,
                    userStorageMock,
                    crossDeviceSessionApiMock
                )

            // Act
            val result = documentSigner.sign(
                message,
                signingUser,
                pinProviderMock,
                deviceName
            )

            // Assert
            Assert.assertTrue(result is MIRACLSuccess)
            val signature = (result as MIRACLSuccess).value.signature
            Assert.assertEquals(message.toHexString(), signature.hash)
            Assert.assertEquals(u.toHexString(), signature.U)
            Assert.assertEquals(v.toHexString(), signature.V)
            Assert.assertEquals(dtas, signature.dtas)
            Assert.assertEquals(mpinId.toHexString(), signature.mpinId)
            Assert.assertEquals(publicKey.toHexString(), signature.publicKey)
        }

    @Test
    fun `sign should return MIRACLError when user is revoked`() =
        runTest {
            // Arrange
            val message = randomByteArray()
            val signingUser = createSigningUser().copy(revoked = true)

            val documentSigner =
                DocumentSigner(
                    cryptoMock,
                    authenticatorContractMock,
                    userStorageMock,
                    crossDeviceSessionApiMock
                )

            // Act
            val result = documentSigner.sign(
                message,
                signingUser,
                pinProviderMock,
                deviceName
            )

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertEquals(
                SigningException.Revoked,
                (result as MIRACLError).value
            )
        }

    @Test
    fun `sign should return MIRACLError when user has empty dtas`() =
        runTest {
            // Arrange
            val message = randomByteArray()
            val emptyDtas = ""
            val signingUser = createSigningUser().copy(dtas = emptyDtas)

            val documentSigner =
                DocumentSigner(
                    cryptoMock,
                    authenticatorContractMock,
                    userStorageMock,
                    crossDeviceSessionApiMock
                )

            // Act
            val result = documentSigner.sign(
                message,
                signingUser,
                pinProviderMock,
                deviceName
            )

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertEquals(
                SigningException.InvalidUserData,
                (result as MIRACLError).value
            )
        }

    @Test
    fun `sign should return MIRACLError when user has empty token`() =
        runTest {
            // Arrange
            val message = randomByteArray()
            val emptyToken = byteArrayOf()
            val signingUser = createSigningUser().copy(token = emptyToken)

            val documentSigner =
                DocumentSigner(
                    cryptoMock,
                    authenticatorContractMock,
                    userStorageMock,
                    crossDeviceSessionApiMock
                )

            // Act
            val result = documentSigner.sign(
                message,
                signingUser,
                pinProviderMock,
                deviceName
            )

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertEquals(
                SigningException.InvalidUserData,
                (result as MIRACLError).value
            )
        }

    @Test
    fun `sign should return MIRACLError when user has empty mpinId`() =
        runTest {
            // Arrange
            val message = randomByteArray()
            val emptyMpinId = byteArrayOf()
            val signingUser = createSigningUser().copy(mpinId = emptyMpinId)

            val documentSigner =
                DocumentSigner(
                    cryptoMock,
                    authenticatorContractMock,
                    userStorageMock,
                    crossDeviceSessionApiMock
                )

            // Act
            val result = documentSigner.sign(
                message,
                signingUser,
                pinProviderMock,
                deviceName
            )

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertEquals(
                SigningException.InvalidUserData,
                (result as MIRACLError).value
            )
        }

    @Test
    fun `sign should return MIRACLError when the user hasn't publicKey`() =
        runTest {
            // Arrange
            val message = randomByteArray()
            val nullPublicKey = null
            val signingUser = createSigningUser().copy(publicKey = nullPublicKey)

            coEvery {
                authenticatorContractMock.authenticate(
                    signingUser,
                    any(),
                    any(),
                    arrayOf(AuthenticatorScopes.SIGNING_AUTHENTICATION.value),
                    deviceName
                )
            } returns MIRACLSuccess(mockk())

            coEvery { userStorageMock.getUser(any(), any()) } returns signingUser.toUserDto()

            val documentSigner =
                DocumentSigner(
                    cryptoMock,
                    authenticatorContractMock,
                    userStorageMock,
                    crossDeviceSessionApiMock
                )

            // Act
            val result = documentSigner.sign(
                message,
                signingUser,
                pinProviderMock,
                deviceName
            )

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertEquals(
                SigningException.EmptyPublicKey,
                (result as MIRACLError).value
            )
        }

    @Test
    fun `sign should return MIRACLError when the user has empty publicKey`() =
        runTest {
            // Arrange
            val message = randomByteArray()
            val emptyPublicKey = byteArrayOf()
            val signingUser = createSigningUser().copy(publicKey = emptyPublicKey)

            coEvery {
                authenticatorContractMock.authenticate(
                    signingUser,
                    any(),
                    any(),
                    arrayOf(AuthenticatorScopes.SIGNING_AUTHENTICATION.value),
                    deviceName
                )
            } returns MIRACLSuccess(mockk())

            coEvery { userStorageMock.getUser(any(), any()) } returns signingUser.toUserDto()

            val documentSigner =
                DocumentSigner(
                    cryptoMock,
                    authenticatorContractMock,
                    userStorageMock,
                    crossDeviceSessionApiMock
                )

            // Act
            val result = documentSigner.sign(
                message,
                signingUser,
                pinProviderMock,
                deviceName
            )

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertEquals(
                SigningException.EmptyPublicKey,
                (result as MIRACLError).value
            )
        }

    @Test
    fun `sign should return MIRACLError when message is empty`() =
        runTest {
            // Arrange
            val message = byteArrayOf()
            val signingUser = createSigningUser()

            val documentSigner =
                DocumentSigner(
                    cryptoMock,
                    authenticatorContractMock,
                    userStorageMock,
                    crossDeviceSessionApiMock
                )

            // Act
            val result = documentSigner.sign(
                message,
                signingUser,
                pinProviderMock,
                deviceName
            )

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertEquals(
                SigningException.EmptyMessageHash,
                (result as MIRACLError).value
            )
        }

    @Test
    fun `sign should return MIRACLError on empty pin entered`() {
        runTest {
            // Arrange
            val pin = null
            val message = randomByteArray()
            val signingUser = createSigningUser()

            val documentSigner =
                DocumentSigner(
                    cryptoMock,
                    authenticatorContractMock,
                    userStorageMock,
                    crossDeviceSessionApiMock
                )

            // Act
            val result = documentSigner.sign(
                message,
                signingUser,
                { it.consume(pin) },
                deviceName
            )

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertEquals(SigningException.PinCancelled, (result as MIRACLError).value)
        }
    }

    @Test
    fun `sign should return MIRACLError when the passed pin has shorter length`() {
        runTest {
            // Arrange
            val pin = randomNumericPin(3)
            val message = randomByteArray()
            val signingUser = createSigningUser()

            val documentSigner =
                DocumentSigner(
                    cryptoMock,
                    authenticatorContractMock,
                    userStorageMock,
                    crossDeviceSessionApiMock
                )

            // Act
            val result = documentSigner.sign(
                message,
                signingUser,
                { it.consume(pin) },
                deviceName
            )

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertEquals(SigningException.InvalidPin, (result as MIRACLError).value)
        }
    }

    @Test
    fun `sign should return MIRACLError when the passed pin has longer length`() {
        runTest {
            // Arrange
            val pin = randomNumericPin(7)
            val message = randomByteArray()
            val signingUser = createSigningUser()

            val documentSigner =
                DocumentSigner(
                    cryptoMock,
                    authenticatorContractMock,
                    userStorageMock,
                    crossDeviceSessionApiMock
                )

            // Act
            val result = documentSigner.sign(
                message,
                signingUser,
                { it.consume(pin) },
                deviceName
            )

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertEquals(SigningException.InvalidPin, (result as MIRACLError).value)
        }
    }

    @Test
    fun `sign should return MIRACLError on entering non numeric pin`() {
        runTest {
            // Arrange
            val pin = "a" + pin.substring(1)
            val message = randomByteArray()
            val signingUser = createSigningUser()

            val documentSigner =
                DocumentSigner(
                    cryptoMock,
                    authenticatorContractMock,
                    userStorageMock,
                    crossDeviceSessionApiMock
                )

            // Act
            val result = documentSigner.sign(
                message,
                signingUser,
                { it.consume(pin) },
                deviceName
            )

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertEquals(SigningException.InvalidPin, (result as MIRACLError).value)
        }
    }

    @Test
    fun `sign should return MIRACLError when authentication fails`() =
        runTest {
            // Arrange
            val message = randomByteArray()
            val signingUser = createSigningUser()

            val authenticationException = AuthenticationException.AuthenticationFail(Exception())
            coEvery {
                authenticatorContractMock.authenticate(
                    signingUser,
                    any(),
                    any(),
                    arrayOf(AuthenticatorScopes.SIGNING_AUTHENTICATION.value),
                    deviceName
                )
            } returns MIRACLError(authenticationException)

            val documentSigner =
                DocumentSigner(
                    cryptoMock,
                    authenticatorContractMock,
                    userStorageMock,
                    crossDeviceSessionApiMock
                )

            // Act
            val result = documentSigner.sign(
                message,
                signingUser,
                pinProviderMock,
                deviceName
            )

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertTrue((result as MIRACLError).value is SigningException.SigningFail)
            Assert.assertEquals(authenticationException.cause, result.value.cause)
        }

    @Test
    fun `sign should return DocumentSigningError when authentication fails because of unsuccessful authentication`() =
        runTest {
            // Arrange
            val message = randomByteArray()
            val signingUser = createSigningUser()

            val authenticationException = AuthenticationException.UnsuccessfulAuthentication
            coEvery {
                authenticatorContractMock.authenticate(
                    signingUser,
                    any(),
                    any(),
                    arrayOf(AuthenticatorScopes.SIGNING_AUTHENTICATION.value),
                    deviceName
                )
            } returns MIRACLError(authenticationException)

            val documentSigner =
                DocumentSigner(
                    cryptoMock,
                    authenticatorContractMock,
                    userStorageMock,
                    crossDeviceSessionApiMock
                )

            // Act
            val result = documentSigner.sign(
                message,
                signingUser,
                pinProviderMock,
                deviceName
            )

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertEquals(
                SigningException.UnsuccessfulAuthentication,
                (result as MIRACLError).value
            )
        }

    @Test
    fun `sign should return DocumentSigningError when authentication fails because of user revocation`() =
        runTest {
            // Arrange
            val message = randomByteArray()
            val signingUser = createSigningUser()

            val authenticationException = AuthenticationException.Revoked
            coEvery {
                authenticatorContractMock.authenticate(
                    signingUser,
                    any(),
                    any(),
                    arrayOf(AuthenticatorScopes.SIGNING_AUTHENTICATION.value),
                    deviceName
                )
            } returns MIRACLError(authenticationException)

            val documentSigner =
                DocumentSigner(
                    cryptoMock,
                    authenticatorContractMock,
                    userStorageMock,
                    crossDeviceSessionApiMock
                )

            // Act
            val result = documentSigner.sign(
                message,
                signingUser,
                pinProviderMock,
                deviceName
            )

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertEquals(
                SigningException.Revoked,
                (result as MIRACLError).value
            )
        }

    @Test
    fun `sign should return MIRACLError when crypto sign fails`() =
        runTest {
            // Arrange
            val message = randomByteArray()
            val signingUser = createSigningUser()

            coEvery {
                authenticatorContractMock.authenticate(
                    signingUser,
                    any(),
                    any(),
                    arrayOf(AuthenticatorScopes.SIGNING_AUTHENTICATION.value),
                    deviceName
                )
            } returns MIRACLSuccess(mockk())

            val cryptoException = CryptoException.SignError()
            coEvery {
                cryptoMock.sign(
                    message,
                    mpinId.plus(publicKey),
                    token,
                    any(),
                    any()
                )
            } returns MIRACLError(cryptoException)

            val documentSigner =
                DocumentSigner(
                    cryptoMock,
                    authenticatorContractMock,
                    userStorageMock,
                    crossDeviceSessionApiMock
                )

            // Act
            val result = documentSigner.sign(
                message,
                signingUser,
                pinProviderMock,
                deviceName
            )

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertTrue((result as MIRACLError).value is SigningException.SigningFail)
            Assert.assertEquals(cryptoException, result.value.cause)
        }

    @Test
    fun `sign should return MIRACLError when crypto sign returns empty U array`() =
        runTest {
            // Arrange
            val message = randomByteArray()
            val signingUser = createSigningUser()

            coEvery {
                authenticatorContractMock.authenticate(
                    signingUser,
                    any(),
                    any(),
                    arrayOf(AuthenticatorScopes.SIGNING_AUTHENTICATION.value),
                    deviceName
                )
            } returns MIRACLSuccess(mockk())

            val u = byteArrayOf()
            val v = randomByteArray()
            coEvery {
                cryptoMock.sign(
                    message,
                    mpinId.plus(publicKey),
                    token,
                    any(),
                    any()
                )
            } returns MIRACLSuccess(SigningResult(u, v))

            val documentSigner =
                DocumentSigner(
                    cryptoMock,
                    authenticatorContractMock,
                    userStorageMock,
                    crossDeviceSessionApiMock
                )

            // Act
            val result = documentSigner.sign(
                message,
                signingUser,
                pinProviderMock,
                deviceName
            )

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertTrue((result as MIRACLError).value is SigningException.SigningFail)
        }

    @Test
    fun `sign should return MIRACLError when crypto sign returns empty V array`() =
        runTest {
            // Arrange
            val message = randomByteArray()
            val signingUser = createSigningUser()

            coEvery {
                authenticatorContractMock.authenticate(
                    signingUser,
                    any(),
                    any(),
                    arrayOf(AuthenticatorScopes.SIGNING_AUTHENTICATION.value),
                    deviceName
                )
            } returns MIRACLSuccess(mockk())

            val u = randomByteArray()
            val v = byteArrayOf()
            coEvery {
                cryptoMock.sign(
                    message,
                    mpinId.plus(publicKey),
                    token,
                    any(),
                    any()
                )
            } returns MIRACLSuccess(SigningResult(u, v))

            val documentSigner =
                DocumentSigner(
                    cryptoMock,
                    authenticatorContractMock,
                    userStorageMock,
                    crossDeviceSessionApiMock
                )

            // Act
            val result = documentSigner.sign(
                message,
                signingUser,
                pinProviderMock,
                deviceName
            )

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertTrue((result as MIRACLError).value is SigningException.SigningFail)
        }

    @Test
    fun `sign with CrossDeviceSession should return MIRACLSuccess on success`() =
        runTest {
            // Arrange
            val signingUser = createSigningUser()
            val crossDeviceSession = createCrossDeviceSession()
            val message = crossDeviceSession.signingHash.hexStringToByteArray()

            coEvery {
                authenticatorContractMock.authenticate(
                    signingUser,
                    any(),
                    any(),
                    arrayOf(AuthenticatorScopes.SIGNING_AUTHENTICATION.value),
                    deviceName
                )
            } returns MIRACLSuccess(mockk())

            val u = randomByteArray()
            val v = randomByteArray()
            coEvery {
                cryptoMock.sign(
                    message,
                    mpinId.plus(publicKey),
                    token,
                    any(),
                    pin.toInt()
                )
            } returns MIRACLSuccess(SigningResult(u, v))

            coEvery {
                crossDeviceSessionApiMock.executeUpdateCrossDeviceSessionForSigningRequest(
                    any(),
                    any()
                )
            } returns MIRACLSuccess(Unit)

            val documentSigner =
                DocumentSigner(
                    cryptoMock,
                    authenticatorContractMock,
                    userStorageMock,
                    crossDeviceSessionApiMock
                )

            // Act
            val result = documentSigner.sign(
                crossDeviceSession = crossDeviceSession,
                user = signingUser,
                pinProvider = pinProviderMock,
                deviceName = deviceName,
            )

            // Assert
            Assert.assertTrue(result is MIRACLSuccess)

            val capturingSlot = CapturingSlot<Signature>()
            coVerify {
                crossDeviceSessionApiMock.executeUpdateCrossDeviceSessionForSigningRequest(
                    sessionId = crossDeviceSession.sessionId,
                    signature = capture(capturingSlot)
                )
            }

            val signature = capturingSlot.captured
            Assert.assertEquals(message.toHexString(), signature.hash)
            Assert.assertEquals(u.toHexString(), signature.U)
            Assert.assertEquals(v.toHexString(), signature.V)
            Assert.assertEquals(dtas, signature.dtas)
            Assert.assertEquals(mpinId.toHexString(), signature.mpinId)
            Assert.assertEquals(publicKey.toHexString(), signature.publicKey)
        }

    @Test
    fun `sign with CrossDeviceSession should return MIRACLError when updateCrossDeviceSessionForSigningRequest fails`() =
        runTest {
            // Arrange
            val signingUser = createSigningUser()
            val crossDeviceSession = createCrossDeviceSession()

            coEvery {
                authenticatorContractMock.authenticate(
                    signingUser,
                    any(),
                    any(),
                    arrayOf(AuthenticatorScopes.SIGNING_AUTHENTICATION.value),
                    deviceName
                )
            } returns MIRACLSuccess(mockk())

            val u = randomByteArray()
            val v = randomByteArray()
            coEvery {
                cryptoMock.sign(
                    crossDeviceSession.signingHash.hexStringToByteArray(),
                    mpinId.plus(publicKey),
                    token,
                    any(),
                    any()
                )
            } returns MIRACLSuccess(SigningResult(u, v))

            val exception = Exception()
            coEvery {
                crossDeviceSessionApiMock.executeUpdateCrossDeviceSessionForSigningRequest(
                    sessionId = crossDeviceSession.sessionId,
                    signature = any()
                )
            } returns MIRACLError(exception)

            val documentSigner = DocumentSigner(
                cryptoMock,
                authenticatorContractMock,
                userStorageMock,
                crossDeviceSessionApiMock
            )

            // Act
            val result = documentSigner.sign(
                crossDeviceSession = crossDeviceSession,
                user = signingUser,
                pinProvider = pinProviderMock,
                deviceName = deviceName
            )

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertTrue((result as MIRACLError).value is SigningException.SigningFail)
            Assert.assertEquals(exception, result.value.cause)
        }

    private fun createSigningUser() =
        User(
            userId = userId,
            projectId = projectId,
            revoked = false,
            pinLength = pinLength,
            mpinId = mpinId,
            token = token,
            dtas = dtas,
            publicKey = publicKey
        )

    private fun createCrossDeviceSession(
        sessionId: String = randomUuidString(),
        description: String = randomUuidString(),
        userId: String = this.userId,
        projectId: String = this.projectId,
        hash: String = randomHexString()
    ) = CrossDeviceSession(
        sessionId = sessionId,
        sessionDescription = description,
        userId = userId,
        projectId = projectId,
        signingHash = hash
    )
}