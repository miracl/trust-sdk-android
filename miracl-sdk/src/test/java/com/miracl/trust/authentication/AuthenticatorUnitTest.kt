package com.miracl.trust.authentication

import android.net.Uri
import com.miracl.trust.MIRACLError
import com.miracl.trust.MIRACLSuccess
import com.miracl.trust.copy
import com.miracl.trust.crypto.*
import com.miracl.trust.delegate.PinProvider
import com.miracl.trust.model.User
import com.miracl.trust.randomByteArray
import com.miracl.trust.randomHexString
import com.miracl.trust.randomNumericPin
import com.miracl.trust.randomPinLength
import com.miracl.trust.randomUuidString
import com.miracl.trust.registration.RegistrationException
import com.miracl.trust.registration.Registrator
import com.miracl.trust.session.SessionApi
import com.miracl.trust.storage.UserDto
import com.miracl.trust.storage.UserStorage
import com.miracl.trust.util.toUserDto
import com.miracl.trust.util.toHexString
import io.mockk.*
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.runTest
import org.junit.Assert
import org.junit.Before
import org.junit.Test

@ExperimentalCoroutinesApi
class AuthenticatorUnitTest {
    private val userId = randomUuidString()
    private val pinLength = randomPinLength()
    private val pin = randomNumericPin(pinLength)
    private val deviceName = randomUuidString()
    private val accessId = randomUuidString()

    private val authenticationApiMock = mockk<AuthenticationApiManager>()
    private val sessionApiMock = mockk<SessionApi>()
    private val cryptoMock = mockk<Crypto>()
    private val pinProviderMock = PinProvider { it.consume(pin) }
    private val registratorMock = mockk<Registrator>()
    private val userStorageMock = mockk<UserStorage>()

    private lateinit var authenticator: Authenticator

    @Before
    fun resetMocks() {
        clearAllMocks()
        setUpCryptoMock()
        setUpAuthenticationApiMock()
        setUpSessionApiMock()

        authenticator = Authenticator(
            authenticationApiMock,
            sessionApiMock,
            cryptoMock,
            registratorMock,
            userStorageMock
        )
    }

    @Test
    fun `authenticate should return MIRACLSuccess when user is successfully authenticated`() =
        runTest {
            // Arrange
            val user = createUser()
            val scope = arrayOf(AuthenticatorScopes.OIDC.value)

            // Act
            val result =
                authenticator.authenticate(user, accessId, pinProviderMock, scope, deviceName)

            // Assert
            coVerify {
                cryptoMock.getClientPass1Proof(
                    mpinId = user.mpinId + user.publicKey!!,
                    token = user.token,
                    pin = any()
                )
            }
            Assert.assertTrue(result is MIRACLSuccess)
        }

    @Test
    fun `authenticate should return MIRACLError when user is revoked`() {
        runTest {
            // Arrange
            val user = createUser().copy(revoked = true)
            val scope = arrayOf(AuthenticatorScopes.OIDC.value)

            // Act
            val result =
                authenticator.authenticate(user, accessId, pinProviderMock, scope, deviceName)

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertTrue((result as MIRACLError).value is AuthenticationException.Revoked)
        }
    }

    @Test
    fun `authenticate should return MIRACLError when user has an empty mpinId`() {
        runTest {
            // Arrange
            val emptyMpinId = byteArrayOf()
            val user = createUser().copy(mpinId = emptyMpinId)
            val scope = arrayOf(AuthenticatorScopes.OIDC.value)

            // Act
            val result =
                authenticator.authenticate(user, accessId, pinProviderMock, scope, deviceName)

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertTrue((result as MIRACLError).value is AuthenticationException.InvalidUserData)
        }
    }

    @Test
    fun `authenticate should return MIRACLError when user has an empty dtas`() {
        runTest {
            // Arrange
            val emptyDtas = ""
            val user = createUser().copy(dtas = emptyDtas)
            val scope = arrayOf(AuthenticatorScopes.OIDC.value)

            // Act
            val result =
                authenticator.authenticate(user, accessId, pinProviderMock, scope, deviceName)

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertTrue((result as MIRACLError).value is AuthenticationException.InvalidUserData)
        }
    }

    @Test
    fun `authenticate should return MIRACLError when user has an empty token`() {
        runTest {
            // Arrange
            val emptyToken = byteArrayOf()
            val user = createUser().copy(token = emptyToken)
            val scope = arrayOf(AuthenticatorScopes.OIDC.value)

            // Act
            val result =
                authenticator.authenticate(user, accessId, pinProviderMock, scope, deviceName)

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertTrue((result as MIRACLError).value is AuthenticationException.InvalidUserData)
        }
    }

    @Test
    fun `authenticate should return MIRACLError when the passed pin has shorter length`() {
        runTest {
            // Arrange
            val user = createUser()
            val scope = arrayOf(AuthenticatorScopes.OIDC.value)

            val shorterPinProvider = PinProvider { it.consume(pin.substring(0, pinLength - 1)) }

            // Act
            val result =
                authenticator.authenticate(user, accessId, shorterPinProvider, scope, deviceName)

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertTrue((result as MIRACLError).value is AuthenticationException.InvalidPin)
        }
    }

    @Test
    fun `authenticate should return MIRACLError when the passed pin has longer length`() {
        runTest {
            // Arrange
            val user = createUser()
            val scope = arrayOf(AuthenticatorScopes.OIDC.value)

            val longerPinProvider = PinProvider { it.consume(pin + "1") }

            // Act
            val result =
                authenticator.authenticate(user, accessId, longerPinProvider, scope, deviceName)

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertTrue((result as MIRACLError).value is AuthenticationException.InvalidPin)
        }
    }

    @Test
    fun `authenticate should return MIRACLError when entering the pin was canceled`() {
        runTest {
            // Arrange
            val user = createUser()
            val scope = arrayOf(AuthenticatorScopes.OIDC.value)

            val nullPinProvider = PinProvider { it.consume(null) }
            // Act
            val result =
                authenticator.authenticate(user, accessId, nullPinProvider, scope, deviceName)

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertTrue((result as MIRACLError).value is AuthenticationException.PinCancelled)
        }
    }

    @Test
    fun `authenticate should return MIRACLError when input pin cannot be parsed to integer`() {
        runTest {
            // Arrange
            val user = createUser()
            val scope = arrayOf(AuthenticatorScopes.OIDC.value)

            val invalidPinProvider = PinProvider { it.consume("a" + pin.substring(1)) }
            // Act
            val result =
                authenticator.authenticate(user, accessId, invalidPinProvider, scope, deviceName)

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertTrue((result as MIRACLError).value is AuthenticationException.InvalidPin)
        }
    }

    @Test
    fun `authenticate should return MIRACLError when pass1proof result is MIRACLError`() {
        runTest {
            // Arrange
            val user = createUser()
            val scope = arrayOf(AuthenticatorScopes.OIDC.value)
            val cryptoException = CryptoException.GetClientPass1ProofError()

            coEvery {
                cryptoMock.getClientPass1Proof(
                    mpinId = any(),
                    token = any(),
                    pin = any()
                )
            } returns MIRACLError(cryptoException)

            // Act
            val result =
                authenticator.authenticate(user, accessId, pinProviderMock, scope, deviceName)

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertTrue((result as MIRACLError).value is AuthenticationException.AuthenticationFail)
            Assert.assertEquals(cryptoException, result.value.cause)
        }
    }

    @Test
    fun `authenticate should return MIRACLError when authentication api pass1Result is MIRACLError`() {
        runTest {
            // Arrange
            val user = createUser()
            val scope = arrayOf(AuthenticatorScopes.OIDC.value)
            val authenticationException = AuthenticationException.AuthenticationFail()

            coEvery { authenticationApiMock.executePass1Request(any(), any()) } returns MIRACLError(
                authenticationException
            )

            // Act
            val result =
                authenticator.authenticate(user, accessId, pinProviderMock, scope, deviceName)

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertEquals(authenticationException, (result as MIRACLError).value)
        }
    }

    @Test
    fun `authenticate should revoke user when executePass1Request returns AuthenticationException Revoked`() {
        runTest {
            // Arrange
            val user = createUser()
            val scope = arrayOf(AuthenticatorScopes.OIDC.value)

            coEvery {
                authenticationApiMock.executePass1Request(
                    any(),
                    any()
                )
            } returns MIRACLError(AuthenticationException.Revoked)

            // Act
            val result =
                authenticator.authenticate(user, accessId, pinProviderMock, scope, deviceName)

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertEquals(
                AuthenticationException.Revoked,
                (result as MIRACLError).value
            )

            val capturingSlot = CapturingSlot<UserDto>()
            verify { userStorageMock.update(capture(capturingSlot)) }
            val updatedUser = capturingSlot.captured

            Assert.assertEquals(user.userId, updatedUser.userId)
            Assert.assertEquals(user.projectId, updatedUser.projectId)
            Assert.assertTrue(updatedUser.revoked)
            Assert.assertEquals(user.pinLength, updatedUser.pinLength)
            Assert.assertEquals(user.token, updatedUser.token)
            Assert.assertEquals(user.dtas, updatedUser.dtas)
            Assert.assertEquals(user.publicKey, updatedUser.publicKey)
        }
    }

    @Test
    fun `authenticate should return MIRACLError when authentication api executePass1Request throws an exception`() {
        runTest {
            // Arrange
            val user = createUser()
            val scope = arrayOf(AuthenticatorScopes.OIDC.value)

            coEvery { authenticationApiMock.executePass1Request(any(), any()) } throws Exception()

            // Act
            val result =
                authenticator.authenticate(user, accessId, pinProviderMock, scope, deviceName)

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertTrue((result as MIRACLError).value is AuthenticationException.AuthenticationFail)
            Assert.assertNotNull(result.value.cause)
        }
    }

    @Test
    fun `authenticate should return MIRACLError when authentication api executePass2Request throws an exception`() {
        runTest {
            // Arrange
            val user = createUser()
            val scope = arrayOf(AuthenticatorScopes.OIDC.value)

            coEvery { authenticationApiMock.executePass2Request(any(), any()) } throws Exception()

            // Act
            val result =
                authenticator.authenticate(user, accessId, pinProviderMock, scope, deviceName)

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertTrue((result as MIRACLError).value is AuthenticationException.AuthenticationFail)
            Assert.assertNotNull(result.value.cause)
        }
    }

    @Test
    fun `authenticate should return MIRACLError when authentication api executePass2Request returns an error`() {
        runTest {
            // Arrange
            val user = createUser()
            val scope = arrayOf(AuthenticatorScopes.OIDC.value)
            val authenticationException = AuthenticationException.AuthenticationFail()

            coEvery { authenticationApiMock.executePass2Request(any(), any()) } returns MIRACLError(
                authenticationException
            )

            // Act
            val result =
                authenticator.authenticate(user, accessId, pinProviderMock, scope, deviceName)

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertEquals(authenticationException, (result as MIRACLError).value)
        }
    }

    @Test
    fun `authenticate should return MIRACLError when client pass2Proof throws an exception`() {
        runTest {
            // Arrange
            val user = createUser()
            val scope = arrayOf(AuthenticatorScopes.OIDC.value)
            val exception = Exception()

            every {
                cryptoMock.getClientPass2Proof(x = any(), y = any(), sec = any())
            } throws exception

            // Act
            val result =
                authenticator.authenticate(user, accessId, pinProviderMock, scope, deviceName)

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertTrue((result as MIRACLError).value is AuthenticationException.AuthenticationFail)
            Assert.assertEquals(exception, result.value.cause)
        }
    }

    @Test
    fun `authenticate should return MIRACLError when client pass2Proof returns error`() {
        runTest {
            // Arrange
            val user = createUser()
            val scope = arrayOf(AuthenticatorScopes.OIDC.value)
            val cryptoException = CryptoException.GetClientPass2ProofError()

            every {
                cryptoMock.getClientPass2Proof(x = any(), y = any(), sec = any())
            } returns MIRACLError(cryptoException)

            // Act
            val result =
                authenticator.authenticate(user, accessId, pinProviderMock, scope, deviceName)

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertTrue((result as MIRACLError).value is AuthenticationException.AuthenticationFail)
            Assert.assertEquals(cryptoException, result.value.cause)
        }
    }

    @Test
    fun `authenticate should return MIRACLError when executeAuthenticationRequest returns error`() {
        runTest {
            // Arrange
            val user = createUser()
            val scope = arrayOf(AuthenticatorScopes.OIDC.value)
            val authenticationException = AuthenticationException.AuthenticationFail()

            coEvery {
                authenticationApiMock.executeAuthenticateRequest(
                    any(),
                    any()
                )
            } returns MIRACLError(
                authenticationException
            )

            // Act
            val result =
                authenticator.authenticate(user, accessId, pinProviderMock, scope, deviceName)

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertEquals(authenticationException, (result as MIRACLError).value)
        }
    }

    @Test
    fun `authenticate should revoke user when executeAuthenticationRequest returns AuthenticationException Revoked`() {
        runTest {
            // Arrange
            val user = createUser()
            val scope = arrayOf(AuthenticatorScopes.OIDC.value)

            coEvery {
                authenticationApiMock.executeAuthenticateRequest(
                    any(),
                    any()
                )
            } returns MIRACLError(AuthenticationException.Revoked)

            // Act
            val result =
                authenticator.authenticate(user, accessId, pinProviderMock, scope, deviceName)

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertEquals(
                AuthenticationException.Revoked,
                (result as MIRACLError).value
            )

            val capturingSlot = CapturingSlot<UserDto>()
            verify { userStorageMock.update(capture(capturingSlot)) }
            val updatedUser = capturingSlot.captured

            Assert.assertEquals(user.userId, updatedUser.userId)
            Assert.assertEquals(user.projectId, updatedUser.projectId)
            Assert.assertTrue(updatedUser.revoked)
            Assert.assertEquals(user.pinLength, updatedUser.pinLength)
            Assert.assertEquals(user.mpinId, updatedUser.mpinId)
            Assert.assertEquals(user.token, updatedUser.token)
            Assert.assertEquals(user.dtas, updatedUser.dtas)
            Assert.assertEquals(user.publicKey, updatedUser.publicKey)
        }
    }

    @Test
    fun `authenticate should return MIRACLError when could not revoke user`() {
        runTest {
            // Arrange
            val user = createUser()
            val scope = arrayOf(AuthenticatorScopes.OIDC.value)
            val apiException = AuthenticationException.Revoked

            coEvery {
                authenticationApiMock.executeAuthenticateRequest(
                    any(),
                    any()
                )
            } returns MIRACLError(apiException)

            every { userStorageMock.update(ofType(UserDto::class)) } throws Exception()

            // Act
            val result =
                authenticator.authenticate(user, accessId, pinProviderMock, scope, deviceName)

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertEquals(apiException, (result as MIRACLError).value)
        }
    }

    @Test
    fun `authenticate should return MIRACLError when executeAuthenticationRequest throws exception`() {
        runTest {
            // Arrange
            val user = createUser()
            val scope = arrayOf(AuthenticatorScopes.OIDC.value)
            val exception = Exception()

            coEvery {
                authenticationApiMock.executeAuthenticateRequest(
                    any(),
                    any()
                )
            } throws exception

            // Act
            val result =
                authenticator.authenticate(user, accessId, pinProviderMock, scope, deviceName)

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertTrue((result as MIRACLError).value is AuthenticationException.AuthenticationFail)
            Assert.assertEquals(exception, result.value.cause)
        }
    }

    @Test
    fun `authenticate combines mpin and public key when public key is not null`() =
        runTest {
            // Arrange
            val user = createUser().copy(publicKey = randomByteArray())
            val scope = arrayOf(AuthenticatorScopes.SIGNING_AUTHENTICATION.value)
            val pass1Proof = Pass1Proof(
                X = randomByteArray(),
                SEC = randomByteArray(),
                U = randomByteArray()
            )

            val capturingSlot = CapturingSlot<ByteArray>()
            coEvery {
                cryptoMock.getClientPass1Proof(
                    mpinId = capture(capturingSlot),
                    token = user.token,
                    pin = any()
                )
            } returns MIRACLSuccess(pass1Proof)

            // Act
            val result = authenticator.authenticate(
                user,
                accessId,
                pinProviderMock,
                scope,
                deviceName
            )

            // Assert
            Assert.assertTrue(result is MIRACLSuccess)
            Assert.assertArrayEquals(
                user.mpinId.plus(user.publicKey!!),
                capturingSlot.captured
            )
        }

    @Test
    fun `authenticate doesn't combine mpin and public key when public key is null`() =
        runTest {
            // Arrange
            val user = createUser().copy(publicKey = null)
            val scope = arrayOf(AuthenticatorScopes.SIGNING_AUTHENTICATION.value)
            val pass1Proof = Pass1Proof(
                X = randomByteArray(),
                SEC = randomByteArray(),
                U = randomByteArray()
            )

            val capturingSlot = CapturingSlot<ByteArray>()
            coEvery {
                cryptoMock.getClientPass1Proof(
                    mpinId = capture(capturingSlot),
                    token = user.token,
                    pin = any()
                )
            } returns MIRACLSuccess(pass1Proof)

            // Act
            val result = authenticator.authenticate(
                user,
                accessId,
                pinProviderMock,
                scope,
                deviceName
            )

            // Assert
            Assert.assertTrue(result is MIRACLSuccess)
            Assert.assertEquals(user.mpinId, capturingSlot.captured)
        }

    @Test
    fun `authenticate adds public key hex when public key is not null`() =
        runTest {
            // Arrange
            val user = createUser().copy(publicKey = randomByteArray())
            val scope = arrayOf(AuthenticatorScopes.SIGNING_AUTHENTICATION.value)

            val capturingSlot = CapturingSlot<Pass1RequestBody>()
            coEvery {
                authenticationApiMock.executePass1Request(
                    capture(capturingSlot),
                    any()
                )
            } returns MIRACLSuccess(
                Pass1Response(Y = randomHexString())
            )

            // Act
            val result = authenticator.authenticate(
                user,
                accessId,
                pinProviderMock,
                scope,
                deviceName
            )

            // Assert
            Assert.assertTrue(result is MIRACLSuccess)
            Assert.assertEquals(
                user.publicKey!!.toHexString(),
                capturingSlot.captured.publicKey
            )
        }

    @Test
    fun `authenticate should renew signing secret if dvsRegister is not null in authentication response`() =
        runTest {
            // Arrange
            val user = createUser()
            val scope = arrayOf(AuthenticatorScopes.SIGNING_AUTHENTICATION.value)
            val token = randomUuidString()
            val authenticationResponse =
                AuthenticateResponse(
                    status = 200,
                    message = "OK",
                    renewSecretResponse = RenewSecretResponse(token, randomUuidString()),
                    jwt = null
                )

            coEvery {
                authenticationApiMock.executeAuthenticateRequest(
                    any(),
                    any()
                )
            } returns MIRACLSuccess(
                authenticationResponse
            ) andThen MIRACLSuccess(AuthenticateResponse(200, "OK", null, null))

            coEvery {
                registratorMock.register(any(), any(), any(), any(), any(), any())
            } returns MIRACLSuccess(createUser())

            // Act
            val result =
                authenticator.authenticate(
                    user,
                    null,
                    pinProviderMock,
                    scope,
                    deviceName
                )

            // Assert
            coVerify {
                registratorMock.register(
                    user.userId,
                    user.projectId,
                    token,
                    any(),
                    deviceName,
                    null
                )
            }
            Assert.assertTrue(result is MIRACLSuccess)
        }

    @Test
    fun `authenticate should authenticate the user after secret renew`() =
        runTest {
            // Arrange
            val user = createUser()
            val scope = arrayOf(AuthenticatorScopes.SIGNING_AUTHENTICATION.value)
            val authenticationResponse =
                AuthenticateResponse(
                    status = 200,
                    message = "OK",
                    renewSecretResponse = RenewSecretResponse(
                        token = randomUuidString(),
                        curve = randomUuidString()
                    ),
                    jwt = null
                )

            coEvery {
                authenticationApiMock.executeAuthenticateRequest(
                    any(),
                    any()
                )
            } returns MIRACLSuccess(
                authenticationResponse
            ) andThen MIRACLSuccess(AuthenticateResponse(200, "OK", null, null))

            val renewedUser = createUser().copy(
                mpinId = randomByteArray(),
                token = randomByteArray(),
                publicKey = randomByteArray()
            )
            coEvery {
                registratorMock.register(any(), any(), any(), any(), any(), any())
            } returns MIRACLSuccess(renewedUser)

            // Act
            val result =
                authenticator.authenticate(
                    user,
                    null,
                    pinProviderMock,
                    scope,
                    deviceName
                )

            // Assert
            coVerify {
                cryptoMock.getClientPass1Proof(
                    renewedUser.mpinId + renewedUser.publicKey!!,
                    renewedUser.token,
                    any()
                )
            }
            Assert.assertTrue(result is MIRACLSuccess)
        }

    @Test
    fun `authenticate should return MIRACLSuccess when renewing signing secret result is MIRACLError`() =
        runTest {
            // Arrange
            val user = createUser()
            val scope = arrayOf(AuthenticatorScopes.SIGNING_AUTHENTICATION.value)
            val authenticationResponse =
                AuthenticateResponse(
                    status = 200,
                    message = "OK",
                    renewSecretResponse = RenewSecretResponse(
                        token = randomUuidString(),
                        curve = randomUuidString()
                    ),
                    jwt = null
                )

            coEvery {
                authenticationApiMock.executeAuthenticateRequest(
                    any(),
                    any()
                )
            } returns MIRACLSuccess(
                authenticationResponse
            )

            coEvery {
                registratorMock.register(any(), any(), any(), any(), any(), any())
            } returns MIRACLError(RegistrationException.RegistrationFail())

            // Act
            val result = authenticator.authenticate(
                user,
                null,
                pinProviderMock,
                scope,
                deviceName
            )

            // Assert
            Assert.assertTrue(result is MIRACLSuccess)
        }

    @Test
    fun `authenticate should update session status when accessId is not null`() =
        runTest {
            // Arrange
            val user = createUser()
            val scope = arrayOf(AuthenticatorScopes.OIDC.value)

            // Act
            val result =
                authenticator.authenticate(user, accessId, pinProviderMock, scope, deviceName)

            // Assert
            coVerify {
                sessionApiMock.executeUpdateSessionRequest(
                    accessId = accessId,
                    userId = user.userId
                )
            }
            Assert.assertTrue(result is MIRACLSuccess)
        }

    @Test
    fun `authenticate should not update session status when accessId is null`() =
        runTest {
            // Arrange
            val user = createUser()
            val scope = arrayOf(AuthenticatorScopes.OIDC.value)

            // Act
            val result =
                authenticator.authenticate(user, null, pinProviderMock, scope, deviceName)

            // Assert
            coVerify(exactly = 0) {
                sessionApiMock.executeUpdateSessionRequest(
                    accessId = accessId,
                    userId = user.userId
                )
            }
            Assert.assertTrue(result is MIRACLSuccess)
        }

    @Test
    fun `authenticate should return MIRACLSuccess when update session result is MIRACLError`() =
        runTest {
            // Arrange
            val user = createUser()
            val scope = arrayOf(AuthenticatorScopes.OIDC.value)

            coEvery {
                sessionApiMock.executeUpdateSessionRequest(
                    any(),
                    any()
                )
            } returns MIRACLError(Exception())

            // Act
            val result =
                authenticator.authenticate(user, accessId, pinProviderMock, scope, deviceName)

            // Assert
            Assert.assertTrue(result is MIRACLSuccess)
        }

    @Test
    fun `authenticateWithAppLink should return MIRACLSuccess when user is successfully authenticated`() =
        runTest {
            // Arrange
            val authenticatorSpy = spyk(authenticator)
            val user = createUser()
            val scope = arrayOf(AuthenticatorScopes.OIDC.value)
            val appLinkMock = mockkClass(Uri::class)

            every { appLinkMock.fragment } returns accessId

            // Act
            val result =
                authenticatorSpy.authenticateWithAppLink(
                    user,
                    appLinkMock,
                    pinProviderMock,
                    scope,
                    deviceName
                )

            // Assert
            coVerify {
                authenticatorSpy.authenticate(
                    user,
                    accessId,
                    pinProviderMock,
                    scope,
                    deviceName
                )
            }
            Assert.assertTrue(result is MIRACLSuccess)
        }

    @Test
    fun `authenticateWithAppLink should return MIRACLError when authentication fails`() {
        runTest {
            // Arrange
            val user = createUser()
            val scope = arrayOf(AuthenticatorScopes.OIDC.value)
            val appLinkMock = mockkClass(Uri::class)
            val authenticationException = AuthenticationException.AuthenticationFail(null)

            every { appLinkMock.fragment } returns accessId

            coEvery {
                authenticationApiMock.executeAuthenticateRequest(
                    any(),
                    any()
                )
            } returns MIRACLError(authenticationException)

            // Act
            val result =
                authenticator.authenticateWithAppLink(
                    user,
                    appLinkMock,
                    pinProviderMock,
                    scope,
                    deviceName
                )

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertEquals(authenticationException, (result as MIRACLError).value)
        }
    }

    @Test
    fun `authenticateWithAppLink should return MIRACLError when appLink is invalid`() {
        runTest {
            // Arrange
            val user = createUser()
            val scope = arrayOf(AuthenticatorScopes.OIDC.value)
            val appLinkMock = mockkClass(Uri::class)

            every { appLinkMock.fragment } returns null

            // Act
            val result =
                authenticator.authenticateWithAppLink(
                    user,
                    appLinkMock,
                    pinProviderMock,
                    scope,
                    deviceName
                )

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertTrue((result as MIRACLError).value is AuthenticationException.InvalidAppLink)
        }
    }

    @Test
    fun `authenticateWithQRCode should return MIRACLSuccess when user is successfully authenticated`() =
        runTest {
            // Arrange
            val authenticatorSpy = spyk(authenticator)
            val user = createUser()
            val scope = arrayOf(AuthenticatorScopes.OIDC.value)
            val qrCode = "https://mcl.mpin.io/mobile-login/#$accessId"
            val uriMock = mockkClass(Uri::class)

            mockkStatic(Uri::class)
            every { Uri.parse(qrCode) } returns uriMock
            every { uriMock.fragment } returns accessId

            // Act
            val result =
                authenticatorSpy.authenticateWithQRCode(
                    user,
                    qrCode,
                    pinProviderMock,
                    scope,
                    deviceName
                )

            // Assert
            coVerify {
                authenticatorSpy.authenticate(
                    user,
                    accessId,
                    pinProviderMock,
                    scope,
                    deviceName
                )
            }
            Assert.assertTrue(result is MIRACLSuccess)
        }

    @Test
    fun `authenticateWithQRCode should return MIRACLError when authentication fails`() {
        runTest {
            // Arrange
            val user = createUser()
            val scope = arrayOf(AuthenticatorScopes.OIDC.value)
            val qrCode = "https://mcl.mpin.io/mobile-login/#$accessId"
            val uriMock = mockkClass(Uri::class)
            val authenticationException = AuthenticationException.AuthenticationFail(null)

            mockkStatic(Uri::class)
            every { Uri.parse(qrCode) } returns uriMock
            every { uriMock.fragment } returns accessId

            coEvery {
                authenticationApiMock.executeAuthenticateRequest(
                    any(),
                    any()
                )
            } returns MIRACLError(authenticationException)

            // Act
            val result =
                authenticator.authenticateWithQRCode(
                    user,
                    qrCode,
                    pinProviderMock,
                    scope,
                    deviceName
                )

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertEquals(authenticationException, (result as MIRACLError).value)
        }
    }

    @Test
    fun `authenticateWithQRCode should return MIRACLError when qrCode is invalid`() {
        runTest {
            // Arrange
            val user = createUser()
            val scope = arrayOf(AuthenticatorScopes.OIDC.value)
            val qrCode = "https://mcl.mpin.io/mobile-login"
            val uriMock = mockkClass(Uri::class)

            mockkStatic(Uri::class)
            every { Uri.parse(qrCode) } returns uriMock
            every { uriMock.fragment } returns null

            // Act
            val result =
                authenticator.authenticateWithQRCode(
                    user,
                    qrCode,
                    pinProviderMock,
                    scope,
                    deviceName
                )

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertTrue((result as MIRACLError).value is AuthenticationException.InvalidQRCode)
        }
    }

    @Test
    fun `authenticateWithNotificationPayload should return MIRACLSuccess when user is successfully authenticated`() =
        runTest {
            // Arrange
            val authenticatorSpy = spyk(authenticator)
            val user = createUser().toUserDto()
            val scope = arrayOf(AuthenticatorScopes.OIDC.value)
            val projectId = randomUuidString()
            val qrUrl = "https://mcl.mpin.io/mobile-login/#$accessId"
            val payload = mapOf(
                Authenticator.PUSH_NOTIFICATION_PROJECT_ID to projectId,
                Authenticator.PUSH_NOTIFICATION_USER_ID to userId,
                Authenticator.PUSH_NOTIFICATION_QR_URL to qrUrl
            )
            val uriMock = mockkClass(Uri::class)

            mockkStatic(Uri::class)
            every { Uri.parse(qrUrl) } returns uriMock
            every { uriMock.fragment } returns accessId
            every { userStorageMock.getUser(userId, projectId) } returns user

            // Act
            val result =
                authenticatorSpy.authenticateWithNotificationPayload(
                    payload,
                    pinProviderMock,
                    scope,
                    deviceName
                )

            // Assert
            coVerify {
                authenticatorSpy.authenticate(
                    any(),
                    accessId,
                    pinProviderMock,
                    scope,
                    deviceName
                )
            }
            Assert.assertTrue(result is MIRACLSuccess)
        }

    @Test
    fun `authenticateWithNotificationPayload should return MIRACLError when authentication fails`() {
        runTest {
            // Arrange
            val user = createUser().toUserDto()
            val scope = arrayOf(AuthenticatorScopes.OIDC.value)
            val projectId = randomUuidString()
            val qrUrl = "https://mcl.mpin.io/mobile-login/#$accessId"
            val payload = mapOf(
                Authenticator.PUSH_NOTIFICATION_PROJECT_ID to projectId,
                Authenticator.PUSH_NOTIFICATION_USER_ID to userId,
                Authenticator.PUSH_NOTIFICATION_QR_URL to qrUrl
            )

            mockkStatic(Uri::class)
            val uriMock = mockkClass(Uri::class)
            every { Uri.parse(qrUrl) } returns uriMock
            every { uriMock.fragment } returns accessId
            every { userStorageMock.getUser(userId, projectId) } returns user

            val authenticationException = AuthenticationException.AuthenticationFail(null)
            coEvery {
                authenticationApiMock.executeAuthenticateRequest(
                    any(),
                    any()
                )
            } returns MIRACLError(authenticationException)

            // Act
            val result =
                authenticator.authenticateWithNotificationPayload(
                    payload,
                    pinProviderMock,
                    scope,
                    deviceName
                )

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertEquals(authenticationException, (result as MIRACLError).value)
        }
    }

    @Test
    fun `authenticateWithNotificationPayload should return MIRACLError when payload doesn't contain projectID`() {
        runTest {
            // Arrange
            val scope = arrayOf(AuthenticatorScopes.OIDC.value)
            val qrUrl = "https://mcl.mpin.io/mobile-login/#$accessId"
            val payload = mapOf(
                Authenticator.PUSH_NOTIFICATION_USER_ID to userId,
                Authenticator.PUSH_NOTIFICATION_QR_URL to qrUrl
            )

            // Act
            val result =
                authenticator.authenticateWithNotificationPayload(
                    payload,
                    pinProviderMock,
                    scope,
                    deviceName
                )

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertTrue((result as MIRACLError).value is AuthenticationException.InvalidPushNotificationPayload)
        }
    }

    @Test
    fun `authenticateWithNotificationPayload should return MIRACLError when payload doesn't contain userID`() {
        runTest {
            // Arrange
            val scope = arrayOf(AuthenticatorScopes.OIDC.value)
            val projectId = randomUuidString()
            val qrUrl = "https://mcl.mpin.io/mobile-login/#$accessId"
            val payload = mapOf(
                Authenticator.PUSH_NOTIFICATION_PROJECT_ID to projectId,
                Authenticator.PUSH_NOTIFICATION_QR_URL to qrUrl
            )

            // Act
            val result =
                authenticator.authenticateWithNotificationPayload(
                    payload,
                    pinProviderMock,
                    scope,
                    deviceName
                )

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertTrue((result as MIRACLError).value is AuthenticationException.InvalidPushNotificationPayload)
        }
    }

    @Test
    fun `authenticateWithNotificationPayload should return MIRACLError when payload doesn't contain qrURL`() {
        runTest {
            // Arrange
            val scope = arrayOf(AuthenticatorScopes.OIDC.value)
            val projectId = randomUuidString()
            val payload = mapOf(
                Authenticator.PUSH_NOTIFICATION_PROJECT_ID to projectId,
                Authenticator.PUSH_NOTIFICATION_USER_ID to userId
            )

            // Act
            val result =
                authenticator.authenticateWithNotificationPayload(
                    payload,
                    pinProviderMock,
                    scope,
                    deviceName
                )

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertTrue((result as MIRACLError).value is AuthenticationException.InvalidPushNotificationPayload)
        }
    }

    @Test
    fun `authenticateWithNotificationPayload should return MIRACLError when payload contains invalid qrURL`() {
        runTest {
            // Arrange
            val user = createUser().toUserDto()
            val scope = arrayOf(AuthenticatorScopes.OIDC.value)
            val projectId = randomUuidString()
            val qrUrl = "https://mcl.mpin.io/mobile-login"
            val payload = mapOf(
                Authenticator.PUSH_NOTIFICATION_PROJECT_ID to projectId,
                Authenticator.PUSH_NOTIFICATION_USER_ID to userId,
                Authenticator.PUSH_NOTIFICATION_QR_URL to qrUrl
            )

            mockkStatic(Uri::class)
            val uriMock = mockkClass(Uri::class)
            every { Uri.parse(qrUrl) } returns uriMock
            every { uriMock.fragment } returns null
            every { userStorageMock.getUser(userId, projectId) } returns user

            // Act
            val result =
                authenticator.authenticateWithNotificationPayload(
                    payload,
                    pinProviderMock,
                    scope,
                    deviceName
                )

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertTrue((result as MIRACLError).value is AuthenticationException.InvalidPushNotificationPayload)
        }
    }

    @Test
    fun `authenticateWithNotificationPayload should return MIRACLError when there isn't a user with the same id as payload userID`() {
        runTest {
            // Arrange
            val scope = arrayOf(AuthenticatorScopes.OIDC.value)
            val projectId = randomUuidString()
            val qrUrl = "https://mcl.mpin.io/mobile-login/#$accessId"
            val payload = mapOf(
                Authenticator.PUSH_NOTIFICATION_PROJECT_ID to projectId,
                Authenticator.PUSH_NOTIFICATION_USER_ID to userId,
                Authenticator.PUSH_NOTIFICATION_QR_URL to qrUrl
            )

            mockkStatic(Uri::class)
            val uriMock = mockkClass(Uri::class)
            every { Uri.parse(qrUrl) } returns uriMock
            every { uriMock.fragment } returns accessId
            every { userStorageMock.getUser(userId, projectId) } returns null

            // Act
            val result =
                authenticator.authenticateWithNotificationPayload(
                    payload,
                    pinProviderMock,
                    scope,
                    deviceName
                )

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertTrue((result as MIRACLError).value is AuthenticationException.UserNotFound)
        }
    }

    private fun createUser() =
        User(
            userId,
            randomUuidString(),
            false,
            pinLength,
            randomByteArray(),
            randomByteArray(),
            randomUuidString(),
            randomByteArray()
        )

    private fun setUpCryptoMock() {
        coEvery {
            cryptoMock.getClientPass1Proof(
                mpinId = any(),
                token = any(),
                pin = any()
            )
        } returns MIRACLSuccess(
            Pass1Proof(
                X = randomByteArray(),
                SEC = randomByteArray(),
                U = randomByteArray()
            )
        )

        every {
            cryptoMock.getClientPass2Proof(any(), any(), any())
        } returns MIRACLSuccess(Pass2Proof(V = randomByteArray()))
    }

    private fun setUpAuthenticationApiMock() {
        coEvery { authenticationApiMock.executePass1Request(any(), any()) } returns MIRACLSuccess(
            Pass1Response(Y = randomHexString())
        )

        val authOTT = randomUuidString()
        coEvery { authenticationApiMock.executePass2Request(any(), any()) } returns MIRACLSuccess(
            Pass2Response(authOtt = authOTT)
        )

        coEvery {
            authenticationApiMock.executeAuthenticateRequest(
                any(),
                any()
            )
        } returns MIRACLSuccess(
            AuthenticateResponse(
                status = 200,
                message = "OK",
                renewSecretResponse = null,
                jwt = null
            )
        )
    }

    private fun setUpSessionApiMock() {
        coEvery {
            sessionApiMock.executeUpdateSessionRequest(any(), any())
        } returns MIRACLSuccess(Unit)
    }
}
