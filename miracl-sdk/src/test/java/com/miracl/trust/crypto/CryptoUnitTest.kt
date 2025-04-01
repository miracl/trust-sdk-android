package com.miracl.trust.crypto

import com.miracl.trust.MIRACLError
import com.miracl.trust.MIRACLSuccess
import com.miracl.trust.randomByteArray
import com.miracl.trust.randomNumericPin
import com.miracl.trust.randomPinLength
import io.mockk.clearAllMocks
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.runTest
import org.junit.Assert
import org.junit.Before
import org.junit.Test
import java.util.*

@ExperimentalCoroutinesApi
class CryptoUnitTest {
    private val cryptoExternalMock = mockk<CryptoExternalContract>()

    @Before
    fun resetMocks() {
        clearAllMocks()
    }

    @Test
    fun `getClientPass1Proof should return MIRACLSuccess with Pass1Proof when input is valid`() {
        runTest {
            // Arrange
            val mpinId = randomByteArray()
            val token = randomByteArray()
            val pass1Proof = Pass1Proof(
                X = randomByteArray(),
                SEC = randomByteArray(),
                U = randomByteArray()
            )
            val pin = randomNumericPin(randomPinLength()).toInt()
            every { cryptoExternalMock.getClientPass1(mpinId, token, pin) } returns pass1Proof

            val crypto = Crypto(cryptoExternalMock)

            // Act
            val pass1ProofResult =
                crypto.getClientPass1Proof(
                    mpinId = mpinId,
                    token = token,
                    pin = pin
                )

            // Assert
            Assert.assertTrue(pass1ProofResult is MIRACLSuccess)
            Assert.assertEquals(pass1Proof, (pass1ProofResult as MIRACLSuccess).value)
        }
    }

    @Test
    fun `getClientPass1Proof should return MIRACLError with exception when external crypto throws`() {
        runTest {
            // Arrange
            val mpinId = randomByteArray()
            val token = randomByteArray()
            val exception = Exception()
            val pin = randomNumericPin(randomPinLength()).toInt()

            every {
                cryptoExternalMock.getClientPass1(
                    mpinId,
                    token,
                    pin
                )
            } throws exception
            val crypto = Crypto(cryptoExternalMock)

            // Act
            val pass1ProofResult =
                crypto.getClientPass1Proof(
                    mpinId = mpinId,
                    token = token,
                    pin
                )

            // Assert
            Assert.assertTrue(pass1ProofResult is MIRACLError)
            Assert.assertTrue((pass1ProofResult as MIRACLError).value is CryptoException.GetClientPass1ProofError)
            Assert.assertEquals(exception, pass1ProofResult.value.cause)
        }
    }

    @Test
    fun `getClientPass2Proof should return MIRACLSuccess with Pass2Proof when input is valid`() {
        // Arrange
        val x = randomByteArray()
        val y = randomByteArray()
        val sec = randomByteArray()
        val pass2Proof = Pass2Proof(V = randomByteArray())
        every { cryptoExternalMock.getClientPass2(x, y, sec) } returns pass2Proof
        val crypto = Crypto(cryptoExternalMock)

        // Act
        val pass1ProofResult =
            crypto.getClientPass2Proof(x, y, sec)

        // Assert
        Assert.assertTrue(pass1ProofResult is MIRACLSuccess)
        Assert.assertEquals(pass2Proof, (pass1ProofResult as MIRACLSuccess).value)
    }

    @Test
    fun `getClientPass2Proof should return MIRACLError with exception when external crypto throws exception`() {
        // Arrange
        val x = randomByteArray()
        val y = randomByteArray()
        val sec = randomByteArray()
        val exception = Exception()
        every { cryptoExternalMock.getClientPass2(any(), any(), any()) } throws exception
        val crypto = Crypto(cryptoExternalMock)

        // Act
        val pass2ProofResult =
            crypto.getClientPass2Proof(x, y, sec)

        // Assert
        Assert.assertTrue(pass2ProofResult is MIRACLError)
        Assert.assertTrue((pass2ProofResult as MIRACLError).value is CryptoException.GetClientPass2ProofError)
        Assert.assertEquals(exception, pass2ProofResult.value.cause)
    }

    @Test
    fun `generateSigningKey returns signingKeyPair on CryptoExternal success`() {
        // Arrange
        val signingKeyPair = SigningKeyPair(
            randomByteArray(),
            randomByteArray()
        )
        every { cryptoExternalMock.generateSigningKeyPair() } returns signingKeyPair
        val crypto = Crypto(cryptoExternalMock)

        // Act
        val result =
            crypto.generateSigningKeyPair()

        // Assert
        Assert.assertTrue(result is MIRACLSuccess)
        Assert.assertEquals(signingKeyPair, (result as MIRACLSuccess).value)
    }

    @Test
    fun `generateSigningKey returns error from CryptoExternal on failure`() {
        // Arrange
        val exception = Exception()
        every { cryptoExternalMock.generateSigningKeyPair() } throws exception
        val crypto = Crypto(cryptoExternalMock)

        // Act
        val result =
            crypto.generateSigningKeyPair()

        // Assert
        Assert.assertTrue(result is MIRACLError)
        Assert.assertTrue((result as MIRACLError).value is CryptoException.GenerateSigningKeyPairError)
        Assert.assertEquals(exception, result.value.cause)
    }

    @Test
    fun `getDVSClientToken returns MIRACLSuccess with byteArray result of the generated token`() {
        runTest {
            // Arrange
            val pin = randomNumericPin(randomPinLength()).toInt()
            val dvsClientToken = randomByteArray()
            every { cryptoExternalMock.combineClientSecret(any(), any()) } returns randomByteArray()
            every {
                cryptoExternalMock.getDVSClientToken(
                    any(),
                    any(),
                    any(),
                    pin
                )
            } returns dvsClientToken

            val crypto = Crypto(cryptoExternalMock)

            // Act
            val result =
                crypto.getSigningClientToken(
                    randomByteArray(),
                    randomByteArray(),
                    randomByteArray(),
                    randomByteArray(),
                    pin
                )

            // Assert
            Assert.assertTrue(result is MIRACLSuccess)
            Assert.assertArrayEquals(dvsClientToken, (result as MIRACLSuccess).value)
        }
    }

    @Test
    fun `getDVSClientToken returns MIRACLError on combineClientSecret CryptoExternal fail`() {
        runTest {
            // Arrange
            val pin = randomNumericPin(randomPinLength()).toInt()
            val exception = Exception()
            every { cryptoExternalMock.combineClientSecret(any(), any()) } throws exception

            val crypto = Crypto(cryptoExternalMock)

            // Act
            val result =
                crypto.getSigningClientToken(
                    randomByteArray(),
                    randomByteArray(),
                    randomByteArray(),
                    randomByteArray(),
                    pin
                )

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertTrue((result as MIRACLError).value is CryptoException.GetSigningClientTokenError)
            Assert.assertEquals(exception, result.value.cause)
        }
    }

    @Test
    fun `getDVSClientToken returns MIRACLError on dvsClientToken CryptoExternal fail`() {
        runTest {
            // Arrange
            val pin = randomNumericPin(randomPinLength()).toInt()
            val exception = Exception()
            every { cryptoExternalMock.combineClientSecret(any(), any()) } returns randomByteArray()
            every {
                cryptoExternalMock.getDVSClientToken(
                    any(),
                    any(),
                    any(),
                    pin
                )
            } throws exception

            val crypto = Crypto(cryptoExternalMock)

            // Act
            val result =
                crypto.getSigningClientToken(
                    randomByteArray(),
                    randomByteArray(),
                    randomByteArray(),
                    randomByteArray(),
                    pin
                )

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertTrue((result as MIRACLError).value is CryptoException.GetSigningClientTokenError)
            Assert.assertEquals(exception, result.value.cause)
        }
    }

    @Test
    fun `sign returns MIRACLSuccess with signingResult on success`() {
        runTest {
            // Arrange
            val pin = randomNumericPin(randomPinLength()).toInt()
            val signingResult = SigningResult(
                randomByteArray(),
                randomByteArray()
            )
            every {
                cryptoExternalMock.sign(
                    any(),
                    any(),
                    any(),
                    pin,
                    any()
                )
            } returns signingResult

            val crypto = Crypto(cryptoExternalMock)

            // Act
            val result =
                crypto.sign(
                    randomByteArray(),
                    randomByteArray(),
                    randomByteArray(),
                    Date(),
                    pin
                )

            // Assert
            Assert.assertTrue(result is MIRACLSuccess)
            Assert.assertEquals(signingResult, (result as MIRACLSuccess).value)
        }
    }

    @Test
    fun `sign returns MIRACLError on signing CryptoExternal fail`() {
        runTest {
            // Arrange
            val pin = randomNumericPin(randomPinLength()).toInt()
            val exception = Exception()
            every {
                cryptoExternalMock.sign(
                    any(),
                    any(),
                    any(),
                    pin,
                    any()
                )
            } throws exception

            val crypto = Crypto(cryptoExternalMock)

            // Act
            val result =
                crypto.sign(
                    randomByteArray(),
                    randomByteArray(),
                    randomByteArray(),
                    Date(),
                    pin
                )

            // Assert
            Assert.assertTrue(result is MIRACLError)
            Assert.assertTrue((result as MIRACLError).value is CryptoException.SignError)
            Assert.assertEquals(exception, result.value.cause)
        }
    }
}
