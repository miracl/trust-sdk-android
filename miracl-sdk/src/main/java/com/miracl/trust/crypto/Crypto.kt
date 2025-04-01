package com.miracl.trust.crypto

import com.miracl.trust.MIRACLError
import com.miracl.trust.MIRACLResult
import com.miracl.trust.MIRACLSuccess
import com.miracl.trust.util.log.Loggable
import com.miracl.trust.util.log.LoggerConstants.CRYPTO_OPERATION_FINISHED
import com.miracl.trust.util.log.LoggerConstants.CRYPTO_OPERATION_STARTED
import com.miracl.trust.util.log.LoggerConstants.CRYPTO_TAG
import com.miracl.trust.util.secondsSince1970
import java.util.Date

internal enum class SupportedEllipticCurves {
    BN254CX
}

internal class Crypto(
    private val cryptoExternal: CryptoExternalContract = CryptoExternal()
) : Loggable {
    fun getClientPass1Proof(
        mpinId: ByteArray,
        token: ByteArray,
        pin: Int
    ): MIRACLResult<Pass1Proof, CryptoException> {
        val operationName = this::getClientPass1Proof.name
        logOperationStarted(operationName)
        return try {
            val pass1Proof = cryptoExternal.getClientPass1(mpinId, token, pin)
            logOperationFinished(operationName)
            MIRACLSuccess(pass1Proof)
        } catch (ex: Exception) {
            MIRACLError(CryptoException.GetClientPass1ProofError(ex))
        }
    }

    fun getClientPass2Proof(
        x: ByteArray,
        y: ByteArray,
        sec: ByteArray
    ): MIRACLResult<Pass2Proof, CryptoException> {
        val operationName = this::getClientPass2Proof.name
        logOperationStarted(operationName)

        return try {
            val pass2Proof =
                cryptoExternal.getClientPass2(x, y, sec)

            logOperationFinished(operationName)
            MIRACLSuccess(pass2Proof)
        } catch (ex: Exception) {
            MIRACLError(CryptoException.GetClientPass2ProofError(ex))
        }
    }

    fun generateSigningKeyPair(): MIRACLResult<SigningKeyPair, CryptoException> {
        val operationName = this::generateSigningKeyPair.name
        logOperationStarted(operationName)

        return try {
            val signingKeyPair = cryptoExternal.generateSigningKeyPair()

            logOperationFinished(operationName)
            MIRACLSuccess(signingKeyPair)
        } catch (ex: Exception) {
            MIRACLError(CryptoException.GenerateSigningKeyPairError(ex))
        }
    }

    fun getSigningClientToken(
        clientSecretShare1: ByteArray,
        clientSecretShare2: ByteArray,
        privateKey: ByteArray,
        signingMpinId: ByteArray,
        pin: Int
    ): MIRACLResult<ByteArray, CryptoException> {
        val operationName = this::getSigningClientToken.name
        logOperationStarted(operationName)

        return try {
            val clientSecret =
                cryptoExternal.combineClientSecret(clientSecretShare1, clientSecretShare2)

            val dvsClientToken = cryptoExternal.getDVSClientToken(
                clientSecret,
                privateKey,
                signingMpinId,
                pin
            )

            logOperationFinished(operationName)
            MIRACLSuccess(dvsClientToken)
        } catch (ex: Exception) {
            MIRACLError(CryptoException.GetSigningClientTokenError(ex))
        }
    }

    fun sign(
        message: ByteArray,
        signingMpinId: ByteArray,
        signingToken: ByteArray,
        timestamp: Date,
        pin: Int
    ): MIRACLResult<SigningResult, CryptoException> {
        val operationName = this::sign.name
        logOperationStarted(operationName)

        return try {
            val signingResult = cryptoExternal.sign(
                message,
                signingMpinId,
                signingToken,
                pin,
                timestamp.secondsSince1970()
            )

            logOperationFinished(operationName)
            MIRACLSuccess(signingResult)
        } catch (ex: Exception) {
            MIRACLError(CryptoException.SignError(ex))
        }
    }

    private fun logOperationStarted(operationName: String) {
        logger?.debug(CRYPTO_TAG, CRYPTO_OPERATION_STARTED.format(operationName))
    }

    private fun logOperationFinished(operationName: String) {
        logger?.debug(CRYPTO_TAG, CRYPTO_OPERATION_FINISHED.format(operationName))
    }
}
