package com.miracl.trust.crypto

import android.util.Log
import androidx.annotation.VisibleForTesting

internal class CryptoExternal : CryptoExternalContract {
    companion object {
        init {
            try {
                System.loadLibrary("miraclcrypto")
            } catch (e: UnsatisfiedLinkError) {
                Log.e("Crypto", "Cannot load crypto lib. ${e.message}")
            }

        }
    }

    @VisibleForTesting
    external override fun combineClientSecret(css1: ByteArray, css2: ByteArray): ByteArray

    @VisibleForTesting
    external override fun getClientPass1(mpinId: ByteArray, token: ByteArray, pin: Int): Pass1Proof

    @VisibleForTesting
    external override fun getClientPass2(x: ByteArray, y: ByteArray, sec: ByteArray): Pass2Proof

    @VisibleForTesting
    external override fun generateSigningKeyPair(): SigningKeyPair

    @VisibleForTesting
    external override fun getDVSClientToken(
        clientSecret: ByteArray,
        privateKey: ByteArray,
        mpinId: ByteArray,
        pin: Int
    ): ByteArray

    @VisibleForTesting
    external override fun sign(
        message: ByteArray,
        signingMpinId: ByteArray,
        signingToken: ByteArray,
        pin: Int,
        timestamp: Int
    ): SigningResult
}
