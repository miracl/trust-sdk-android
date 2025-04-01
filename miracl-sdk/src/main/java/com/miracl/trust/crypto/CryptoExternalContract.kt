package com.miracl.trust.crypto

internal interface CryptoExternalContract {
    fun combineClientSecret(css1: ByteArray, css2: ByteArray): ByteArray

    fun getClientPass1(mpinId: ByteArray, token: ByteArray, pin: Int): Pass1Proof

    fun getClientPass2(x: ByteArray, y: ByteArray, sec: ByteArray): Pass2Proof

    fun generateSigningKeyPair(): SigningKeyPair

    fun getDVSClientToken(
        clientSecret: ByteArray,
        privateKey: ByteArray,
        mpinId: ByteArray,
        pin: Int
    ): ByteArray

    fun sign(
        message: ByteArray,
        signingMpinId: ByteArray,
        signingToken: ByteArray,
        pin: Int,
        timestamp: Int
    ): SigningResult
}
