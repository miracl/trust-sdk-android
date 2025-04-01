package com.miracl.trust.crypto

/** A class hierarchy that describes issues with cryptography calculations. */
public sealed class CryptoException(cause: Throwable? = null) : Exception(cause) {
    /** Error while getting client token. */
    public class GetClientTokenError internal constructor(cause: Throwable? = null) :
        CryptoException(cause)

    /** Error while getting client pass1. */
    public class GetClientPass1ProofError internal constructor(cause: Throwable? = null) :
        CryptoException(cause)

    /** Error while getting client pass2. */
    public class GetClientPass2ProofError internal constructor(cause: Throwable? = null) :
        CryptoException(cause)

    /** Error while generating signing key pair. */
    public class GenerateSigningKeyPairError internal constructor(cause: Throwable? = null) :
        CryptoException(cause)

    /** Error while getting signing client token. */
    public class GetSigningClientTokenError internal constructor(cause: Throwable? = null) :
        CryptoException(cause)

    /** Error while signing. */
    public class SignError internal constructor(cause: Throwable? = null) : CryptoException(cause)
}