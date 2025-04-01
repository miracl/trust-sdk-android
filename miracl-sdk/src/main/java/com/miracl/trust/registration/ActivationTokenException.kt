package com.miracl.trust.registration

/** A class hierarchy that describes verification confirmation issues. */
public sealed class ActivationTokenException(cause: Throwable? = null) : Exception(cause) {
    /** Empty user ID in the App Link. */
    public object EmptyUserId : ActivationTokenException()

    /** Empty verification code in the App Link. */
    public object EmptyVerificationCode : ActivationTokenException()

    /** Invalid or expired verification code. There may be [ActivationTokenErrorResponse] in the error. */
    public class UnsuccessfulVerification internal constructor(
        public val activationTokenErrorResponse: ActivationTokenErrorResponse? = null
    ) : ActivationTokenException()

    /** The request for fetching the activation token failed. */
    public class GetActivationTokenFail internal constructor(cause: Throwable? = null) :
        ActivationTokenException(cause)
}
