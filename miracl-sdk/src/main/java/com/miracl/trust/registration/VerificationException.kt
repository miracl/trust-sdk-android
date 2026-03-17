package com.miracl.trust.registration

/** A class hierarchy that describes verification issues. */
public sealed class VerificationException(cause: Throwable? = null) : Exception(cause) {
    /** Empty User ID. */
    public object EmptyUserId : VerificationException()

    /** The session identifier in SessionDetails is empty or blank. */
    public object InvalidSessionDetails : VerificationException()

    /**
     * Too many verification requests. Wait until the [backoff] period has elapsed.
     * @property backoff Unix timestamp after which a new verification email can be sent for the same User ID.
     */
    public class RequestBackoff internal constructor(public val backoff: Long) :
        VerificationException()

    /** Verification failed. */
    public class VerificationFail internal constructor(cause: Throwable? = null) :
        VerificationException(cause)
}
