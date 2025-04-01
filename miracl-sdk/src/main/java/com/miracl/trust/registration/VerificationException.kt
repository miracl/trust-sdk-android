package com.miracl.trust.registration

/** A class hierarchy that describes verification issues. */
public sealed class VerificationException(cause: Throwable? = null) : Exception(cause) {
    /** Empty user ID. */
    public object EmptyUserId : VerificationException()

    /** The session identifier in SessionDetails is empty or blank. */
    public object InvalidSessionDetails : VerificationException()

    /**
     * Too many verification requests. Wait for the [backoff] period.
     * @property backoff Unix timestamp before a new verification email could be sent for the same user ID.
     */
    public class RequestBackoff internal constructor(public val backoff: Long) :
        VerificationException()

    /** Verification failed. */
    public class VerificationFail internal constructor(cause: Throwable? = null) :
        VerificationException(cause)
}
