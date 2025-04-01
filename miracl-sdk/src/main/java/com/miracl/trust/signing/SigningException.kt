package com.miracl.trust.signing

/** A class hierarchy that describes signing issues. */
public sealed class SigningException(cause: Throwable? = null) : Exception(cause) {
    /** Empty message hash. */
    public object EmptyMessageHash : SigningException()

    /** User object passed for signing is not valid. */
    public object InvalidUserData : SigningException()

    /** Pin code includes invalid symbols or pin length does not match. */
    public object InvalidPin : SigningException()

    /** Pin not entered. */
    public object PinCancelled : SigningException()

    /** The authentication was not successful. */
    public object UnsuccessfulAuthentication : SigningException()

    /** The user is revoked because of too many unsuccessful authentication attempts or has not been
     *  used in a substantial amount of time. The device needs to be re-registered.
     */
    public object Revoked : SigningException()

    /** Public key of the signing identity is empty. */
    public object EmptyPublicKey : SigningException()

    /** The session identifier in SigningSessionDetails is empty or blank. */
    public object InvalidSigningSessionDetails : SigningException()

    /** Invalid or expired signing session. */
    public object InvalidSigningSession : SigningException()

    /** Signing failed. */
    public class SigningFail internal constructor(cause: Throwable? = null) :
        SigningException(cause)
}
