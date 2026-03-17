package com.miracl.trust.signing

/** A class hierarchy that describes signing issues. */
public sealed class SigningException(cause: Throwable? = null) : Exception(cause) {
    /** Empty message hash. */
    public object EmptyMessageHash : SigningException()

    /** The user object passed for signing is not valid. */
    public object InvalidUserData : SigningException()

    /** PIN code contains invalid symbols or PIN length does not match. */
    public object InvalidPin : SigningException()

    /** PIN not entered. */
    public object PinCancelled : SigningException()

    /** Authentication was not successful. */
    public object UnsuccessfulAuthentication : SigningException()

    /** The user was revoked due to too many failed authentication attempts or
    prolonged inactivity. The device must be re-registered.*/
    public object Revoked : SigningException()

    /** The public key of the signing identity is empty. */
    public object EmptyPublicKey : SigningException()

    /** The session identifier in SigningSessionDetails is empty or blank. */
    public object InvalidSigningSessionDetails : SigningException()

    /** Invalid or expired signing session. */
    public object InvalidSigningSession : SigningException()

    /** Signing failed. */
    public class SigningFail internal constructor(cause: Throwable? = null) :
        SigningException(cause)
}
