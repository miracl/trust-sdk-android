package com.miracl.trust.registration

public sealed class QuickCodeException(cause: Throwable? = null) : Exception(cause) {
    /** PIN code contains invalid symbols or PIN length does not match. */
    public object InvalidPin : QuickCodeException()

    /** PIN not entered. */
    public object PinCancelled : QuickCodeException()

    /** The authentication was not successful. */
    public object UnsuccessfulAuthentication : QuickCodeException()

    /** The user was revoked due to too many failed authentication attempts or
    prolonged inactivity. The device must be re-registered.
     */
    public object Revoked : QuickCodeException()

    /** QuickCode generation failed. */
    public class GenerationFail internal constructor(cause: Throwable? = null) :
        QuickCodeException(cause)
}
