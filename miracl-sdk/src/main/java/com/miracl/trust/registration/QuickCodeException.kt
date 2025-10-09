package com.miracl.trust.registration

public sealed class QuickCodeException(cause: Throwable? = null) : Exception(cause) {
    /** Pin code includes invalid symbols or pin length does not match. */
    public object InvalidPin : QuickCodeException()

    /** Pin not entered. */
    public object PinCancelled : QuickCodeException()

    /** The authentication was not successful. */
    public object UnsuccessfulAuthentication : QuickCodeException()

    /** The user is revoked because of too many unsuccessful authentication attempts or has not been
     *  used in a substantial amount of time. The device needs to be re-registered.
     */
    public object Revoked : QuickCodeException()

    /** QuickCode generation failed. */
    public class GenerationFail internal constructor(cause: Throwable? = null) :
        QuickCodeException(cause)
}