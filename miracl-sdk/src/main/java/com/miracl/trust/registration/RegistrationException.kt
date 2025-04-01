package com.miracl.trust.registration

/** A class hierarchy that describes registration issues. */
public sealed class RegistrationException(cause: Throwable? = null) : Exception(cause) {
    /** Empty user ID. */
    public object EmptyUserId : RegistrationException()

    /** Empty activation token. */
    public object EmptyActivationToken : RegistrationException()

    /** The registration was started for a different project. */
    public object ProjectMismatch : RegistrationException()

    /** Invalid activation token. */
    public object InvalidActivationToken : RegistrationException()

    /** Pin code includes invalid symbols or pin length does not match. */
    public object InvalidPin : RegistrationException()

    /** Pin not entered. */
    public object PinCancelled : RegistrationException()

    /** Curve returned by the platform is unsupported by this version of the SDK. */
    public object UnsupportedEllipticCurve : RegistrationException()

    /** Registration failed. */
    public class RegistrationFail internal constructor(cause: Throwable? = null) :
        RegistrationException(cause)
}
