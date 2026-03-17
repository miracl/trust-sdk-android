package com.miracl.trust.registration

/** A class hierarchy that describes registration issues. */
public sealed class RegistrationException(cause: Throwable? = null) : Exception(cause) {
    /** Empty User ID. */
    public object EmptyUserId : RegistrationException()

    /** Empty activation token. */
    public object EmptyActivationToken : RegistrationException()

    /** The registration was started for a different project. */
    public object ProjectMismatch : RegistrationException()

    /** Invalid activation token. */
    public object InvalidActivationToken : RegistrationException()

    /** PIN code contains invalid symbols or PIN length does not match. */
    public object InvalidPin : RegistrationException()

    /** PIN not entered. */
    public object PinCancelled : RegistrationException()

    /** The curve returned by the platform is unsupported by this version of the SDK. */
    public object UnsupportedEllipticCurve : RegistrationException()

    /** Registration failed. */
    public class RegistrationFail internal constructor(cause: Throwable? = null) :
        RegistrationException(cause)
}
