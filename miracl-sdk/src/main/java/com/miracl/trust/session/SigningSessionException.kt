package com.miracl.trust.session

/** A class hierarchy that describes issues with the signing session management. */
public sealed class SigningSessionException(cause: Exception? = null) : Exception(cause) {
    /** Could not find the session identifier in the App Link. */
    public object InvalidAppLink : SigningSessionException()

    /** Could not find the session identifier in the QR code. */
    public object InvalidQRCode : SigningSessionException()

    /** The session identifier in SigningSessionDetails is empty or blank. */
    public object InvalidSigningSessionDetails : SigningSessionException()

    /** Invalid or expired signing session. */
    public object InvalidSigningSession : SigningSessionException()

    /** Fetching the signing session details failed. */
    public class GetSigningSessionDetailsFail internal constructor(cause: Exception?) :
        SigningSessionException(cause)

    /** Signing session completion failed. */
    public class CompleteSigningSessionFail internal constructor(cause: Exception?) :
        SigningSessionException(cause)

    /** Abort of the signing session has failed. */
    public class AbortSigningSessionFail internal constructor(cause: Exception?) :
        SigningSessionException(cause)
}
