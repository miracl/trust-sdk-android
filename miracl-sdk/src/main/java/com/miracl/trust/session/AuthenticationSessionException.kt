package com.miracl.trust.session

/** A class hierarchy that describes issues with the authentication session management. */
public sealed class AuthenticationSessionException(cause: Exception? = null) : Exception(cause) {
    /** Could not find the session identifier in the App Link. */
    public object InvalidAppLink : AuthenticationSessionException()

    /** Could not find the session identifier in the QR code. */
    public object InvalidQRCode : AuthenticationSessionException()

    /** Could not find the session identifier in the push notification payload. */
    public object InvalidNotificationPayload : AuthenticationSessionException()

    /** The session identifier in SessionDetails is empty or blank. */
    public object InvalidSessionDetails : AuthenticationSessionException()

    /** Fetching the authentication session details failed. */
    public class GetAuthenticationSessionDetailsFail internal constructor(cause: Exception?) :
        AuthenticationSessionException(cause)

    /** Authentication session abort failed. */
    public class AbortSessionFail internal constructor(cause: Exception?) :
        AuthenticationSessionException(cause)
}
