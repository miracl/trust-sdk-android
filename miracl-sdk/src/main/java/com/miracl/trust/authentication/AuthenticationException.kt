package com.miracl.trust.authentication

/** A class hierarchy that describes authentication issues. */
public sealed class AuthenticationException(cause: Throwable? = null) : Exception(cause) {
    /** User object passed for authentication is not valid. */
    public object InvalidUserData : AuthenticationException()

    /** Could not find the session identifier in App Link. */
    public object InvalidAppLink : AuthenticationException()

    /** Could not find the session identifier in QR URL. */
    public object InvalidQRCode : AuthenticationException()

    /** Could not find a valid projectID, qrURL, or userID in the push notification payload. */
    public object InvalidPushNotificationPayload : AuthenticationException()

    /** There isn't a registered user for the provided user ID and project in the push notification payload. */
    public object UserNotFound : AuthenticationException()

    /** Pin code includes invalid symbols or pin length does not match. */
    public object InvalidPin : AuthenticationException()

    /** Pin not entered. */
    public object PinCancelled : AuthenticationException()

    /** Invalid or expired authentication session. */
    public object InvalidAuthenticationSession : AuthenticationException()

    /** Invalid or expired cross-device session. */
    public object InvalidCrossDeviceSession : AuthenticationException()

    /** The authentication was not successful. */
    public object UnsuccessfulAuthentication : AuthenticationException()

    /** The user is revoked because of too many unsuccessful authentication attempts or has not been
     *  used in a substantial amount of time. The device needs to be re-registered.
     */
    public object Revoked : AuthenticationException()

    /** Authentication failed. */
    public class AuthenticationFail internal constructor(cause: Throwable? = null) :
        AuthenticationException(cause)
}
