package com.miracl.trust.authentication

/** A class hierarchy that describes authentication issues. */
public sealed class AuthenticationException(cause: Throwable? = null) : Exception(cause) {
    /** The user object passed for authentication is not valid. */
    public object InvalidUserData : AuthenticationException()

    /** Could not find the session identifier in the App Link. */
    public object InvalidAppLink : AuthenticationException()

    /** Could not find the session identifier in the QR code URL. */
    public object InvalidQRCode : AuthenticationException()

    /** Could not find a valid projectID, qrURL, or userID in the push notification payload. */
    public object InvalidPushNotificationPayload : AuthenticationException()

    /** There is no registered user for the provided User ID and project in the push notification payload. */
    public object UserNotFound : AuthenticationException()

    /** PIN code contains invalid symbols or PIN length does not match. */
    public object InvalidPin : AuthenticationException()

    /** PIN not entered. */
    public object PinCancelled : AuthenticationException()

    /** Invalid or expired authentication session. */
    public object InvalidAuthenticationSession : AuthenticationException()

    /** Invalid or expired cross-device session. */
    public object InvalidCrossDeviceSession : AuthenticationException()

    /** Authentication was not successful. */
    public object UnsuccessfulAuthentication : AuthenticationException()

    /** The user was revoked due to too many failed authentication attempts or prolonged
     *  inactivity. The device must be re-registered.
     */
    public object Revoked : AuthenticationException()

    /** Authentication failed. */
    public class AuthenticationFail internal constructor(cause: Throwable? = null) :
        AuthenticationException(cause)
}
