package com.miracl.trust.session

/** A class hierarchy that describes issues with the cross-device session management. */
public sealed class CrossDeviceSessionException(cause: Exception? = null) : Exception(cause) {
    /** Could not find the session identifier in the App Link. */
    public object InvalidAppLink : CrossDeviceSessionException()

    /** Could not find the session identifier in the QR code. */
    public object InvalidQRCode : CrossDeviceSessionException()

    /** Could not find the session identifier in the push notification payload. */
    public object InvalidNotificationPayload : CrossDeviceSessionException()

    /** The session identifier in the [CrossDeviceSession] is empty or blank. */
    public object InvalidCrossDeviceSession: CrossDeviceSessionException()

    /** Fetching the cross-device session failed. */
    public class GetCrossDeviceSessionFail internal constructor(cause: Exception?) :
        CrossDeviceSessionException(cause)

    /** Cross-device session abort failed. */
    public class AbortCrossDeviceSessionFail internal constructor(cause: Exception?) :
        CrossDeviceSessionException(cause)
}