package com.miracl.trust.session

import com.miracl.trust.MIRACLTrust

/**
 * An object representing details for an operation (authentication or signing)
 * started on another device.
 *
 * @property sessionId The identifier of the session.
 * @property sessionDescription The description of the operation that needs to be done.
 * @property userId The User ID entered by the user when the session is started.
 * @property projectId The Project ID setting for the application in the MIRACL Trust platform.
 * @property signingHash The hash of the transaction that needs to be signed, if any.
 *
 * @see [MIRACLTrust.getCrossDeviceSessionFromAppLink]
 * @see [MIRACLTrust.getCrossDeviceSessionFromQRCode]
 * @see [MIRACLTrust.getCrossDeviceSessionFromNotificationPayload]
 */
public class CrossDeviceSession(
    public val sessionId: String,
    public val sessionDescription: String,
    public val userId: String,
    public val projectId: String,
    public val signingHash: String
) {
    override fun toString(): String {
        return "CrossDeviceSession(" +
                "sessionId=$sessionId, " +
                "sessionDescription=$sessionDescription, " +
                "userId=$userId, " +
                "projectId=$projectId, " +
                "signingHash=$signingHash" +
                ")"
    }
}
