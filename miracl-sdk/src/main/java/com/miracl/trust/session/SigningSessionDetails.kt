package com.miracl.trust.session

/**
 * Object representing details from incoming signing session.
 * @property sessionId Identifier of the signing session.
 * @property signingHash Hash of the transaction that needs to be signed.
 * @property signingDescription Description of the transaction that needs to be signed.
 * @property status Status of the session.
 * @property expireTime Date indicating if session is expired
 * @property userId User ID entered by the user when session is started.
 * @property projectId Project ID setting for the application in MIRACL platform.
 * @property projectName Name of the project in MIRACL platform.
 * @property projectLogoUrl URL of the project logo.
 * @property pinLength Pin Length that needs to be entered from user.
 * @property verificationMethod Indicates method of user verification.
 * @property verificationUrl URL for verification in case of custom verification method.
 * @property verificationCustomText Custom text specified in the MIRACL Trust portal for the custom verification.
 * @property identityType Identity type which will be used for identity verification.
 * @property identityTypeLabel Label of the identity which will be used for identity verification.
 * @property quickCodeEnabled Indicates whether the QuickCode is enabled for the project or not.
 */
public class SigningSessionDetails internal constructor(
    public val sessionId: String,
    public val signingHash: String,
    public val signingDescription: String,
    public val status: SigningSessionStatus,
    public val expireTime: Long,
    userId: String,
    projectId: String,
    projectUrl: String,
    projectName: String,
    projectLogoUrl: String,
    pinLength: Int,
    verificationMethod: VerificationMethod,
    verificationUrl: String,
    verificationCustomText: String,
    identityType: IdentityType,
    identityTypeLabel: String,
    quickCodeEnabled: Boolean,
) : SessionDetails(
    userId,
    projectId,
    projectUrl,
    projectName,
    projectLogoUrl,
    pinLength,
    verificationMethod,
    verificationUrl,
    verificationCustomText,
    identityType,
    identityTypeLabel,
    quickCodeEnabled
) {
    override fun toString(): String {
        return "SigningSessionDetails(" +
                "sessionId=$sessionId, " +
                "signingHash=$signingHash, " +
                "signingDescription=$signingDescription, " +
                "status=$status, " +
                "expireTime=$expireTime, " +
                "userId=$userId, " +
                "projectId=$projectId, " +
                "projectName=$projectName, " +
                "projectLogoUrl=$projectLogoUrl, " +
                "pinLength=$pinLength, " +
                "verificationMethod=$verificationMethod, " +
                "verificationUrl=$verificationUrl, " +
                "verificationCustomText=$verificationCustomText, " +
                "identityType=$identityType, " +
                "identityTypeLabel=$identityTypeLabel, " +
                "quickCodeEnabled=$quickCodeEnabled" +
                ")"
    }
}

/** An enumeration describing the status of the signing session. */
public enum class SigningSessionStatus {
    /** The session is active. */
    Active,

    /** The session has finished signing the transaction. */
    Signed;

    public companion object {
        public fun fromString(value: String): SigningSessionStatus {
            return when (value) {
                "active" -> Active
                "signed" -> Signed
                else -> Active
            }
        }
    }
}