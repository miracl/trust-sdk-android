package com.miracl.trust.session

/**
 * Object representing details from an incoming authentication session.
 * @property accessId The identifier of the authentication session.
 * @property userId The User ID entered by the user when the session is started.
 * @property projectId The Project ID setting for the application in the MIRACL Trust platform.
 * @property projectName The name of the project in the MIRACL Trust platform.
 * @property projectLogoUrl The URL of the project logo.
 * @property pinLength The required length of the PIN entered by the user.
 * @property verificationMethod The method of user verification.
 * @property verificationUrl The URL for verification when custom user verification is used.
 * @property verificationCustomText The custom text specified in the MIRACL Trust Portal for the custom user verification.
 * @property identityType The identity type which will be used for identity verification.
 * @property identityTypeLabel The label of the identity which will be used for identity verification.
 * @property quickCodeEnabled Indicates whether the QuickCode is enabled for the project or not.
 */
public class AuthenticationSessionDetails internal constructor(
    public val accessId: String,
    userId: String,
    projectId: String,
    projectName: String,
    projectLogoUrl: String,
    pinLength: Int,
    verificationMethod: VerificationMethod,
    verificationUrl: String,
    verificationCustomText: String,
    identityType: IdentityType,
    identityTypeLabel: String,
    quickCodeEnabled: Boolean
) : SessionDetails(
    userId,
    projectId,
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
        return "AuthenticationSessionDetails(" +
                "accessId=$accessId, " +
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
