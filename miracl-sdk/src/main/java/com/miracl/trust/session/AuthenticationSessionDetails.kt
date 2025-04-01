package com.miracl.trust.session

/**
 * Object representing details from incoming authentication session.
 * @property accessId Identifier of the authentication session.
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
 * @property limitQuickCodeRegistration Indicates whether registration with QuickCode is allowed for identities registered also with QuickCode.
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
    quickCodeEnabled: Boolean,
    limitQuickCodeRegistration: Boolean
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
    quickCodeEnabled,
    limitQuickCodeRegistration
)
