package com.miracl.trust.session

/**
 * An object representing details for an operation (authentication or signing)
 * started on another device.
 *
 * @property sessionId Identifier of the session.
 * @property sessionDescription Description of the operation that needs to be done.
 * @property userId User ID entered by the user when session is started.
 * @property projectId Project ID setting for the application in MIRACL Trust platform.
 * @property projectName Name of the project in MIRACL Trust platform.
 * @property projectLogoUrl URL of the project logo.
 * @property pinLength PIN length that needs to be entered from the user.
 * @property verificationMethod Indicates method of user verification.
 * @property verificationUrl URL for verification in case of custom verification method.
 * @property verificationCustomText Custom text specified in the MIRACL Trust portal for the custom verification.
 * @property identityType Identity type which will be used for identity verification.
 * @property identityTypeLabel Label of the identity which will be used for identity verification.
 * @property quickCodeEnabled Indicates whether [QuickCode](https://miracl.com/resources/docs/guides/built-in-user-verification/quickcode/)
 * is enabled for the project or not.
 * @property signingHash Hash of the transaction that needs to be signed if any.
 */
public class CrossDeviceSession(
    public val sessionId: String,
    public val sessionDescription: String,
    public val userId: String,
    public val projectId: String,
    public val projectName: String,
    public val projectLogoUrl: String,
    public val pinLength: Int,
    public val verificationMethod: VerificationMethod,
    public val verificationUrl: String,
    public val verificationCustomText: String,
    public val identityType: IdentityType,
    public val identityTypeLabel: String,
    public val quickCodeEnabled: Boolean,
    public val signingHash: String
)
