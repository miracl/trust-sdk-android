package com.miracl.trust.session

/**
 * Object representing details from incoming session.
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
public sealed class SessionDetails(
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
    public val quickCodeEnabled: Boolean
)

/** Possible verification methods that can be used for identity verification. */
public enum class VerificationMethod {
    /** Identity verification done by email. */
    StandardEmail,

    /** Custom identity verification, done with a client implementation. */
    FullCustom;

    public companion object {
        public fun fromString(value: String): VerificationMethod {
            return when (value) {
                "standardEmail" -> StandardEmail
                "fullCustom" -> FullCustom
                else -> StandardEmail
            }
        }
    }
}

/** Possible identity types that can be used for identity verification. */
public enum class IdentityType {
    /** Identity is identified with email. */
    Email,

    /** Identity is identified with alphanumeric symbols. */
    Alphanumeric;

    public companion object {
        public fun fromString(value: String): IdentityType {
            return when (value) {
                "email" -> Email
                "alphanumeric" -> Alphanumeric
                else -> Email
            }
        }
    }
}
