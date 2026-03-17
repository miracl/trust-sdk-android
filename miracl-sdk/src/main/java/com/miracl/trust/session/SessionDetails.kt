package com.miracl.trust.session

/**
 * Object representing details from an incoming session.
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
