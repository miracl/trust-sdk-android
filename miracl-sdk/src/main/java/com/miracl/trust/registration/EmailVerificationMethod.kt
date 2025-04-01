package com.miracl.trust.registration

/** Possible email verification methods. */
public enum class EmailVerificationMethod {
    /** Verification link is sent to the user email. */
    Link,

    /** Verification code is sent to the user email. */
    Code;

    override fun toString(): String {
        return when (this) {
            Code -> "code"
            Link -> "link"
        }
    }

    public companion object {
        public fun fromString(value: String): EmailVerificationMethod {
            return when (value) {
                "link" -> Link
                "code" -> Code
                else -> Link
            }
        }
    }
}