package com.miracl.trust.registration

import androidx.annotation.Keep
import com.miracl.trust.MIRACLTrust

/**
 * Response returned from the [sendVerificationEmail][MIRACLTrust.sendVerificationEmail] method of [MIRACLTrust].
 * @property backoff Unix timestamp after which a new verification email can be sent for the same User ID.
 * @property method Indicates the method of the verification.
 */
@Keep
public class VerificationResponse internal constructor(
    public val backoff: Long,
    public val method: EmailVerificationMethod
) {
    override fun toString(): String {
        return "VerificationResponse(backoff=$backoff, method=$method)"
    }
}
