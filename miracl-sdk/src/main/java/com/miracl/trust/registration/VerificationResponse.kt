package com.miracl.trust.registration

import androidx.annotation.Keep
import com.miracl.trust.MIRACLTrust

/**
 * Response returned from [sendVerificationEmail][MIRACLTrust.sendVerificationEmail] method of [MIRACLTrust].
 * @property backoff Unix timestamp before a new verification email could be sent for the same user ID.
 * @property method Indicates the method of the verification.
 */
@Keep
public class VerificationResponse internal constructor(
    public val backoff: Long,
    public val method: EmailVerificationMethod
)