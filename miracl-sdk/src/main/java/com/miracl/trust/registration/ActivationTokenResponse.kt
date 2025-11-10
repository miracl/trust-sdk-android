package com.miracl.trust.registration

import androidx.annotation.Keep
import com.miracl.trust.MIRACLTrust

/**
 * Response returned from [getActivationToken][MIRACLTrust.getActivationToken] method of [MIRACLTrust]
 * @property projectId Identifier of the project against which the verification is performed.
 * @property accessId Identifier of the session from which the verification started.
 * @property userId Identifier of the user that is currently verified.
 * @property activationToken The activation token returned after successful user verification.
 */
@Keep
public class ActivationTokenResponse internal constructor(
    public val projectId: String,
    public val accessId: String?,
    public val userId: String,
    public val activationToken: String
) {
    override fun toString(): String {
        return "ActivationTokenResponse(activationToken=<REDACTED>, projectId=$projectId, accessId=$accessId, userId=$userId)"
    }
}
