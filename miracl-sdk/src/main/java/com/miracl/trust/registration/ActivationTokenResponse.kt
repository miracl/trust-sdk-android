package com.miracl.trust.registration

import androidx.annotation.Keep
import com.miracl.trust.MIRACLTrust

/**
 * Response returned from the [getActivationToken][MIRACLTrust.getActivationToken] method of [MIRACLTrust].
 * @property projectId The identifier of the project against which the verification is performed.
 * @property accessId The identifier of the session from which the verification started.
 * @property userId The identifier of the user that is currently being verified.
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
