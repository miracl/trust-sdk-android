package com.miracl.trust.registration

import androidx.annotation.Keep
import com.miracl.trust.MIRACLTrust

/**
 * The response returned from the [getActivationToken][MIRACLTrust.getActivationToken] method when there is an error in the request.
 * @property projectId The identifier of the project against which the verification is performed.
 * @property userId The identifier of the user for which the verification is performed.
 * @property accessId The identifier of the session from which the verification started.
 */
@Keep
public class ActivationTokenErrorResponse internal constructor(
    public val projectId: String,
    public val userId: String,
    public val accessId: String?
) {
    override fun toString(): String {
        return "ActivationTokenErrorResponse(projectId=$projectId, userId=$userId, accessId=$accessId)"
    }
}
