package com.miracl.trust.registration

import androidx.annotation.Keep
import com.miracl.trust.MIRACLTrust

/**
 * The response returned from [getActivationToken][MIRACLTrust.getActivationToken] method when there is an error in the request.
 * @property projectId Identifier of the project against which the verification is performed.
 * @property userId Identifier of the user for which the verification is performed.
 * @property accessId Identifier of the session from which the verification started.
 */
@Keep
public class ActivationTokenErrorResponse internal constructor(
    public val projectId: String,
    public val userId: String,
    public val accessId: String?
)
