package com.miracl.trust.model

import androidx.annotation.Keep
import com.miracl.trust.util.toSHA256

/**
 * Object representing the user in the platform.
 * @property userId Identifier of the user. Could be email, username, etc.
 * @property projectId Required to link the user with the project on the MIRACLTrust platform.
 * @property revoked Provides information if the user is revoked or not.
 * @property pinLength The number of the digits the user PIN should be.
 */
@Keep
public class User internal constructor(
    public val userId: String,
    public val projectId: String,
    public val revoked: Boolean,
    public val pinLength: Int,
    internal val mpinId: ByteArray,
    internal val token: ByteArray,
    internal val dtas: String,
    internal val publicKey: ByteArray?
) {
    /** Hex encoded SHA256 representation of the mpinId property. */
    public val hashedMpinId: String = mpinId.toSHA256()
}

internal fun User.isEmpty(): Boolean = dtas.isBlank() || mpinId.isEmpty() || token.isEmpty()

internal fun User.revoke(): User = User(
    userId = userId,
    projectId = projectId,
    revoked = true,
    pinLength = pinLength,
    mpinId = mpinId,
    token = token,
    dtas = dtas,
    publicKey = publicKey
)