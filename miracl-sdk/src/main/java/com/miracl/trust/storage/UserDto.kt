package com.miracl.trust.storage

/**
 * Defines the persistent data representation of a user.
 *
 * A user is uniquely identified by the composite key of (`userId`, `projectId`).
 *
 * WARNING: This object contains sensitive data.
 * Implementers must ensure secure storage (e.g., encryption at rest).
 *
 * @property userId The identifier of the user, which is unique within the scope of a project.
 * Could be email, username, etc.
 * @property projectId The identifier of the project this user belongs to.
 * @property revoked The revocation status of the user.
 * @property pinLength The user's PIN's number of digits.
 * @property mpinId The identifier of this user registration in the MIRACL Trust Platform.
 * @property publicKey The public part of the user's signing key.
 * @property token A secure user token.
 * **CAUTION** This field contain sensitive data. The storage implementation
 * is responsible for its secure handling, including encryption at rest.
 * @property dtas Data required for server-side validation.
 */
public class UserDto(
    public val userId: String,
    public val projectId: String,
    public val revoked: Boolean,
    public val pinLength: Int,
    public val mpinId: ByteArray,
    public val token: ByteArray,
    public val dtas: String,
    public val publicKey: ByteArray?
)
