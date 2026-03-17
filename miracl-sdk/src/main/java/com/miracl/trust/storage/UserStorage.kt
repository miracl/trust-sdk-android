package com.miracl.trust.storage

/**
 * ## A type representing storage
 * Already registered users will be kept in it between app launches.
 * >
 * Methods of this interface must not be called outside of the SDK, as they are intended
 * for internal use only.
 *
 * Note that this interface does not provide any data encryption. Developers must ensure data is encrypted as needed.
 * >
 * By default, this SDK uses a concrete implementation of this interface [RoomUserStorage][com.miracl.trust.storage.room.RoomUserStorage].
 */
public interface UserStorage {
    /**
     * Prepares the user storage to be used.
     * > Called once when the SDK is initialized.
     */
    public fun loadStorage()

    /**
     * Adds a registered user to the user storage.
     * @param user The registered user.
     */
    public fun add(user: UserDto)

    /**
     * Updates a registered user in the user storage.
     * @param user The registered user to update.
     */
    public fun update(user: UserDto)

    /**
     * Deletes a registered user and its identities from the user storage.
     * @param user The registered user to delete.
     */
    public fun delete(user: UserDto)

    /**
     * Retrieves a registered user from the user storage.
     * @param userId The identifier of the user.
     * @param projectId The unique identifier of the MIRACL Trust project associated with the user.
     */
    public fun getUser(userId: String, projectId: String): UserDto?

    /**
     * Returns all users from the user storage.
     */
    public fun all(): List<UserDto>
}
