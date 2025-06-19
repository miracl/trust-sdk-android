package com.miracl.trust.storage

/**
 * ## A type representing storage
 * Already registered users will be kept in it between app launches.
 * >
 * Methods of this interface must not be called outside of the SDK, as they are intended
 * to be only for internal usage.
 *
 * Keep in mind, that this interface doesn't provide any data encryption and developers should take
 * care of this by themselves.
 * >
 * By default this SDK uses a concrete implementation of this interface [RoomUserStorage][com.miracl.trust.storage.room.RoomUserStorage].
 */
public interface UserStorage {
    /**
     * Prepares the user storage to be used.
     * > Called once on initialization of the SDK.
     */
    public fun loadStorage()

    /**
     * Adds a registered user to the user storage.
     * @param user registered user.
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
     * @param userId Identifier of the user.
     * @param projectId Identifier of the project on the MIRACLTrust platform to which the user is linked.
     */
    public fun getUser(userId: String, projectId: String): UserDto?

    /**
     * Returns all users from the user storage.
     */
    public fun all(): List<UserDto>
}