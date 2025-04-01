package com.miracl.trust.storage.room

import com.miracl.trust.model.User
import com.miracl.trust.storage.UserStorage
import com.miracl.trust.storage.room.model.UserModel
import kotlinx.coroutines.runBlocking

internal class RoomUserStorage(private val userDatabase: UserDatabase) : UserStorage {
    override fun loadStorage() {
    }

    override fun add(user: User) {
        runBlocking {
            userDatabase.userDao().insert(user.toUserModel())
        }
    }

    override fun update(user: User) {
        runBlocking {
            userDatabase.userDao().update(user.toUserModel())
        }
    }

    override fun delete(user: User) {
        runBlocking {
            userDatabase.userDao().delete(user.toUserModel())
        }
    }

    override fun getUser(userId: String, projectId: String): User? {
        return runBlocking {
            val userModel = userDatabase.userDao().get(userId, projectId)
            userModel?.toUser()
        }
    }

    override fun all(): List<User> {
        return runBlocking {
            userDatabase.userDao().getAll()
                .map { it.toUser() }
        }
    }

    private fun UserModel.toUser(): User =
        User(
            userId = userId,
            projectId = projectId,
            revoked = revoked,
            pinLength = pinLength,
            mpinId = mpinId,
            token = token,
            dtas = dtas,
            publicKey = publicKey
        )

    private fun User.toUserModel(): UserModel =
        UserModel(
            userId = userId,
            projectId = projectId,
            revoked = revoked,
            pinLength = pinLength,
            mpinId = mpinId,
            token = token,
            dtas = dtas,
            publicKey = publicKey
        )
}