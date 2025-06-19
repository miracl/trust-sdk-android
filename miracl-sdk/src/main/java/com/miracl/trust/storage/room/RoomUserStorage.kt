package com.miracl.trust.storage.room

import com.miracl.trust.storage.UserDto
import com.miracl.trust.storage.UserStorage
import com.miracl.trust.storage.room.model.UserModel
import kotlinx.coroutines.runBlocking

internal class RoomUserStorage(private val userDatabase: UserDatabase) : UserStorage {
    override fun loadStorage() {
    }

    override fun add(user: UserDto) {
        runBlocking {
            userDatabase.userDao().insert(user.toUserModel())
        }
    }

    override fun update(user: UserDto) {
        runBlocking {
            userDatabase.userDao().update(user.toUserModel())
        }
    }

    override fun delete(user: UserDto) {
        runBlocking {
            userDatabase.userDao().delete(user.toUserModel())
        }
    }

    override fun getUser(userId: String, projectId: String): UserDto? {
        return runBlocking {
            val userModel = userDatabase.userDao().get(userId, projectId)
            userModel?.toUserDto()
        }
    }

    override fun all(): List<UserDto> {
        return runBlocking {
            userDatabase.userDao().getAll()
                .map { it.toUserDto() }
        }
    }

    private fun UserModel.toUserDto(): UserDto =
        UserDto(
            userId = userId,
            projectId = projectId,
            revoked = revoked,
            pinLength = pinLength,
            mpinId = mpinId,
            token = token,
            dtas = dtas,
            publicKey = publicKey
        )

    private fun UserDto.toUserModel(): UserModel =
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