package com.miracl.trust.storage.room.dao

import androidx.room.*
import com.miracl.trust.storage.room.model.UserModel

@Dao
internal interface UserDao {
    @Query("SELECT * FROM users")
    suspend fun getAll(): List<UserModel>

    @Query("SELECT * FROM users WHERE userId == :userId AND projectId == :projectId")
    suspend fun get(userId: String, projectId: String): UserModel?

    @Insert
    suspend fun insert(userModel: UserModel)

    @Update
    suspend fun update(userModel: UserModel)

    @Delete
    suspend fun delete(userModel: UserModel)
}