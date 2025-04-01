package com.miracl.trust.storage

import android.content.Context
import androidx.room.Room
import androidx.test.core.app.ApplicationProvider
import com.miracl.trust.storage.room.UserDatabase
import com.miracl.trust.storage.room.dao.UserDao
import com.miracl.trust.storage.room.model.UserModel
import com.miracl.trust.utilities.randomByteArray
import com.miracl.trust.utilities.randomPinLength
import com.miracl.trust.utilities.randomUuidString
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import java.io.IOException
import kotlin.random.Random

class UserDaoTest {

    private lateinit var userDao: UserDao
    private lateinit var db: UserDatabase

    private val user = createUserModel()

    @Before
    fun createDb() {
        val context: Context = ApplicationProvider.getApplicationContext()
        db = Room.inMemoryDatabaseBuilder(context, UserDatabase::class.java)
            // Allowing main thread queries, just for testing.
            .allowMainThreadQueries()
            .build()
        userDao = db.userDao()
    }

    @After
    @Throws(IOException::class)
    fun closeDb() {
        db.close()
    }

    @Test
    @Throws(Exception::class)
    fun testInsertAndGetUser() = runBlocking {
        // Act
        userDao.insert(user)

        // Assert
        val dbUser = userDao.get(user.userId, user.projectId)
        assertEquals(dbUser, user)
    }

    @Test
    @Throws(Exception::class)
    fun testUpdateAndGetUser() = runBlocking {
        // Arrange
        userDao.insert(user)

        // Act
        val updatedUser = user.copy(token = byteArrayOf(55))
        userDao.update(updatedUser)

        // Assert
        val dbUser = userDao.get(updatedUser.userId, updatedUser.projectId)
        assertEquals(dbUser, updatedUser)
    }

    @Test
    @Throws(Exception::class)
    fun testDeleteAndGetUser() = runBlocking {
        // Arrange
        userDao.insert(user)

        // Act
        userDao.delete(user)

        // Assert
        val dbUser = userDao.get(user.userId, user.projectId)
        assertNull(dbUser)
    }

    @Test
    @Throws(Exception::class)
    fun testGetAll() = runBlocking {
        // Arrange
        val users = mutableListOf<UserModel>()
        (1..10).forEach {
            val userModel = createUserModel()
            users.add(userModel)
            userDao.insert(userModel)
        }

        // Act
        val dbUsers = userDao.getAll()

        // Assert
        assertEquals(users.size, dbUsers.size)
        users.forEach { user ->
            assertTrue(dbUsers.contains(user))
        }
    }

    private fun createUserModel() = UserModel(
        userId = randomUuidString(),
        projectId = randomUuidString(),
        revoked = Random.nextBoolean(),
        pinLength = randomPinLength(),
        mpinId = randomByteArray(),
        token = randomByteArray(),
        dtas = randomUuidString(),
        publicKey = randomByteArray()
    )
}