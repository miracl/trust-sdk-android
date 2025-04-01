package com.miracl.trust.user_storage

import androidx.room.withTransaction
import com.miracl.trust.model.User
import com.miracl.trust.randomByteArray
import com.miracl.trust.randomPinLength
import com.miracl.trust.randomUuidString
import com.miracl.trust.storage.room.RoomUserStorage
import com.miracl.trust.storage.room.UserDatabase
import com.miracl.trust.storage.room.dao.UserDao
import com.miracl.trust.storage.room.model.UserModel
import io.mockk.*
import kotlinx.coroutines.ExperimentalCoroutinesApi
import org.junit.After
import org.junit.Assert
import org.junit.Before
import org.junit.Test
import kotlin.random.Random

@ExperimentalCoroutinesApi
class RoomUserStorageUnitTest {
    private val projectId = randomUuidString()

    private val userDatabaseMock = mockk<UserDatabase>()
    private val userDaoMock = mockk<UserDao>()

    @Before
    fun setUp() {
        clearAllMocks()
        mockkStatic(
            "androidx.room.RoomDatabaseKt"
        )
    }

    @After
    fun tearDown() {
        unmockkStatic(
            "androidx.room.RoomDatabaseKt"
        )
    }

    @Test
    fun `add should correctly call insert on the dao`() {
        // Arrange
        every { userDatabaseMock.userDao() } returns userDaoMock
        coEvery { userDaoMock.insert(any()) } returns Unit

        val userStorage = RoomUserStorage(userDatabaseMock)

        // Act
        userStorage.add(createUser())

        // Assert
        coVerify { userDaoMock.insert(ofType(UserModel::class)) }
    }

    @Test
    fun `add should correctly map the User object to UserModel`() {
        // Arrange
        val user = createUser()

        every { userDatabaseMock.userDao() } returns userDaoMock
        coEvery { userDaoMock.insert(any()) } returns Unit

        val userStorage = RoomUserStorage(userDatabaseMock)

        // Act
        userStorage.add(user)

        // Assert
        val capturingSlot = CapturingSlot<UserModel>()
        coVerify { userDaoMock.insert(capture(capturingSlot)) }

        val userModel = capturingSlot.captured
        Assert.assertEquals(user.userId, userModel.userId)
        Assert.assertEquals(projectId, userModel.projectId)
        Assert.assertEquals(user.revoked, userModel.revoked)
        Assert.assertEquals(user.pinLength, userModel.pinLength)
        Assert.assertEquals(user.mpinId, userModel.mpinId)
        Assert.assertEquals(user.token, userModel.token)
        Assert.assertEquals(user.dtas, userModel.dtas)
        Assert.assertEquals(user.publicKey, userModel.publicKey)
    }

    @Test
    fun `update should correctly call update on the dao`() {
        // Arrange
        val user = createUser()

        every { userDatabaseMock.userDao() } returns userDaoMock
        coEvery { userDaoMock.update(any()) } returns Unit

        val userStorage = RoomUserStorage(userDatabaseMock)

        // Act
        userStorage.update(user)

        // Assert
        coVerify { userDaoMock.update(ofType(UserModel::class)) }
    }

    @Test
    fun `update should correctly map the User object to UserModel`() {
        // Arrange
        val user = createUser()

        every { userDatabaseMock.userDao() } returns userDaoMock
        coEvery { userDaoMock.update(any()) } returns Unit

        val userStorage = RoomUserStorage(userDatabaseMock)

        // Act
        userStorage.update(user)

        // Assert
        val capturingSlot = CapturingSlot<UserModel>()
        coVerify { userDaoMock.update(capture(capturingSlot)) }

        val userModel = capturingSlot.captured
        Assert.assertEquals(user.userId, userModel.userId)
        Assert.assertEquals(projectId, userModel.projectId)
        Assert.assertEquals(user.revoked, userModel.revoked)
        Assert.assertEquals(user.pinLength, userModel.pinLength)
        Assert.assertEquals(user.mpinId, userModel.mpinId)
        Assert.assertEquals(user.token, userModel.token)
        Assert.assertEquals(user.dtas, userModel.dtas)
        Assert.assertEquals(user.publicKey, userModel.publicKey)
    }

    @Test
    fun `delete should correctly call delete on the dao`() {
        // Arrange
        val user = createUser()
        val userStorage = RoomUserStorage(userDatabaseMock)

        val slot = slot<suspend () -> Unit>()
        coEvery { userDatabaseMock.withTransaction(capture(slot)) } coAnswers { slot.captured.invoke() }

        every { userDatabaseMock.userDao() } returns userDaoMock
        coEvery { userDaoMock.delete(any()) } returns Unit

        // Act
        userStorage.delete(user)

        // Assert
        coVerify { userDaoMock.delete(any()) }
    }

    @Test
    fun `delete should correctly map the User object to UserModel`() {
        // Arrange
        val user = createUser()

        val slot = slot<suspend () -> Unit>()
        coEvery { userDatabaseMock.withTransaction(capture(slot)) } coAnswers { slot.captured() }

        every { userDatabaseMock.userDao() } returns userDaoMock
        coEvery { userDaoMock.delete(any()) } returns Unit

        val userStorage = RoomUserStorage(userDatabaseMock)

        // Act
        userStorage.delete(user)

        // Assert
        val capturingSlot = CapturingSlot<UserModel>()
        coVerify { userDaoMock.delete(capture(capturingSlot)) }

        val userModel = capturingSlot.captured
        Assert.assertEquals(user.userId, userModel.userId)
        Assert.assertEquals(projectId, userModel.projectId)
        Assert.assertEquals(user.revoked, userModel.revoked)
        Assert.assertEquals(user.pinLength, userModel.pinLength)
        Assert.assertEquals(user.mpinId, userModel.mpinId)
        Assert.assertEquals(user.token, userModel.token)
        Assert.assertEquals(user.dtas, userModel.dtas)
        Assert.assertEquals(user.publicKey, userModel.publicKey)
    }

    @Test
    fun `getUser should return user if the UserDao returns userModel`() {
        // Arrange
        val userId = randomUuidString()
        val userModel = createUserModel()

        every { userDatabaseMock.userDao() } returns userDaoMock
        coEvery { userDaoMock.get(userId, projectId) } returns userModel

        val userStorage = RoomUserStorage(userDatabaseMock)

        // Act
        val user = userStorage.getUser(userId, projectId)

        // Assert
        Assert.assertNotNull(userModel)
        Assert.assertEquals(userModel.userId, user!!.userId)
        Assert.assertEquals(projectId, user.projectId)
        Assert.assertEquals(userModel.revoked, user.revoked)
        Assert.assertEquals(userModel.pinLength, user.pinLength)
        Assert.assertEquals(userModel.mpinId, user.mpinId)
        Assert.assertEquals(userModel.token, user.token)
        Assert.assertEquals(userModel.dtas, user.dtas)
        Assert.assertEquals(userModel.publicKey, user.publicKey)
    }

    @Test
    fun `getUser should return null if the UserDao returns null`() {
        // Arrange
        val userId = randomUuidString()
        every { userDatabaseMock.userDao() } returns userDaoMock
        coEvery { userDaoMock.get(userId, projectId) } returns null

        val userStorage = RoomUserStorage(userDatabaseMock)

        // Act & Assert
        Assert.assertNull(userStorage.getUser(userId, projectId))
    }

    @Test
    fun `all should return empty list when no user is saved`() {
        // Arrange
        every { userDatabaseMock.userDao() } returns userDaoMock
        coEvery { userDaoMock.getAll() } returns listOf()

        val userStorage = RoomUserStorage(userDatabaseMock)

        // Act
        val list = userStorage.all()

        // Assert
        Assert.assertTrue(list.isEmpty())
    }

    @Test
    fun `all should return list with mapped users when there are saved users`() {
        // Arrange
        val userModel = createUserModel()
        every { userDatabaseMock.userDao() } returns userDaoMock
        coEvery { userDaoMock.getAll() } returns listOf(userModel)

        val userStorage = RoomUserStorage(userDatabaseMock)

        // Act
        val list = userStorage.all()

        // Assert
        Assert.assertEquals(1, list.size)
        val user: User = list.first()

        Assert.assertEquals(userModel.userId, user.userId)
        Assert.assertEquals(projectId, user.projectId)
        Assert.assertEquals(userModel.revoked, user.revoked)
        Assert.assertEquals(userModel.pinLength, user.pinLength)
        Assert.assertEquals(userModel.mpinId, user.mpinId)
        Assert.assertEquals(userModel.token, user.token)
        Assert.assertEquals(userModel.dtas, user.dtas)
        Assert.assertEquals(userModel.publicKey, user.publicKey)
    }

    private fun createUser() = User(
        userId = randomUuidString(),
        projectId = projectId,
        revoked = Random.nextBoolean(),
        pinLength = randomPinLength(),
        mpinId = randomByteArray(),
        token = randomByteArray(),
        dtas = randomUuidString(),
        publicKey = randomByteArray()
    )

    private fun createUserModel() = UserModel(
        userId = randomUuidString(),
        projectId = projectId,
        revoked = Random.nextBoolean(),
        pinLength = randomPinLength(),
        mpinId = randomByteArray(),
        token = randomByteArray(),
        dtas = randomUuidString(),
        publicKey = randomByteArray()
    )
}
