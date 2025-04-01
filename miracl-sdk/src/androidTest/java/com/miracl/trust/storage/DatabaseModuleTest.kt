package com.miracl.trust.storage

import android.content.Context
import androidx.room.Room
import androidx.test.core.app.ApplicationProvider
import com.miracl.trust.model.User
import com.miracl.trust.storage.room.MIGRATION_3_4
import com.miracl.trust.storage.room.Migration1to2
import com.miracl.trust.storage.room.RoomDatabaseModule
import com.miracl.trust.storage.room.RoomUserStorage
import com.miracl.trust.storage.room.UserDatabase
import com.miracl.trust.storage.security.KeyProtector
import com.miracl.trust.storage.security.KeyProvider
import com.miracl.trust.utilities.randomByteArray
import com.miracl.trust.utilities.randomPinLength
import com.miracl.trust.utilities.randomUuidString
import kotlinx.coroutines.runBlocking
import net.zetetic.database.sqlcipher.SupportOpenHelperFactory
import org.junit.After
import org.junit.Assert
import org.junit.Test
import java.io.File
import kotlin.random.Random

class DatabaseModuleTest {
    companion object {
        private const val STORAGE_PREFERENCES = "storage_preferences"
        private const val DATABASE_FILE_NAME = "users.db"
        private val projectId = randomUuidString()
    }

    private val context: Context = ApplicationProvider.getApplicationContext()

    @After
    fun cleanUp() {
        File(context.noBackupFilesDir, DATABASE_FILE_NAME).delete()
        File(context.noBackupFilesDir, "$DATABASE_FILE_NAME-shm").delete()
        File(context.noBackupFilesDir, "$DATABASE_FILE_NAME-wal").delete()
    }

    @Test
    fun testDatabaseModuleCreatesDatabaseInNoBackupFilesDirOnApiLevel21AndAbove() {
        // Act
        RoomDatabaseModule(context, projectId).userStorage().all()

        // Assert
        Assert.assertTrue(File(context.noBackupFilesDir, DATABASE_FILE_NAME).exists())
        Assert.assertTrue(File(context.noBackupFilesDir, "$DATABASE_FILE_NAME-shm").exists())
        Assert.assertTrue(File(context.noBackupFilesDir, "$DATABASE_FILE_NAME-wal").exists())
    }

    @Test
    fun testDatabaseModuleMovesDatabaseFilesToNoBackupFilesDirOnApiLevel21AndAbove() =
        runBlocking {
            // Arrange
            val userStorage = RoomUserStorage(createDatabaseInDefaultDatabaseDir())
            val user = createUser()
            userStorage.add(user)

            userStorage.all().let { users ->
                Assert.assertEquals(1, users.size)
                Assert.assertEquals(user.userId, users.first().userId)
            }

            // Act
            val users = RoomDatabaseModule(context, projectId).userStorage().all()

            // Assert
            Assert.assertEquals(1, users.size)
            Assert.assertEquals(user.userId, users.first().userId)
            Assert.assertTrue(File(context.noBackupFilesDir, DATABASE_FILE_NAME).exists())
            Assert.assertTrue(File(context.noBackupFilesDir, "$DATABASE_FILE_NAME-shm").exists())
            Assert.assertTrue(File(context.noBackupFilesDir, "$DATABASE_FILE_NAME-wal").exists())
            Assert.assertFalse(context.getDatabasePath(DATABASE_FILE_NAME).exists())
            Assert.assertFalse(context.getDatabasePath("$DATABASE_FILE_NAME-shm").exists())
            Assert.assertFalse(context.getDatabasePath("$DATABASE_FILE_NAME-wal").exists())
        }

    private suspend fun createDatabaseInDefaultDatabaseDir(): UserDatabase {
        val userDatabase = Room.databaseBuilder(
            context,
            UserDatabase::class.java,
            DATABASE_FILE_NAME
        )
            .addMigrations(Migration1to2(projectId), MIGRATION_3_4)
            .openHelperFactory(
                SupportOpenHelperFactory(
                    KeyProvider(
                        context,
                        context.getSharedPreferences(
                            STORAGE_PREFERENCES,
                            Context.MODE_PRIVATE
                        ),
                        KeyProtector(context)
                    ).storageKey
                )
            )
            .build()
        userDatabase.userDao().getAll()
        Assert.assertTrue(context.getDatabasePath(DATABASE_FILE_NAME).exists())
        Assert.assertTrue(context.getDatabasePath("$DATABASE_FILE_NAME-shm").exists())
        Assert.assertTrue(context.getDatabasePath("$DATABASE_FILE_NAME-wal").exists())

        return userDatabase
    }

    private fun createUser() = User(
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