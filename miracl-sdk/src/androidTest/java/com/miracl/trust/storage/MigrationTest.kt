package com.miracl.trust.storage

import android.content.ContentValues
import android.database.sqlite.SQLiteDatabase
import androidx.core.database.getBlobOrNull
import androidx.core.database.getStringOrNull
import androidx.room.Room
import androidx.room.testing.MigrationTestHelper
import androidx.sqlite.db.SupportSQLiteDatabase
import androidx.sqlite.db.framework.FrameworkSQLiteOpenHelperFactory
import androidx.test.platform.app.InstrumentationRegistry
import com.miracl.trust.storage.room.MIGRATION_3_4
import com.miracl.trust.storage.room.Migration1to2
import com.miracl.trust.storage.room.UserDatabase
import com.miracl.trust.utilities.randomByteArray
import com.miracl.trust.utilities.randomPinLength
import com.miracl.trust.utilities.randomUuidString
import kotlinx.coroutines.runBlocking
import org.junit.Assert
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import java.io.IOException
import java.util.UUID
import kotlin.random.Random

class MigrationTest {
    private val testDb = "migration-test"
    private val testProjectId = randomUuidString()

    @get:Rule
    val helper = MigrationTestHelper(
        InstrumentationRegistry.getInstrumentation(),
        UserDatabase::class.java,
        listOf(UserDatabase.AutoMigration2to3()),
        FrameworkSQLiteOpenHelperFactory()
    )

    @Test
    @Throws(IOException::class)
    fun migrateVersion1To2() = runBlocking {
        val testUsers = getTestUsers()
        helper.createDatabase(testDb, 1).apply {
            // db has schema version 1. inserting some data using SQL queries.
            insertUsers(testUsers, this)
            // Prepare for the next version.
            close()
        }

        // Re-open the database with version 2 and provide
        // Migration1to2 as the migration process.
        val migratedDatabase =
            helper.runMigrationsAndValidate(testDb, 2, true, Migration1to2(testProjectId))

        // MigrationTestHelper automatically verifies the schema changes,
        // but we need to validate that the data was migrated properly.
        for (user in testUsers) {
            var cursor = migratedDatabase.query(
                "SELECT `authenticationIdentityId`, `signingIdentityId` FROM `users` WHERE users.userId = ? AND users.projectId = ?",
                arrayOf(user.userId, testProjectId)
            )
            Assert.assertTrue(cursor.moveToNext())

            val authenticationIdentityId =
                cursor.getString(cursor.getColumnIndexOrThrow("authenticationIdentityId"))

            val signingIdentityId =
                cursor.getStringOrNull(cursor.getColumnIndexOrThrow("signingIdentityId"))

            cursor = migratedDatabase.query(
                "SELECT `pinLength`, `mpinId`, `revoked`, `token`, `dtas`, `publicKey` FROM `identities` WHERE identities.id = ?",
                arrayOf(authenticationIdentityId)
            )
            Assert.assertTrue(cursor.moveToNext())

            with(cursor) {
                assertEquals(
                    user.authenticationIdentity.pinLength,
                    cursor.getInt(getColumnIndexOrThrow("pinLength"))
                )
                assertArrayEquals(
                    user.authenticationIdentity.mpinId,
                    cursor.getBlob(getColumnIndexOrThrow("mpinId"))
                )
                assertEquals(
                    user.authenticationIdentity.revoked,
                    cursor.getInt(getColumnIndexOrThrow("revoked")) > 0
                )
                assertArrayEquals(
                    user.authenticationIdentity.token,
                    cursor.getBlob(getColumnIndexOrThrow("token"))
                )
                assertEquals(
                    user.authenticationIdentity.dtas,
                    cursor.getString(getColumnIndexOrThrow("dtas"))
                )
                assertArrayEquals(
                    user.authenticationIdentity.publicKey,
                    cursor.getBlobOrNull(getColumnIndexOrThrow("publicKey"))
                )
            }

            if (user.signingIdentity != null) {
                Assert.assertNotNull(signingIdentityId)

                cursor = migratedDatabase.query(
                    "SELECT `pinLength`, `mpinId`, `revoked`, `token`, `dtas`, `publicKey` FROM `identities` WHERE identities.id = ?",
                    arrayOf(signingIdentityId)
                )
                Assert.assertTrue(cursor.moveToNext())

                with(cursor) {
                    assertEquals(
                        user.signingIdentity.pinLength,
                        cursor.getInt(getColumnIndexOrThrow("pinLength"))
                    )
                    assertArrayEquals(
                        user.signingIdentity.mpinId,
                        cursor.getBlob(getColumnIndexOrThrow("mpinId"))
                    )
                    assertEquals(
                        user.signingIdentity.revoked,
                        cursor.getInt(getColumnIndexOrThrow("revoked")) > 0
                    )
                    assertArrayEquals(
                        user.signingIdentity.token,
                        cursor.getBlob(getColumnIndexOrThrow("token"))
                    )
                    assertEquals(
                        user.signingIdentity.dtas,
                        cursor.getString(getColumnIndexOrThrow("dtas"))
                    )
                    assertArrayEquals(
                        user.signingIdentity.publicKey,
                        cursor.getBlobOrNull(getColumnIndexOrThrow("publicKey"))
                    )
                }
            }
        }
    }

    @Test
    @Throws(IOException::class)
    fun migrateVersion2to3() = runBlocking {
        val user = getTestUsers().first()
        helper.createDatabase(testDb, 2).apply {
            val values = ContentValues().apply {
                put("userId", user.userId)
                put("projectId", testProjectId)
                put("authenticationIdentityId", UUID.randomUUID().toString())
            }
            insert("users", SQLiteDatabase.CONFLICT_FAIL, values)
            close()
        }

        val migratedDatabase = helper.runMigrationsAndValidate(testDb, 3, true)

        with(migratedDatabase) {
            val cursor =
                query(
                    "SELECT `userId`, `projectId`, `revoked` FROM `users` WHERE users.userId = ? AND users.projectId = ?",
                    arrayOf(user.userId, user.projectId)
                )
            with(cursor) {
                while (moveToNext()) {
                    assertEquals(0, getInt(getColumnIndexOrThrow("revoked")))
                }
            }
        }
    }

    @Test
    fun migrateVersion3to4() = runBlocking {
        val testUsers = getTestUsers()
        helper.createDatabase(testDb, 3).apply {
            for (user in testUsers) {
                var values = ContentValues().apply {
                    put("userId", user.userId)
                    put("projectId", user.projectId)
                    put(
                        "revoked",
                        user.signingIdentity?.revoked ?: user.authenticationIdentity.revoked
                    )
                    put("authenticationIdentityId", user.authenticationIdentity.id.toString())
                    put("signingIdentityId", user.signingIdentity?.id?.toString())
                }
                insert("users", SQLiteDatabase.CONFLICT_REPLACE, values)

                values = ContentValues().apply {
                    put("id", user.authenticationIdentity.id.toString())
                    put("pinLength", user.authenticationIdentity.pinLength)
                    put("mpinId", user.authenticationIdentity.mpinId)
                    put("token", user.authenticationIdentity.token)
                    put("dtas", user.authenticationIdentity.dtas)
                }
                insert("identities", SQLiteDatabase.CONFLICT_REPLACE, values)

                user.signingIdentity?.let { signingIdentity ->
                    values = ContentValues().apply {
                        put("id", signingIdentity.id.toString())
                        put("pinLength", signingIdentity.pinLength)
                        put("mpinId", signingIdentity.mpinId)
                        put("token", signingIdentity.token)
                        put("dtas", signingIdentity.dtas)
                        put("publicKey", signingIdentity.publicKey)
                    }
                    insert("identities", SQLiteDatabase.CONFLICT_REPLACE, values)
                }
            }

            close()
        }

        val migratedDatabase = helper.runMigrationsAndValidate(testDb, 4, true, MIGRATION_3_4)

        for (user in testUsers) {
            val identity = user.signingIdentity ?: user.authenticationIdentity
            with(migratedDatabase) {
                val cursor =
                    query(
                        "SELECT `userId`, `projectId`, `revoked`, `pinLength`, `mpinId`, `token`, `dtas`, `publicKey` FROM `users` WHERE users.userId = ? AND users.projectId = ?",
                        arrayOf(user.userId, user.projectId)
                    )
                with(cursor) {
                    while (moveToNext()) {
                        assertEquals(user.userId, getString(getColumnIndexOrThrow("userId")))
                        assertEquals(user.projectId, getString(getColumnIndexOrThrow("projectId")))
                        assertEquals(identity.revoked, getInt(getColumnIndexOrThrow("revoked")) > 0)
                        assertEquals(identity.pinLength, getInt(getColumnIndexOrThrow("pinLength")))
                        assertArrayEquals(identity.mpinId, getBlob(getColumnIndexOrThrow("mpinId")))
                        assertArrayEquals(identity.token, getBlob(getColumnIndexOrThrow("token")))
                        assertEquals(identity.dtas, getString(getColumnIndexOrThrow("dtas")))
                        assertArrayEquals(
                            identity.publicKey,
                            getBlob(getColumnIndexOrThrow("publicKey"))
                        )
                    }
                }
            }
        }
        helper.closeWhenFinished(migratedDatabase)
    }

    @Test
    @Throws(IOException::class)
    fun migrateAll() {
        helper.createDatabase(testDb, 1).apply {
            close()
        }

        Room.databaseBuilder(
            InstrumentationRegistry.getInstrumentation().targetContext,
            UserDatabase::class.java,
            testDb
        ).addMigrations(Migration1to2(testProjectId), MIGRATION_3_4).build().apply {
            openHelper.writableDatabase.close()
        }
    }

    private fun insertUsers(
        users: List<MigrationTestUser>,
        db: SupportSQLiteDatabase
    ) {
        for (user in users) {
            val values = ContentValues()
            values.put("userId", user.userId)
            values.put("pinLength", user.authenticationIdentity.pinLength)
            values.put("isBlocked", user.authenticationIdentity.revoked)
            values.put("mpinId", user.authenticationIdentity.mpinId)
            values.put("token", user.authenticationIdentity.token)
            values.put("dtas", user.authenticationIdentity.dtas)
            db.insert("authentication_users", SQLiteDatabase.CONFLICT_REPLACE, values)

            val signingValues = ContentValues()
            user.signingIdentity?.let {
                signingValues.put("userId", user.userId)
                signingValues.put("pinLength", it.pinLength)
                signingValues.put("isBlocked", it.revoked)
                signingValues.put("mpinId", it.mpinId)
                signingValues.put("token", it.token)
                signingValues.put("dtas", it.dtas)
                signingValues.put("publicKey", it.publicKey)
                db.insert("signing_users", SQLiteDatabase.CONFLICT_REPLACE, signingValues)
            }
        }
    }

    private fun getTestUsers(): List<MigrationTestUser> {
        val testUsers = mutableListOf<MigrationTestUser>()

        for (i in 1..10) {
            testUsers.add(
                MigrationTestUser(
                    userId = randomUuidString(),
                    projectId = randomUuidString(),
                    authenticationIdentity = MigrationTestIdentity(
                        UUID.randomUUID(),
                        randomPinLength(),
                        Random.nextBoolean(),
                        randomByteArray(),
                        randomByteArray(),
                        randomUuidString(),
                        null
                    ),
                    signingIdentity = if (i % 2 == 0) {
                        MigrationTestIdentity(
                            UUID.randomUUID(),
                            randomPinLength(),
                            Random.nextBoolean(),
                            randomByteArray(),
                            randomByteArray(),
                            randomUuidString(),
                            randomByteArray()
                        )
                    } else null
                )
            )
        }

        return testUsers
    }

    private class MigrationTestIdentity(
        val id: UUID,
        val pinLength: Int,
        val revoked: Boolean,
        val mpinId: ByteArray,
        val token: ByteArray,
        val dtas: String,
        val publicKey: ByteArray?
    )

    private class MigrationTestUser(
        val userId: String,
        val projectId: String,
        val authenticationIdentity: MigrationTestIdentity,
        val signingIdentity: MigrationTestIdentity?
    )
}