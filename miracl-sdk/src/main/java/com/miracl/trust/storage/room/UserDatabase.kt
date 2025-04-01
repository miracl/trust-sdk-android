package com.miracl.trust.storage.room

import androidx.room.*
import androidx.room.migration.AutoMigrationSpec
import androidx.room.migration.Migration
import androidx.sqlite.db.SupportSQLiteDatabase
import com.miracl.trust.storage.room.dao.UserDao
import com.miracl.trust.storage.room.model.UserModel
import java.util.UUID

@Database(
    version = 4,
    entities = [UserModel::class],
    autoMigrations = [
        AutoMigration(
            from = 2,
            to = 3,
            spec = UserDatabase.AutoMigration2to3::class
        )
    ]
)
internal abstract class UserDatabase : RoomDatabase() {
    abstract fun userDao(): UserDao

    @DeleteColumn(tableName = "identities", columnName = "revoked")
    class AutoMigration2to3 : AutoMigrationSpec
}

internal class Migration1to2(val projectId: String) : Migration(1, 2) {
    override fun migrate(db: SupportSQLiteDatabase) {
        with(db) {
            // Create the new tables
            execSQL(
                "CREATE TABLE `users` (" +
                        "`userId` TEXT NOT NULL," +
                        "`projectId` TEXT NOT NULL," +
                        "`authenticationIdentityId` TEXT NOT NULL," +
                        "`signingIdentityId` TEXT," +
                        "PRIMARY KEY(`userId`, `projectId`))"
            )

            execSQL(
                "CREATE TABLE `identities` (" +
                        "`id` TEXT NOT NULL," +
                        "`pinLength` INTEGER NOT NULL," +
                        "`revoked` INTEGER NOT NULL," +
                        "`mpinId` BLOB NOT NULL," +
                        "`token` BLOB NOT NULL," +
                        "`dtas` TEXT NOT NULL," +
                        "`publicKey` BLOB," +
                        "PRIMARY KEY(`id`))"
            )

            // Migrate the data
            execSQL("ALTER TABLE `authentication_users` ADD COLUMN `id` TEXT")
            var cursor = query("SELECT `mpinId`, `token` FROM `authentication_users`")
            with(cursor) {
                while (moveToNext()) {
                    val mpinId = getBlob(getColumnIndexOrThrow("mpinId"))
                    val token = getBlob(getColumnIndexOrThrow("token"))

                    execSQL(
                        "UPDATE `authentication_users` SET `id` = '${UUID.randomUUID()}' WHERE authentication_users.mpinId = ? AND authentication_users.token = ?",
                        arrayOf(mpinId, token)
                    )
                }
            }
            cursor.close()

            execSQL("ALTER TABLE `signing_users` ADD COLUMN `id` TEXT")
            cursor = query("SELECT `mpinId`, `token` FROM `signing_users`")
            with(cursor) {
                while (moveToNext()) {
                    val mpinId = getBlob(getColumnIndexOrThrow("mpinId"))
                    val token = getBlob(getColumnIndexOrThrow("token"))

                    execSQL(
                        "UPDATE `signing_users` SET `id` = '${UUID.randomUUID()}' WHERE signing_users.mpinId = ? AND signing_users.token = ?",
                        arrayOf(mpinId, token)
                    )
                }
            }
            cursor.close()

            execSQL(
                "INSERT INTO `identities` (`id`, `pinLength`, `revoked`, `mpinId`, `token`, `dtas`, `publicKey`) " +
                        "SELECT `id`, `pinLength`, `isBlocked`, `mpinId`, `token`, `dtas`, NULL " +
                        "FROM `authentication_users`"
            )
            execSQL(
                "INSERT INTO `identities` (`id`, `pinLength`, `revoked`, `mpinId`, `token`, `dtas`, `publicKey`) " +
                        "SELECT `id`, `pinLength`, `isBlocked`, `mpinId`, `token`, `dtas`, `publicKey` " +
                        "FROM `signing_users`"
            )

            execSQL(
                "INSERT INTO `users` (`userId`, `projectId`, `authenticationIdentityId`) " +
                        "SELECT `userId`, '${projectId}', `id` " +
                        "FROM `authentication_users`"
            )
            execSQL(
                "UPDATE `users` SET `signingIdentityId` = " +
                        "(SELECT `id` FROM `signing_users` WHERE signing_users.userId = users.userId)"
            )

            // Remove the old table
            execSQL("DROP TABLE authentication_users")
            execSQL("DROP TABLE signing_users")
        }
    }
}

internal val MIGRATION_3_4 = object : Migration(3, 4) {
    override fun migrate(db: SupportSQLiteDatabase) {
        with(db) {
            // Create new users table
            execSQL(
                "CREATE TABLE `users_new` (" +
                        "`userId` TEXT NOT NULL," +
                        "`projectId` TEXT NOT NULL," +
                        "`revoked` INTEGER NOT NULL," +
                        "`pinLength` INTEGER NOT NULL," +
                        "`mpinId` BLOB NOT NULL," +
                        "`token` BLOB NOT NULL," +
                        "`dtas` TEXT NOT NULL," +
                        "`publicKey` BLOB," +
                        "PRIMARY KEY(`userId`, `projectId`))"
            )

            // Migrate identities to users
            execSQL(
                "INSERT INTO `users_new` (`userId`, `projectId`, `revoked`, `pinLength`, `mpinId`, `token`, `dtas`, `publicKey`) " +
                        "SELECT `userId`, `projectId`, `revoked`, i.pinLength, i.mpinId, i.token, i.dtas, i.publicKey FROM users u " +
                        "INNER JOIN identities i WHERE " +
                        "CASE WHEN u.signingIdentityId IS NOT NULL " +
                        "THEN i.id = u.signingIdentityId " +
                        "ELSE i.id = u.authenticationIdentityId " +
                        "END"
            )

            // Remove the old tables and rename the new one
            execSQL("DROP TABLE users")
            execSQL("DROP TABLE identities")
            execSQL("ALTER TABLE users_new RENAME TO users")
        }
    }
}