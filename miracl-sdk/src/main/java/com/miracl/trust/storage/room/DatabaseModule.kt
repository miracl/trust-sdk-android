package com.miracl.trust.storage.room

import android.content.Context
import androidx.room.Room
import com.miracl.trust.storage.UserStorage
import com.miracl.trust.storage.security.KeyProtector
import com.miracl.trust.storage.security.KeyProvider
import net.zetetic.database.sqlcipher.SupportOpenHelperFactory

internal class RoomDatabaseModule(private val context: Context, private val projectId: String) {
    companion object {
        private const val STORAGE_PREFERENCES = "storage_preferences"
        private const val DATABASE_FILE_NAME = "users.db"
    }

    fun userStorage(): UserStorage {
        return RoomUserStorage(getRoomDatabase())
    }

    private fun getRoomDatabase() =
        Room.databaseBuilder(
            MIRACLDatabaseContext(context, DATABASE_FILE_NAME),
            UserDatabase::class.java,
            DATABASE_FILE_NAME
        )
            .addMigrations(Migration1to2(projectId), MIGRATION_3_4)
            .openHelperFactory(getSQLiteOpenHelperFactory())
            .build()


    private fun getSQLiteOpenHelperFactory(): SupportOpenHelperFactory {
        System.loadLibrary("sqlcipher")

        return SupportOpenHelperFactory(
            KeyProvider(context, getStoragePreferences(), getKeyProtector()).storageKey
        )
    }

    private fun getStoragePreferences() =
        context.getSharedPreferences(STORAGE_PREFERENCES, Context.MODE_PRIVATE)

    private fun getKeyProtector() =
        KeyProtector(context)
}