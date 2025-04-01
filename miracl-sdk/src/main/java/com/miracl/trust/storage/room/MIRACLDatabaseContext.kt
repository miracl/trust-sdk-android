package com.miracl.trust.storage.room

import android.content.Context
import android.content.ContextWrapper
import java.io.File
import java.io.IOException

internal class MIRACLDatabaseContext(context: Context, private val databaseName: String) :
    ContextWrapper(context) {

    override fun getDatabasePath(name: String): File {
        val databaseFile = File(noBackupFilesDir, name)

        if (!databaseFile.exists()) {
            try {
                moveDatabaseToNoBackupFolder()
            } catch (ex: IOException) {
                // Return the default database path if database can't be moved
                return super.getDatabasePath(name)
            }
        }

        return databaseFile
    }

    private fun moveDatabaseToNoBackupFolder() {
        val db = baseContext.getDatabasePath(databaseName)
        val dbShm = baseContext.getDatabasePath("${databaseName}-shm")
        val dbWal = baseContext.getDatabasePath("${databaseName}-wal")

        if (db.exists()) {
            db.copyTo(target = File(noBackupFilesDir, databaseName), overwrite = true)
        }

        if (dbShm.exists()) {
            dbShm.copyTo(File(noBackupFilesDir, "${databaseName}-shm"), overwrite = true)
        }

        if (dbWal.exists()) {
            dbWal.copyTo(File(noBackupFilesDir, "${databaseName}-wal"), overwrite = true)
        }

        db.delete()
        dbShm.delete()
        dbWal.delete()
    }
}