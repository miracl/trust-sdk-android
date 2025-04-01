package com.miracl.trust.util.log

import android.util.Log

internal class DefaultLogger(private val loggingLevel: Logger.LoggingLevel) : Logger {
    override fun error(logTag: String, message: String) {
        if (loggingLevel >= Logger.LoggingLevel.ERROR) {
            Log.e(logTag, message)
        }
    }

    override fun warning(logTag: String, message: String) {
        if (loggingLevel >= Logger.LoggingLevel.WARNING) {
            Log.w(logTag, message)
        }
    }

    override fun info(logTag: String, message: String) {
        if (loggingLevel >= Logger.LoggingLevel.INFO) {
            Log.i(logTag, message)
        }
    }

    override fun debug(logTag: String, message: String) {
        if (loggingLevel >= Logger.LoggingLevel.DEBUG) {
            Log.d(logTag, message)
        }
    }
}