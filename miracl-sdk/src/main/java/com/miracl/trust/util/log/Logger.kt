package com.miracl.trust.util.log

import com.miracl.trust.util.log.Logger.LoggingLevel
import com.miracl.trust.util.log.Logger.LoggingLevel.*

/**
 * ## A type representing message logger
 * Some important and useful information will be outputted through this interface
 * while a debug build.
 * >
 * By default this SDK uses a concrete implementation of this interface [DefaultLogger][com.miracl.trust.util.log.DefaultLogger].
 *
 * @see LoggingLevel
 */
public interface Logger {

    /**
     * Controls which logs to be written to the console when using a debug build of the SDK.
     *
     * Available log levels are:
     * - *[NONE]* (default) - disables all output
     * - *[ERROR]* - enables only error logs
     * - *[WARNING]* - enables error and warning logs
     * - *[INFO]* - enables error, warning and info logs
     * - *[DEBUG]* - enables error, warning, info and debug logs
     */
    public enum class LoggingLevel {
        /**
         * **Default**
         *
         * Disables all output.
         */
        NONE,

        /**
         * Enables only error logs.
         */
        ERROR,

        /**
         * Enables error and warning logs.
         */
        WARNING,

        /**
         * Enables error, warning and info logs.
         */
        INFO,

        /**
         * Enables error, warning, info and debug logs.
         */
        DEBUG
    }

    /**
     * Writes an [ERROR] level log using the provided implementation.
     */
    public fun error(logTag: String, message: String)

    /**
     * Writes a [WARNING] level log using the provided implementation.
     */
    public fun warning(logTag: String, message: String)

    /**
     * Writes an [INFO] level log using the provided implementation.
     */
    public fun info(logTag: String, message: String)

    /**
     * Writes a [DEBUG] level log using the provided implementation.
     */
    public fun debug(logTag: String, message: String)
}

