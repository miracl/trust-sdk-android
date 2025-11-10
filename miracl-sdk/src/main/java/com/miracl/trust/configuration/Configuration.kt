package com.miracl.trust.configuration

import android.os.Build
import com.miracl.trust.factory.ComponentFactory
import com.miracl.trust.network.HttpRequestExecutor
import com.miracl.trust.network.HttpsURLConnectionRequestExecutor
import com.miracl.trust.storage.UserStorage
import com.miracl.trust.util.UrlValidator
import com.miracl.trust.util.log.DefaultLogger
import com.miracl.trust.util.log.Logger
import kotlinx.coroutines.Dispatchers
import kotlin.coroutines.CoroutineContext
import kotlin.jvm.Throws

/**
 * The Configuration class is used to set up the MIRACLTrust SDK. It provides a way
 * to customize some of the SDK components.
 *
 * Instance is created though its [Builder]
 */
public class Configuration private constructor(
    internal val projectId: String,
    internal val projectUrl: String,
    internal val deviceName: String,
    internal val applicationInfo: String? = null,
    internal val httpRequestExecutor: HttpRequestExecutor,
    internal val componentFactory: ComponentFactory? = null,
    internal val userStorage: UserStorage? = null,
    internal val logger: Logger,
    internal val loggingLevel: Logger.LoggingLevel? = null,
    internal val miraclCoroutineContext: CoroutineContext,
    internal val connectTimeout: Int,
    internal val readTimeout: Int
) {
    private companion object {
        private const val DEFAULT_PLATFORM_URL = "https://api.mpin.io"
        private const val DEFAULT_CONNECT_TIMEOUT_SECONDS: Int = 10
        private const val DEFAULT_READ_TIMEOUT_SECONDS: Int = 10
    }

    private constructor(builder: Builder) :
            this(
                builder.projectId,
                builder.projectUrl,
                builder.deviceNameValue,
                builder.applicationInfo,
                builder.httpRequestExecutorValue,
                builder.componentFactory,
                builder.userStorage,
                builder.loggerValue,
                builder.loggingLevel,
                builder.coroutineContext,
                builder.connectTimeout,
                builder.readTimeout
            )

    override fun toString(): String {
        return "Configuration(" +
                "projectId=$projectId, " +
                "projectUrl=$projectUrl, " +
                "deviceName=$deviceName, " +
                "applicationInfo=$applicationInfo, " +
                "httpRequestExecutor=$httpRequestExecutor, " +
                "userStorage=${userStorage ?: "DefaultUserStorage"}, " +
                "logger=$logger, " +
                "loggingLevel=$loggingLevel, " +
                "connectTimeout=$connectTimeout, " +
                "readTimeout=$readTimeout" +
                ")"
    }

    /**
     * Builds a [Configuration] object.
     *
     * @param projectId The unique identifier for your MIRACL Trust project.
     * @param projectUrl MIRACL Trust Project URL that is used for communication with the MIRACL Trust API.
     */
    public class Builder @JvmOverloads constructor(
        internal val projectId: String,
        internal val projectUrl: String = DEFAULT_PLATFORM_URL
    ) {
        internal lateinit var deviceNameValue: String
            private set
        internal var applicationInfo: String? = null
            private set
        internal lateinit var httpRequestExecutorValue: HttpRequestExecutor
            private set
        internal var componentFactory: ComponentFactory? = null
            private set
        internal var coroutineContext: CoroutineContext = Dispatchers.IO
            private set
        internal var userStorage: UserStorage? = null
            private set
        internal lateinit var loggerValue: Logger
            private set
        internal var loggingLevel: Logger.LoggingLevel? = null
            private set
        internal var connectTimeout: Int = DEFAULT_CONNECT_TIMEOUT_SECONDS
            private set
        internal var readTimeout: Int = DEFAULT_READ_TIMEOUT_SECONDS
            private set

        internal fun componentFactory(componentFactory: ComponentFactory) =
            apply { this.componentFactory = componentFactory }

        internal fun coroutineContext(coroutineContext: CoroutineContext) =
            apply { this.coroutineContext = coroutineContext }

        /**
         * Sets additional information that will be sent via X-MIRACL-CLIENT HTTP header.
         */
        public fun applicationInfo(applicationInfo: String): Builder =
            apply { this.applicationInfo = applicationInfo }

        /**
         * Sets value of device name.
         */
        public fun deviceName(deviceName: String): Builder =
            apply { this.deviceNameValue = deviceName }

        /**
         * Provides implementation of the [HttpRequestExecutor] interface to be used by the SDK.
         */
        public fun httpRequestExecutor(httpRequestExecutor: HttpRequestExecutor): Builder =
            apply { this.httpRequestExecutorValue = httpRequestExecutor }

        /**
         * Provides implementation of the [UserStorage] interface to be used by the SDK.
         */
        public fun userStorage(userStorage: UserStorage): Builder =
            apply { this.userStorage = userStorage }

        /**
         * Provides implementation of the [Logger] interface to be used by the SDK.
         */
        public fun logger(logger: Logger): Builder =
            apply { this.loggerValue = logger }

        /**
         * Provides specific [Logger.LoggingLevel] to be used by the SDK default logger.
         *
         * The default is [Logger.LoggingLevel.NONE]
         * >
         * **Has no effect if using custom logger provided by
         * [logger(logger: Logger)][logger]**
         */
        public fun loggingLevel(loggingLevel: Logger.LoggingLevel): Builder =
            apply { this.loggingLevel = loggingLevel }

        /**
         * Sets HTTP requests connect timeout in seconds to be used by the SDK default [HttpRequestExecutor].
         *
         * The default is 10 seconds.
         * >
         * **Has no effect if using custom HTTP request executor provided by
         * [httpRequestExecutor(httpRequestExecutor: HttpRequestExecutor)][httpRequestExecutor]**
         */
        public fun connectTimeout(connectTimeout: Int): Builder =
            apply { this.connectTimeout = connectTimeout }

        /**
         * Sets HTTP requests read timeout in seconds to be used by the SDK default [HttpRequestExecutor].
         *
         * The default is 10 seconds.
         * >
         * **Has no effect if using custom HTTP request executor provided by
         * [httpRequestExecutor(httpRequestExecutor: HttpRequestExecutor)][httpRequestExecutor]**
         */
        public fun readTimeout(readTimeout: Int): Builder =
            apply { this.readTimeout = readTimeout }

        /** Returns a [com.miracl.trust.configuration.Configuration] object. */
        @Throws(ConfigurationException::class)
        public fun build(): Configuration {
            if (projectId.isBlank()) {
                throw ConfigurationException.EmptyProjectId
            }

            if (!UrlValidator.isValid(projectUrl)) {
                throw ConfigurationException.InvalidProjectUrl
            }

            if (!this::deviceNameValue.isInitialized) {
                deviceNameValue = Build.MODEL
            }

            if (!this::httpRequestExecutorValue.isInitialized) {
                httpRequestExecutorValue =
                    HttpsURLConnectionRequestExecutor(connectTimeout, readTimeout)
            }

            if (!this::loggerValue.isInitialized) {
                val loggingLevel = loggingLevel ?: Logger.LoggingLevel.NONE
                loggerValue = DefaultLogger(loggingLevel)
                this.loggingLevel = loggingLevel
            }

            return Configuration(this)
        }
    }
}