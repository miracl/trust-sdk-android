package com.miracl.trust.utilities

import android.util.Base64
import android.util.Log
import com.miracl.trust.BuildConfig
import com.miracl.trust.MIRACLSuccess
import com.miracl.trust.network.ApiRequest
import com.miracl.trust.network.HttpMethod
import com.miracl.trust.network.HttpsURLConnectionRequestExecutor
import com.miracl.trust.util.log.DefaultLogger
import com.miracl.trust.util.log.Logger
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import java.net.URLEncoder

@Serializable
private data class MessageList(val messages: List<Message>)

@Serializable
private data class Message(@SerialName("ID") val id: String)

@Serializable
private data class MessageContent(@SerialName("Text") val text: String)


object MailpitService {
    private val TAG = MailpitService::class.simpleName

    private const val RETRY_COUNT = 60
    private const val RETRY_TIMEOUT = 10 * 1000L

    private val requestExecutor = HttpsURLConnectionRequestExecutor(
        logger = DefaultLogger(Logger.LoggingLevel.NONE),
        connectTimeout = 10,
        readTimeout = 10
    )

    private val json = Json {
        ignoreUnknownKeys = true
    }

    fun getVerificationUrl(
        receiver: String,
        timestamp: Long
    ): String? = runBlocking {
        val messageData = getMessageData(receiver, timestamp) ?: return@runBlocking null

        val regex =
            """https?://.*/verification/confirmation\?code=([^&]*)&user_id=(\S*)""".toRegex()
        val matchResult = regex.find(messageData)

        matchResult?.groups?.get(0)?.value
    }

    fun getVerificationCode(
        receiver: String,
        timestamp: Long
    ): String? = runBlocking {
        val messageData = getMessageData(receiver, timestamp) ?: return@runBlocking null

        val regex = """Type the following code to register your device: (\d{6})""".toRegex()
        val matchResult = regex.find(messageData)

        matchResult?.groups?.get(1)?.value
    }

    private suspend fun getMessageData(receiver: String, timestamp: Long): String? {
        val baseUrl = BuildConfig.MAILPIT_URL
        val query = "from:noreply@trust.miracl.cloud to:$receiver after:$timestamp"
        val credentials = Base64.encodeToString(
            "${BuildConfig.MAILPIT_USER}:${BuildConfig.MAILPIT_PASS}".toByteArray(),
            Base64.NO_WRAP
        )

        val searchRequest = ApiRequest(
            method = HttpMethod.GET,
            headers = mapOf("Authorization" to "Basic $credentials"),
            body = null,
            params = mapOf("query" to URLEncoder.encode(query, "UTF-8")),
            url = "$baseUrl/api/v1/search"
        )

        var messageData: String? = null
        for (currentRetryCount in 1..RETRY_COUNT) {
            Log.d(TAG, "Getting the email message data attempt: $currentRetryCount")

            val messages = requestExecutor.execute(searchRequest) as? MIRACLSuccess ?: return null
            val messagesList = json.decodeFromString<MessageList>(messages.value)
            if (messagesList.messages.isEmpty()) {
                Log.d(TAG, "No messages found.")
                delay(RETRY_TIMEOUT)
                continue
            }

            val messageRequest = ApiRequest(
                method = HttpMethod.GET,
                headers = mapOf("Authorization" to "Basic $credentials"),
                body = null,
                params = null,
                url = "${baseUrl}/api/v1/message/${messagesList.messages.first().id}"
            )

            val msgJson = requestExecutor.execute(messageRequest) as? MIRACLSuccess ?: return null
            val message = json.decodeFromString<MessageContent>(msgJson.value)

            messageData = message.text
            break
        }

        return messageData
    }
}