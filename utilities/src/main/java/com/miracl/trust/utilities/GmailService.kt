package com.miracl.trust.utilities

import android.content.Context
import android.util.Base64
import android.util.Log
import com.google.api.client.auth.oauth2.BearerToken
import com.google.api.client.auth.oauth2.ClientParametersAuthentication
import com.google.api.client.auth.oauth2.Credential
import com.google.api.client.auth.oauth2.TokenResponse
import com.google.api.client.googleapis.auth.oauth2.GoogleClientSecrets
import com.google.api.client.http.GenericUrl
import com.google.api.client.http.HttpRequestInitializer
import com.google.api.client.http.javanet.NetHttpTransport
import com.google.api.client.json.gson.GsonFactory
import com.google.api.services.gmail.Gmail
import java.nio.charset.StandardCharsets

object GmailService {
    private val TAG = GmailService::class.simpleName

    private const val RETRY_COUNT = 60
    private const val RETRY_TIMEOUT = 10 * 1000L

    private val httpTransport = NetHttpTransport()
    private val gsonFactory = GsonFactory.getDefaultInstance()

    fun getVerificationUrl(
        context: Context,
        userId: String,
        receiver: String,
        timestamp: Long
    ): String? {
        val messageData = getMessageData(context, userId, receiver, timestamp) ?: return null

        val regex =
            """https?://.*/verification/confirmation\?code=([^&]*)&user_id=(\S*)""".toRegex()
        val matchResult = regex.find(messageData)

        return matchResult?.groups?.get(0)?.value
    }

    fun getVerificationCode(
        context: Context,
        userId: String,
        receiver: String,
        timestamp: Long
    ): String? {
        val messageData = getMessageData(context, userId, receiver, timestamp) ?: return null

        val regex = """Type the following code to register your device: (\d{6})""".toRegex()
        val matchResult = regex.find(messageData)

        return matchResult?.groups?.get(1)?.value
    }

    private fun getMessageData(
        context: Context,
        userId: String,
        receiver: String,
        timestamp: Long
    ): String? {
        val gmail = Gmail.Builder(httpTransport, gsonFactory, getCredentials(context)).build()
        var messageData: String? = null

        for (currentRetryCount in 1..RETRY_COUNT) {
            Log.d(TAG, "Getting the email message data attempt: $currentRetryCount")

            val listResponse = gmail.users().messages().list(userId)
                .setQ("from:noreply@trust.miracl.cloud to:$receiver after:${timestamp}")
                .setMaxResults(1)
                .execute()

            val messages = listResponse.messages
            if (messages == null || messages.isEmpty()) {
                Log.d(TAG, "No messages found.")
                Thread.sleep(RETRY_TIMEOUT)
                continue
            }

            val message =
                gmail.users().messages().get(userId, messages.first().id).setFormat("full")
                    .execute()

            messageData = String(
                Base64.decode(message.payload.parts[0].body.data, Base64.URL_SAFE),
                StandardCharsets.UTF_8
            )
            break
        }

        return messageData
    }

    private fun getCredentials(context: Context): HttpRequestInitializer {
        val credentialsInputStream = context.resources.openRawResource(R.raw.credentials)
        val googleClientSecrets =
            gsonFactory.fromInputStream(credentialsInputStream, GoogleClientSecrets::class.java)

        val tokenInputStream = context.resources.openRawResource(R.raw.token)
        val tokenResponse = gsonFactory.fromInputStream(tokenInputStream, TokenResponse::class.java)

        return Credential.Builder(BearerToken.authorizationHeaderAccessMethod())
            .setJsonFactory(gsonFactory)
            .setTransport(httpTransport)
            .setClientAuthentication(
                ClientParametersAuthentication(
                    /* clientId = */ googleClientSecrets.installed.clientId,
                    /* clientSecret = */ googleClientSecrets.installed.clientSecret
                )
            )
            .setTokenServerUrl(GenericUrl(googleClientSecrets.installed.tokenUri))
            .build()
            .setFromTokenResponse(tokenResponse)
    }
}