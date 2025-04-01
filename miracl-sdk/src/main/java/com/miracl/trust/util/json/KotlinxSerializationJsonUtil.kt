package com.miracl.trust.util.json

import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

internal object KotlinxSerializationJsonUtil {
    val json = Json {
        encodeDefaults = true
        explicitNulls = false
        ignoreUnknownKeys = true
    }

    inline fun <reified T : Any> fromJsonString(jsonString: String): T {
        return json.decodeFromString(jsonString)
    }

    inline fun <reified T : Any> toJsonString(obj: T): String {
        return json.encodeToString(obj)
    }
}