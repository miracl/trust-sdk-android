package com.miracl.trust.util

import java.net.MalformedURLException
import java.net.URL

internal object UrlValidator {
    fun isValid(url: String): Boolean {
        return try {
            URL(url)
            true
        } catch (_: MalformedURLException) {
            false
        }
    }
}