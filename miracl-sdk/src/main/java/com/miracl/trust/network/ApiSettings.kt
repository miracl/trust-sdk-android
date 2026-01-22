package com.miracl.trust.network

import android.net.Uri

internal class ApiSettings {
    companion object {
        const val REGISTER_URL = "/registration"
        const val PASS1_URL = "/rps/v2/pass1"
        const val PASS2_URL = "/rps/v2/pass2"
        const val AUTHENTICATE_URL = "/rps/v2/authenticate"
        const val VERIFICATION_URL = "/verification/email"
        const val QUICK_CODE_VERIFICATION_URL = "/verification/quickcode"
        const val VERIFICATION_CONFIRMATION_URL = "/verification/confirmation"
        const val CODE_STATUS_URL = "/rps/v2/codeStatus"
        const val SIGNING_SESSION_PATH = "/dvs/session"
        const val SIGNING_SESSION_DETAILS_PATH = "/dvs/session/details"
    }

    fun registerUrl(projectUrl: String) =
        projectUrl.appendPath(REGISTER_URL)

    fun pass1Url(projectUrl: String) =
        projectUrl.appendPath(PASS1_URL)

    fun pass2Url(projectUrl: String) =
        projectUrl.appendPath(PASS2_URL)

    fun authenticateUrl(projectUrl: String) =
        projectUrl.appendPath(AUTHENTICATE_URL)

    fun verificationUrl(projectUrl: String) =
        projectUrl.appendPath(VERIFICATION_URL)

    fun quickCodeVerificationUrl(projectUrl: String) =
        projectUrl.appendPath(QUICK_CODE_VERIFICATION_URL)

    fun verificationConfirmationUrl(projectUrl: String) =
        projectUrl.appendPath(VERIFICATION_CONFIRMATION_URL)

    fun codeStatusUrl(projectUrl: String) =
        projectUrl.appendPath(CODE_STATUS_URL)

    fun signingSessionUrl(projectUrl: String) =
        projectUrl.appendPath(SIGNING_SESSION_PATH)

    fun signingSessionDetailsUrl(projectUrl: String) =
        projectUrl.appendPath(SIGNING_SESSION_DETAILS_PATH)
}

internal fun Uri.toProjectUrl(): String {
    val scheme = this.scheme ?: return ""
    val host = this.host ?: return ""

    val newHost = host.replace(".app", ".io")

    return "$scheme://$newHost"
}

internal fun String.appendPath(path: String): String {
    val urlDelimiter = '/'

    return this.trimEnd(urlDelimiter) + urlDelimiter + path.trimStart(urlDelimiter)
}
