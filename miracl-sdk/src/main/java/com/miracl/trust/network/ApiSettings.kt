package com.miracl.trust.network

internal class ApiSettings(var projectUrl: String) {
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

    val registerUrl
        get() = projectUrl.appendPath(REGISTER_URL)

    val pass1Url
        get() = projectUrl.appendPath(PASS1_URL)

    val pass2Url
        get() = projectUrl.appendPath(PASS2_URL)

    val authenticateUrl
        get() = projectUrl.appendPath(AUTHENTICATE_URL)

    val verificationUrl
        get() = projectUrl.appendPath(VERIFICATION_URL)

    val quickCodeVerificationUrl
        get() = projectUrl.appendPath(QUICK_CODE_VERIFICATION_URL)

    val verificationConfirmationUrl
        get() = projectUrl.appendPath(VERIFICATION_CONFIRMATION_URL)

    val codeStatusUrl
        get() = projectUrl.appendPath(CODE_STATUS_URL)

    val signingSessionUrl
        get() = projectUrl.appendPath(SIGNING_SESSION_PATH)

    val signingSessionDetailsUrl
        get() = projectUrl.appendPath(SIGNING_SESSION_DETAILS_PATH)
}

internal fun String.appendPath(path: String): String {
    val urlDelimiter = '/'

    return this.trimEnd(urlDelimiter) + urlDelimiter + path.trimStart(urlDelimiter)
}
