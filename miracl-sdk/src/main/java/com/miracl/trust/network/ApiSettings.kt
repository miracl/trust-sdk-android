package com.miracl.trust.network

internal class ApiSettings(platformUrl: String) {
    companion object {
        const val SIGNATURE_PATH = "/rps/v2/signature"
        const val REGISTER_URL = "/rps/v2/user"
        const val PASS1_URL = "/rps/v2/pass1"
        const val PASS2_URL = "/rps/v2/pass2"
        const val AUTHENTICATE_URL = "/rps/v2/authenticate"
        const val DVS_REG_URL = "/rps/v2/dvsregister"
        const val VERIFICATION_URL = "/verification/email"
        const val QUICK_CODE_VERIFICATION_URL = "/verification/quickcode"
        const val VERIFICATION_CONFIRMATION_URL = "/verification/confirmation"
        const val CODE_STATUS_URL = "/rps/v2/codeStatus"
        const val SIGNING_SESSION_PATH = "/dvs/session"
        const val SIGNING_SESSION_DETAILS_PATH = "/dvs/session/details"
    }

    val signatureUrl = platformUrl.appendPath(SIGNATURE_PATH)

    val registerUrl = platformUrl.appendPath(REGISTER_URL)

    val pass1Url = platformUrl.appendPath(PASS1_URL)

    val pass2Url = platformUrl.appendPath(PASS2_URL)

    val authenticateUrl = platformUrl.appendPath(AUTHENTICATE_URL)

    val dvsRegUrl = platformUrl.appendPath(DVS_REG_URL)

    val verificationUrl = platformUrl.appendPath(VERIFICATION_URL)

    val quickCodeVerificationUrl = platformUrl.appendPath(QUICK_CODE_VERIFICATION_URL)

    val verificationConfirmationUrl = platformUrl.appendPath(VERIFICATION_CONFIRMATION_URL)

    val codeStatusUrl = platformUrl.appendPath(CODE_STATUS_URL)

    val signingSessionUrl = platformUrl.appendPath(SIGNING_SESSION_PATH)

    val signingSessionDetailsUrl = platformUrl.appendPath(SIGNING_SESSION_DETAILS_PATH)
}

internal fun String.appendPath(path: String): String {
    val urlDelimiter = '/'

    return this.trimEnd(urlDelimiter) + urlDelimiter + path.trimStart(urlDelimiter)
}
