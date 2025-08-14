package com.miracl.trust.util.log

internal object LoggerConstants {
    internal const val VERIFICATOR_TAG = "Verificator"
    internal const val REGISTRATOR_TAG = "Registrator"
    internal const val AUTHENTICATOR_TAG = "Authenticator"
    internal const val DOCUMENT_SIGNER_TAG = "DocumentSigner"
    internal const val SESSION_MANAGER_TAG = "SessionManager"
    internal const val SIGNING_SESSION_MANAGER_TAG = "SigningSessionManager"
    internal const val CROSS_DEVICE_SESSION_MANAGER_TAG = "CrossDeviceSessionManager"

    internal const val FLOW_STARTED = "Flow started."
    internal const val FLOW_FINISHED = "Flow finished."
    internal const val FLOW_ERROR = "Flow finished with error = %s"

    internal const val CRYPTO_TAG = "Crypto"
    internal const val CRYPTO_OPERATION_STARTED = "Crypto operation %s has started."
    internal const val CRYPTO_OPERATION_FINISHED = "Crypto operation %s has finished."

    internal const val NETWORK_TAG = "Network"
    internal const val NETWORK_REQUEST = "%s %s"
    internal const val NETWORK_RESPONSE = "%s %s Status code: %d %s"

    object VerificatorOperations {
        internal const val VERIFY_REQUEST = "Executing verify request."
        internal const val QUICK_CODE_REQUEST = "Executing QuickCode request"
        internal const val ACTIVATION_TOKEN_REQUEST = "Executing activation token request."
    }

    object RegistratorOperations {
        internal const val REGISTER_REQUEST = "Executing register request."
        internal const val SIGNING_KEY_PAIR = "Getting signing key pair."
        internal const val DVS_CLIENT_SECRET_REQUESTS = "Executing DVS client secret requests."
        internal const val SIGNING_CLIENT_TOKEN = "Getting signing client token."
        internal const val SAVING_USER = "Saving user to the database."
        internal const val UPDATING_EXISTING_USER = "Updating the existing user."
    }

    object AuthenticatorOperations {
        internal const val UPDATE_SESSION_STATUS = "Executing update session status request."
        internal const val CLIENT_PASS_1_PROOF = "Getting client pass proof 1."
        internal const val CLIENT_PASS_1_REQUEST = "Execute pass 1 request."
        internal const val CLIENT_PASS_2_PROOF = "Getting client pass proof 2."
        internal const val CLIENT_PASS_2_REQUEST = "Executing pass 2 request."
        internal const val AUTHENTICATE_REQUEST = "Executing authenticate request."
        internal const val RENEW_SECRET_STARTED = "Secrets renewal for user started."
        internal const val RENEW_SECRET_FINISHED = "Secrets renewal for user finished."
        internal const val RENEW_SECRET_AUTHENTICATE = "Authenticate with the new user secrets."
        internal const val RENEW_SECRET_ERROR = "Secrets renewal for user finished with error."
        internal const val REVOKE_USER_ERROR = "User revocation finished with error = %s"
    }

    object DocumentSignerOperations {
        internal const val SIGNING = "Signing."
        internal const val UPDATE_SIGNING_SESSION_REQUEST =
            "Executing update signing session request."
        internal const val UPDATE_CROSS_DEVICE_SESSION_REQUEST =
            "Executing update cross-device session request."
    }

    object SessionManagementOperations {
        internal const val CODE_STATUS_REQUEST = "Executing code status request."
        internal const val ABORT_SESSION_REQUEST = "Executing abort session request."
    }

    object SigningSessionManagementOperations {
        internal const val SESSION_DETAILS_REQUEST = "Executing signing session details request."
        internal const val ABORT_SESSION_REQUEST = "Executing abort signing session request."
    }
}