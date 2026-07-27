package com.miracl.trust.session

/**
 * Represents the type of [CrossDeviceSession].
 *
 * Use this enum to determine the appropriate flow when handling the session.
 */
public enum class CrossDeviceSessionType {
    /** Indicates an authentication session. */
    Authentication,

    /** Indicates a signing session. */
    Signing
}
