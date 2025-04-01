package com.miracl.trust.util

import java.security.MessageDigest

internal fun ByteArray.toSHA256(): String {
    return MessageDigest
        .getInstance("SHA-256")
        .digest(this)
        .toHexString()
}