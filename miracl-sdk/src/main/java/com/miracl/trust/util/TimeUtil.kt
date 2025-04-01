package com.miracl.trust.util

import java.util.*

internal fun getCurrentTimeUnixTimestamp(): Long {
    return Date().time / 1000
}

internal fun Date.secondsSince1970(): Int =
    (this.time / 1000).toInt()
