package com.miracl.trust.crypto

import androidx.annotation.Keep

@Keep
internal data class Pass2Proof(val V: ByteArray) {

    constructor() : this(byteArrayOf())

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as Pass2Proof

        if (!V.contentEquals(other.V)) return false

        return true
    }

    override fun hashCode(): Int {
        return V.contentHashCode()
    }
}
