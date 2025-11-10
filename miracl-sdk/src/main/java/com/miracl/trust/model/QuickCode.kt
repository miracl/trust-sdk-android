package com.miracl.trust.model

import java.io.Serializable

/**
 * Object representing QuickCode and its validity period.
 * @property code The issued QuickCode.
 * @property expireTime MIRACL MFA system time when the code will expire.
 * @property ttlSeconds The expiration period in seconds.
 */
public class QuickCode internal constructor(
    public val code: String,
    public val expireTime: Long,
    public val ttlSeconds: Int
) : Serializable {
    override fun toString(): String {
        return "QuickCode(code=<REDACTED>, expireTime=$expireTime, ttlSeconds=$ttlSeconds"
    }
}