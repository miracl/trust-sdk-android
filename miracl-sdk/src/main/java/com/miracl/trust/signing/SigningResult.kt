package com.miracl.trust.signing

import com.miracl.trust.MIRACLTrust
import java.util.Date

/**
 * Result returned from [MIRACLTrust.sign] method.
 * @property signature Cryptographic representation of the signature.
 * @property timestamp When the document has been signed.
 */
public class SigningResult internal constructor(
    public val signature: Signature,
    public val timestamp: Date
) {
    override fun toString(): String {
        return "SigningResult(signature=$signature, timestamp=$timestamp)"
    }
}