package com.miracl.trust.signing

import com.miracl.trust.MIRACLTrust
import java.util.Date

/**
 * Result returned from the [MIRACLTrust.generateSignature] method.
 * @property signature The cryptographic representation of the signature.
 * @property timestamp Shows when the document was signed.
 */
public class SigningResult internal constructor(
    public val signature: Signature,
    public val timestamp: Date
) {
    override fun toString(): String {
        return "SigningResult(signature=$signature, timestamp=$timestamp)"
    }
}
