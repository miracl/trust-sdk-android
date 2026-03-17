package com.miracl.trust.network

/**
 * Client error representation which is returned by the MIRACL Trust API.
 *
 * @property code The code of the error.
 * @property info The human-readable representation of the error.
 * @property context Additional information received in the error response.
 */
public class ClientErrorData internal constructor(
    public val code: String,
    public val info: String,
    public val context: Map<String, String>?
) {
    override fun toString(): String {
        return "ClientErrorData(code=$code, info=$info, context=$context)"
    }
}
