package com.miracl.trust.network

/**
 * Client error representation which is returned by the MIRACL API.
 *
 * @property code Code of the error.
 * @property info Human readable representation of the error.
 * @property context Additional information received in the error response.
 */
public class ClientErrorData internal constructor(
    public val code: String,
    public val info: String,
    public val context: Map<String, String>?
)
