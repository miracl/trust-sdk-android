package com.miracl.trust.network

/***
 * HttpMethod is a MIRACLTrust SDK representation of the HTTP methods
 */
public enum class HttpMethod(public val method: String) {
    GET("GET"),
    POST("POST"),
    PUT("PUT"),
    DELETE("DELETE")
}

/***
 * ApiRequest is a data class that keeps the main properties of a HTTP request.
 */
public data class ApiRequest(
    val method: HttpMethod,
    val headers: Map<String, String>?,
    val body: String?,
    val params: Map<String, String>?,
    val url: String
)
