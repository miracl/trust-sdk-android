package com.miracl.trust.network

/** A class hierarchy that describes network issues. */
public sealed class HttpRequestExecutorException(
    message: String? = null,
    cause: Throwable? = null
) : Exception(message, cause) {

    /** The server responded with an HTTP error. */
    public class HttpError(public val responseCode: Int, public val responseBody: String) :
        HttpRequestExecutorException()

    /** Error while executing HTTP request. */
    public class ExecutionError(message: String? = null, cause: Throwable? = null) :
        HttpRequestExecutorException(message = message, cause = cause)
}
