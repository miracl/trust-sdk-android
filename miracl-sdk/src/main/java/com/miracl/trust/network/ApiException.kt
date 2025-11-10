package com.miracl.trust.network

/** A class hierarchy that describes network issues. */
public sealed class ApiException(public val url: String, cause: Throwable? = null) :
    Exception(cause) {

    /** Error while executing HTTP request. */
    public class ExecutionError internal constructor(url: String = "", cause: Throwable? = null) :
        ApiException(url, cause)

    /** The request response is a client error (4xx). */
    public class ClientError internal constructor(
        public val clientErrorData: ClientErrorData? = null,
        url: String = "",
        cause: Throwable? = null
    ) : ApiException(url, cause)

    /** The request response is a server error (5xx). */
    public class ServerError internal constructor(url: String = "", cause: Throwable? = null) :
        ApiException(url, cause)

    override fun toString(): String {
        return "${this.javaClass.simpleName}(url=$url, cause=$cause)"
    }
}
