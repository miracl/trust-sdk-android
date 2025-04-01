package com.miracl.trust.network

import com.miracl.trust.MIRACLResult

/**
 * HttpRequestExecutor is an interface providing pluggable networking layer
 * of the MIRACLTrust SDK. If implemented and passed as an argument when initializing the
 * MIRACLTrust SDK, you can provide your own HTTP request executor.
 */
public interface HttpRequestExecutor {

    /**
     * Executes HTTP requests.
     * @param apiRequest provides the required information for processing the HTTP request.
     * @return MIRACLResult<String, HttpRequestExecutorException> which can be either:
     * - MIRACLSuccess with value of type [String] (the response of the executed request)
     * - MIRACLError with value of type [HttpRequestExecutorException].
     */
    public suspend fun execute(apiRequest: ApiRequest): MIRACLResult<String, HttpRequestExecutorException>
}
