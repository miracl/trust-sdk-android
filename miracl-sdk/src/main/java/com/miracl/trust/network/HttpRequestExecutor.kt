package com.miracl.trust.network

import com.miracl.trust.MIRACLError
import com.miracl.trust.MIRACLResult
import com.miracl.trust.MIRACLSuccess

/**
 * HttpRequestExecutor is an interface providing a pluggable networking layer
 * of the MIRACL Trust SDK. If implemented and passed as an argument when initializing the
 * MIRACL Trust SDK, you can provide your own HTTP request executor.
 */
public interface HttpRequestExecutor {

    /**
     * Executes HTTP requests.
     * @param apiRequest Provides the required information for processing the HTTP request.
     * @return MIRACLResult<String, HttpRequestExecutorException> which can be either:
     * - [MIRACLSuccess] with a value of type [String] (the response of the executed request).
     * - [MIRACLError] with a value of type [HttpRequestExecutorException].
     */
    public suspend fun execute(apiRequest: ApiRequest): MIRACLResult<String, HttpRequestExecutorException>
}
