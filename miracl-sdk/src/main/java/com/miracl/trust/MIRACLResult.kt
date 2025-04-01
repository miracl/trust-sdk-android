package com.miracl.trust

/**
 * MIRACLResult is a class representing the MIRACLTrust SDK responses.
 */
public sealed class MIRACLResult<SUCCESS, FAIL>

/**
 * MIRACLSuccess<SUCCESS, FAIL> is a success response from the MIRACLTrust SDK.
 * It provides a value of type SUCCESS.
 */
public data class MIRACLSuccess<SUCCESS, FAIL>(val value: SUCCESS) : MIRACLResult<SUCCESS, FAIL>()

/**
 * MIRACLError<SUCCESS, FAIL> is an error response from the MIRACLTrust SDK.
 * It provides a value of type FAIL and an optional exception.
 */
public data class MIRACLError<SUCCESS, FAIL>(val value: FAIL) : MIRACLResult<SUCCESS, FAIL>()
