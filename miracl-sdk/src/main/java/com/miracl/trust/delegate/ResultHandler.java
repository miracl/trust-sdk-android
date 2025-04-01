package com.miracl.trust.delegate;

import androidx.annotation.NonNull;

import com.miracl.trust.MIRACLResult;
import com.miracl.trust.MIRACLSuccess;
import com.miracl.trust.MIRACLError;

/**
 * An interface used to connect MIRACLTrust SDK output to your application.
 *
 * <p>This interface defines the {@link #onResult(MIRACLResult)} method, which handles the result of a MIRACLTrust SDK operation.
 * <b>Important:</b> Implementations of this method will be invoked on the main thread.</p>
 *
 * @param <SUCCESS> type of the value on success.
 * @param <FAIL>    type of the value on failure.
 */
public interface ResultHandler<SUCCESS, FAIL> {
    /**
     * Handles the result of a MIRACLTrust SDK operation.
     *
     * <p><b>Important:</b> The implementation of this method will be invoked on the main thread.</p>
     *
     * @param result The {@link MIRACLResult} containing the result of the SDK operation.
     * It can be either a {@link MIRACLSuccess} or a {@link MIRACLError}.
     */
    void onResult(@NonNull MIRACLResult<SUCCESS, FAIL> result);
}