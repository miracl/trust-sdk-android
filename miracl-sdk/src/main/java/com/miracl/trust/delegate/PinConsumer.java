package com.miracl.trust.delegate;

import androidx.annotation.Nullable;

/**
 * An interface used to allow the application, using the MIRACL Trust SDK, to pass the PIN
 * to the SDK.
 */
public interface PinConsumer {
    void consume(@Nullable String pin);
}
