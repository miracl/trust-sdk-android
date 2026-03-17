package com.miracl.trust.delegate;

import androidx.annotation.NonNull;

/**
 * An interface used to allow the MIRACL Trust SDK to request PIN. The application using
 * the SDK is responsible for obtaining the PIN from the user and then passing it
 * to the {@link PinConsumer}.
 */
public interface PinProvider {
    void provide(@NonNull PinConsumer pinConsumer);
}
