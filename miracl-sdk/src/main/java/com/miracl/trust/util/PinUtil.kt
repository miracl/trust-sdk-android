package com.miracl.trust.util

import com.miracl.trust.delegate.PinProvider
import kotlinx.coroutines.sync.Semaphore

private const val SEMAPHORE_PERMITS = 1
private const val SEMAPHORE_ACQUIRED_PERMITS = 1

internal suspend fun acquirePin(pinProvider: PinProvider): String? {
    val semaphore = Semaphore(SEMAPHORE_PERMITS, SEMAPHORE_ACQUIRED_PERMITS)

    var pinEntered: String? = null

    pinProvider.provide { pin ->
        pinEntered = pin
        semaphore.release()
    }
    semaphore.acquire()

    return pinEntered
}