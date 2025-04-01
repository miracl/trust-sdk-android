package com.miracl.trust

import com.miracl.trust.model.User
import java.util.UUID
import kotlin.random.Random
import kotlin.random.nextInt
import kotlin.random.nextUInt

fun randomUuidString() = UUID.randomUUID().toString()

fun randomHexString() = Random.nextUInt().toString(16)

fun randomByteArray(size: Int = 20) = Random.nextBytes(size)

fun randomPinLength() = Random.nextInt(4..6)

const val SINGLE_DIGIT_LIMITER = 10
fun randomNumericPin(length: Int): String {
    var pass = ""

    repeat(length) {
        pass += (Random.nextInt(SINGLE_DIGIT_LIMITER))
    }

    return pass
}

fun User.copy(
    userId: String = this.userId,
    projectId: String = this.projectId,
    revoked: Boolean = this.revoked,
    pinLength: Int = this.pinLength,
    mpinId: ByteArray = this.mpinId,
    token: ByteArray = this.token,
    dtas: String = this.dtas,
    publicKey: ByteArray? = this.publicKey
): User = User(userId, projectId, revoked, pinLength, mpinId, token, dtas, publicKey)
