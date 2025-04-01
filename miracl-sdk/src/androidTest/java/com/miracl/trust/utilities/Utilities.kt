package com.miracl.trust.utilities

import java.util.UUID
import kotlin.random.Random
import kotlin.random.nextInt

const val USER_ID = "int@miracl.com"
const val USER_PIN_LENGTH = 4
const val WRONG_FORMAT_PIN = "FAIL"
const val SINGLE_DIGIT_LIMITER = 10

fun randomNumericPin(length: Int = USER_PIN_LENGTH): String {
    var pass = ""

    repeat(length) {
        pass += (Random.nextInt(SINGLE_DIGIT_LIMITER))
    }

    return pass
}

fun generateWrongPin(correctPin: String): String {
    var wrongPin: String

    do {
        wrongPin = randomNumericPin(correctPin.length)
    } while (wrongPin == correctPin)

    return wrongPin
}

fun getUnixTime() = System.currentTimeMillis() / 1000

fun randomUuidString() = UUID.randomUUID().toString()

fun randomByteArray(size: Int = 20) = Random.nextBytes(size)

fun randomPinLength() = Random.nextInt(4..6)