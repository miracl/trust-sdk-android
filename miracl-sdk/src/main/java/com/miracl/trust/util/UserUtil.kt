package com.miracl.trust.util

import com.miracl.trust.model.User
import com.miracl.trust.storage.UserDto

internal fun UserDto.toUser(): User = User(
    userId = userId,
    projectId = projectId,
    revoked = revoked,
    pinLength = pinLength,
    mpinId = mpinId,
    token = token,
    dtas = dtas,
    publicKey = publicKey
)

internal fun User.toUserDto(): UserDto = UserDto(
    userId = userId,
    projectId = projectId,
    revoked = revoked,
    pinLength = pinLength,
    mpinId = mpinId,
    token = token,
    dtas = dtas,
    publicKey = publicKey
)