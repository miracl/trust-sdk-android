package com.miracl.trust.storage

public class UserDto(
    public val userId: String,
    public val projectId: String,
    public val revoked: Boolean,
    public val pinLength: Int,
    public val mpinId: ByteArray,
    public val token: ByteArray,
    public val dtas: String,
    public val publicKey: ByteArray?
)
