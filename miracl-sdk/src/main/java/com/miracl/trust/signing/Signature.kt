package com.miracl.trust.signing

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
public class Signature internal constructor(
    @SerialName("mpinId") public val mpinId: String,
    @SerialName("u") public val U: String,
    @SerialName("v") public val V: String,
    @SerialName("publicKey") public val publicKey: String,
    @SerialName("dtas") public val dtas: String,
    @SerialName("hash") public val hash: String
)