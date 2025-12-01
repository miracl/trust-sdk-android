package com.miracl.trust.utilities

import io.jsonwebtoken.Claims
import io.jsonwebtoken.Jws
import io.jsonwebtoken.JwtException
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.Locator
import io.jsonwebtoken.LocatorAdapter
import io.jsonwebtoken.ProtectedHeader
import io.jsonwebtoken.security.JwkSet
import io.jsonwebtoken.security.Jwks
import java.security.Key

object JwtHelper {
    fun parseSignedClaims(token: String, jwks: String): Jws<Claims> {
        return Jwts.parser()
            .keyLocator(getKeyLocator(jwks))
            .build()
            .parseSignedClaims(token)
    }


    private fun getKeyLocator(jwks: String): Locator<Key> {
        val jwkSet: JwkSet = Jwks.setParser()
            .build()
            .parse(jwks)

        val keyLocator = object : LocatorAdapter<Key>() {
            override fun locate(header: ProtectedHeader?): Key {
                jwkSet.getKeys().forEach { jwk ->
                    if (header == null || jwk.id == header.keyId) {
                        return jwk.toKey()
                    }
                }

                throw JwtException("Can't locate the key.")
            }
        }

        return keyLocator
    }
}