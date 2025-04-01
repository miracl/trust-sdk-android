package com.miracl.trust.utilities

import com.miracl.trust.MIRACLSuccess
import io.jsonwebtoken.Claims
import io.jsonwebtoken.Jws
import io.jsonwebtoken.JwtException
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.Locator
import io.jsonwebtoken.LocatorAdapter
import io.jsonwebtoken.ProtectedHeader
import io.jsonwebtoken.security.JwkSet
import io.jsonwebtoken.security.Jwks
import kotlinx.coroutines.runBlocking
import org.junit.Assert
import java.security.Key

object JwtHelper {
    fun parseSignedClaims(token: String): Jws<Claims> = runBlocking {
        Jwts.parser()
            .keyLocator(getKeyLocator())
            .build()
            .parseSignedClaims(token)
    }

    private suspend fun getKeyLocator(): Locator<Key> {
        val result = MIRACLService.getJwkSet()
        Assert.assertTrue(result is MIRACLSuccess)

        val json = (result as MIRACLSuccess).value
        val jwkSet: JwkSet = Jwks.setParser()
            .build()
            .parse(json)

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