package com.miracl.trust.test_helpers

import com.miracl.trust.BuildConfig
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.URL
import java.security.cert.Certificate
import javax.net.ssl.HttpsURLConnection

class MockHttpURLConnection(
    u: URL?,
    statusCode: Int,
    private val inputStreamProvider: () -> InputStream = { throw IOException() },
    private val errorStreamProvider: () -> InputStream = { throw IOException() }
) : HttpsURLConnection(u) {

    init {
        if (BuildConfig.DEBUG) {
            responseCode = statusCode
        } else {
            throw IllegalAccessError(
                "MockHttpURLConnection is only meant for Testing Purposes and " +
                        "bound to be used only with DEBUG mode"
            )
        }
    }

    override fun getInputStream(): InputStream {
        return inputStreamProvider()
    }

    override fun getErrorStream(): InputStream {
        return errorStreamProvider()
    }

    override fun getOutputStream(): OutputStream {
        return ByteArrayOutputStream()
    }

    override fun getCipherSuite(): String = ""

    override fun getLocalCertificates(): Array<Certificate> = arrayOf()

    override fun getServerCertificates(): Array<Certificate> = arrayOf()

    override fun connect() {}

    override fun disconnect() {}

    override fun usingProxy(): Boolean = false
}