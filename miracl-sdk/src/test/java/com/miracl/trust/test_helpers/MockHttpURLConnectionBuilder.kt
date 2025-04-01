package com.miracl.trust.test_helpers

import com.miracl.trust.network.HttpURLConnectionBuilder
import java.io.IOException
import java.io.InputStream
import java.net.HttpURLConnection
import java.net.URL

class MockHttpURLConnectionBuilder(
    private val build: (url: URL) -> HttpURLConnection,
) : HttpURLConnectionBuilder {

    constructor(
        statusCode: Int,
        inputStreamProvider: () -> InputStream = { throw IOException() },
        errorStreamProvider: () -> InputStream = { throw IOException() }
    ) : this(build = { url ->
        MockHttpURLConnection(
            url,
            statusCode,
            inputStreamProvider,
            errorStreamProvider
        )
    })

    override fun build(url: URL): HttpURLConnection {
        return build.invoke(url)
    }
}