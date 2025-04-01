package com.miracl.trust.network

import org.junit.Assert
import org.junit.Test

class ApiSettingsUnitTest {
    @Test
    fun `appendPath successfully appends path to the baseUrl when baseUrl doesn't have trailing slash and path doesn't have leading slash`() {
        val baseUrl = "https://api.base.url"
        val path = "path"
        val expectedResult = "https://api.base.url/path"

        Assert.assertEquals(expectedResult, baseUrl.appendPath(path))
    }

    @Test
    fun `appendPath successfully appends path to the baseUrl when baseUrl has trailing slash and path doesn't have leading slash`() {
        val baseUrl = "https://api.base.url/"
        val path = "path"
        val expectedResult = "https://api.base.url/path"

        Assert.assertEquals(expectedResult, baseUrl.appendPath(path))
    }

    @Test
    fun `appendPath successfully appends path to the baseUrl when baseUrl doesn't have trailing slash and path has leading slash`() {
        val baseUrl = "https://api.base.url"
        val path = "/path"
        val expectedResult = "https://api.base.url/path"

        Assert.assertEquals(expectedResult, baseUrl.appendPath(path))
    }

    @Test
    fun `appendPath successfully appends path to the baseUrl when baseUrl has trailing slash and path has leading slash`() {
        val baseUrl = "https://api.base.url/"
        val path = "/path"
        val expectedResult = "https://api.base.url/path"

        Assert.assertEquals(expectedResult, baseUrl.appendPath(path))
    }
}