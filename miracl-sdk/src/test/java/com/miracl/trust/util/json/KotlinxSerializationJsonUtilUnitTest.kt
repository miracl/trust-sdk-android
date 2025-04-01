package com.miracl.trust.util.json

import com.miracl.trust.authentication.AuthenticateRequestBody
import com.miracl.trust.authentication.AuthenticateResponse
import com.miracl.trust.randomUuidString
import com.miracl.trust.registration.ConfirmationResponse
import kotlinx.serialization.SerializationException
import org.junit.Assert
import org.junit.Test

class KotlinxSerializationJsonUtilUnitTest {
    private val jsonUtil = KotlinxSerializationJsonUtil

    @Test
    fun `fromJsonString should return an object of the passed type when json string is valid`() {
        // Arrange
        val expectedProjectId = randomUuidString()
        val expectedActivateToken = randomUuidString()
        val expectedAccessId = randomUuidString()
        val jsonString = """
            {
              "projectId": "$expectedProjectId",
              "actToken": "$expectedActivateToken",
              "accessId": "$expectedAccessId"
            }
        """.trimIndent()

        // Act
        val result = jsonUtil.fromJsonString<ConfirmationResponse>(jsonString)

        // Assert
        Assert.assertEquals(expectedProjectId, result.projectId)
        Assert.assertEquals(expectedActivateToken, result.activateToken)
        Assert.assertEquals(expectedAccessId, result.accessId)
    }

    @Test
    fun `fromJsonString should not throw and should return an object of the passed type when json string has more properties than the object has`() {
        // Arrange
        val expectedProjectId = randomUuidString()
        val expectedActivateToken = randomUuidString()
        val expectedAccessId = randomUuidString()
        val jsonString = """
            {
              "projectId": "$expectedProjectId",
              "actToken": "$expectedActivateToken",
              "accessId": "$expectedAccessId",
              "dtas": "${randomUuidString()}"
            }
        """.trimIndent()

        // Act
        val result = jsonUtil.fromJsonString<ConfirmationResponse>(jsonString)

        // Assert
        Assert.assertEquals(expectedProjectId, result.projectId)
        Assert.assertEquals(expectedActivateToken, result.activateToken)
        Assert.assertEquals(expectedAccessId, result.accessId)
    }

    @Test
    fun `fromJsonString treat the absence of a field value as null for nullable properties without a default value`() {
        // Arrange
        val expectedStatus = 200
        val expectedMessage = "OK"
        val jsonString = """
            {"status":"$expectedStatus","message":"$expectedMessage"}
        """.trimIndent()

        // Act
        val result = jsonUtil.fromJsonString<AuthenticateResponse>(jsonString)

        // Assert
        Assert.assertEquals(expectedStatus, result.status)
        Assert.assertEquals(expectedMessage, result.message)
        Assert.assertEquals(null, result.renewSecretResponse)
    }

    @Test(expected = SerializationException::class)
    fun `fromJsonString should throw exception when jsonString is not valid`() {
        // Arrange
        val expectedProjectId = randomUuidString()
        val expectedActivateToken = randomUuidString()
        val expectedAccessId = randomUuidString()
        val jsonString = """
            {
              "projectId": "$expectedProjectId,
              "actToken": "$expectedActivateToken",
              "accessId": "$expectedAccessId"
            }
        """.trimIndent()

        // Act
        jsonUtil.fromJsonString<ConfirmationResponse>(jsonString)
    }

    @Test(expected = SerializationException::class)
    fun `fromJsonString should throw exception when jsonString contains a required string property with a null value`() {
        // Arrange
        val expectedProjectId = randomUuidString()
        val expectedAccessId = randomUuidString()
        val jsonString = """
            {
              "projectId": "$expectedProjectId",
              "actToken":,
              "accessId": "$expectedAccessId"
            }
        """.trimIndent()

        // Act
        jsonUtil.fromJsonString<ConfirmationResponse>(jsonString)
    }

    @Test(expected = SerializationException::class)
    fun `fromJsonString should throw exception when jsonString is empty or blank`() {
        // Arrange
        val jsonString = """

        """.trimIndent()

        // Act
        jsonUtil.fromJsonString<ConfirmationResponse>(jsonString)
    }

    @Test
    fun `toJsonString should return a valid json string of the passed type`() {
        // Arrange
        val expectedProjectId = randomUuidString()
        val expectedActivateToken = randomUuidString()
        val expectedAccessId = randomUuidString()
        val confirmationResponse =
            ConfirmationResponse(
                projectId = expectedProjectId,
                activateToken = expectedActivateToken,
                accessId = expectedAccessId
            )
        val expectedJsonString = """
            {"projectId":"$expectedProjectId","actToken":"$expectedActivateToken","accessId":"$expectedAccessId"}
        """.trimIndent()

        // Act
        val result = jsonUtil.toJsonString(confirmationResponse)

        // Assert
        Assert.assertEquals(expectedJsonString, result)
    }

    @Test
    fun `toJsonString should encode default values`() {
        // Arrange
        val expectedAuthOTT = randomUuidString()
        val expectedWam = "dvs"
        val authenticateRequest = AuthenticateRequestBody(expectedAuthOTT)
        val expectedJsonString = """
            {"authOTT":"$expectedAuthOTT","wam":"$expectedWam"}
        """.trimIndent()

        // Act
        val result = jsonUtil.toJsonString(authenticateRequest)

        // Assert
        Assert.assertEquals(expectedJsonString, result)
    }
}
