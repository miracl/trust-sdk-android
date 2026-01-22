package com.miracl.trust.project

import androidx.annotation.Keep
import com.miracl.trust.MIRACLError
import com.miracl.trust.MIRACLSuccess
import com.miracl.trust.network.ApiRequest
import com.miracl.trust.network.ApiRequestExecutor
import com.miracl.trust.network.HttpMethod
import com.miracl.trust.util.json.KotlinxSerializationJsonUtil
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
internal data class ProjectConfiguration(
    @SerialName("customDomain") val projectUrl: String
)

@Keep
internal interface ProjectApi {
    suspend fun getProjectUrl(
        projectId: String
    ): String?
}

internal class ProjectApiManager(
    private val apiRequestExecutor: ApiRequestExecutor,
    private val jsonUtil: KotlinxSerializationJsonUtil
) : ProjectApi {
    override suspend fun getProjectUrl(
        projectId: String
    ): String? {
        try {
            val apiRequest = ApiRequest(
                method = HttpMethod.GET,
                headers = null,
                body = null,
                params = mapOf("id" to projectId),
                url = "https://api.mpin.io/.well-known/project-configuration"
            )

            val result = apiRequestExecutor.execute(apiRequest)
            if (result is MIRACLError) {
                return null
            }

            val projectConfiguration =
                jsonUtil.fromJsonString<ProjectConfiguration>((result as MIRACLSuccess).value)

            return projectConfiguration.projectUrl
        } catch (ex: Exception) {
            return null
        }
    }
}
