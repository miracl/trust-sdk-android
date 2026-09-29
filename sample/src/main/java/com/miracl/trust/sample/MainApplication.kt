package com.miracl.trust.sample

import android.app.Application
import com.miracl.trust.MIRACLTrust
import com.miracl.trust.configuration.Configuration
import com.miracl.trust.configuration.ConfigurationException

class MainApplication : Application() {

    override fun onCreate() {
        super.onCreate()

        try {
            val configuration = Configuration
                .Builder(
                    projectId = BuildConfig.MIRACL_PROJECT_ID,
                    projectUrl = "https://${BuildConfig.MIRACL_PROJECT_DOMAIN}"
                )
                .build()

            MIRACLTrust.configure(this, configuration)
        } catch (e: ConfigurationException) {
            val hint = when (e) {
                ConfigurationException.EmptyProjectId ->
                    "Project ID is missing. Set 'miracl.projectId' in sample/local.properties."

                ConfigurationException.InvalidProjectUrl ->
                    "Project Domain is invalid. Set 'miracl.projectDomain' in sample/local.properties."
            }

            throw IllegalStateException(
                "MIRACL Trust SDK Configuration Error: $hint\n" +
                        "Please copy 'sample/local.properties.example' to 'sample/local.properties'.",
                e
            )
        }
    }
}