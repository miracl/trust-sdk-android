package com.miracl.trust.sample

import android.app.Application
import com.miracl.trust.MIRACLTrust
import com.miracl.trust.configuration.Configuration

class MainApplication : Application() {

    override fun onCreate() {
        super.onCreate()

        val projectId = BuildConfig.MIRACL_PROJECT_ID.trim()
        check(projectId.isNotBlank() && projectId != "YOUR_PROJECT_ID") {
            "Set your miracl.projectId in sample/config.properties"
        }

        val projectDomain = BuildConfig.MIRACL_PROJECT_DOMAIN.trim()
        check(projectDomain.isNotBlank() && projectDomain != "YOUR_PROJECT_DOMAIN") {
            "Set your miracl.projectDomain in sample/config.properties"
        }

        val configuration = Configuration
            .Builder(
                projectId = projectId,
                projectUrl = "https://$projectDomain"
            )
            .build()

        MIRACLTrust.configure(this, configuration)
    }
}