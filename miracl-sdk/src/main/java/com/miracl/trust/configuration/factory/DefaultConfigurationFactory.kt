package com.miracl.trust.configuration.factory

import com.miracl.trust.MIRACLTrustAuthenticatorApi
import com.miracl.trust.configuration.Configuration

internal class DefaultConfigurationFactory : ConfigurationFactory {
    @OptIn(MIRACLTrustAuthenticatorApi::class)
    override fun create(): Configuration {
        return Configuration.Builder().build()
    }
}