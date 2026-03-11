package com.miracl.trust.configuration.factory

import com.miracl.trust.configuration.Configuration

internal interface ConfigurationFactory {
    fun create(): Configuration
}