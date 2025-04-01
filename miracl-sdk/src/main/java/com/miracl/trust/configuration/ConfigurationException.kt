package com.miracl.trust.configuration

/** A class hierarchy that describes issues with the SDK configuration. */
public sealed class ConfigurationException : Exception() {

    /** Empty project ID. */
    public object EmptyProjectId : ConfigurationException()
}
