package com.miracl.trust.storage

/** A class for wrapping exceptions thrown from user storage operations. */
public class UserStorageException internal constructor(cause: Throwable) : Exception(cause)