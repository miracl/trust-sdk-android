package com.miracl.trust.util.log

import com.miracl.trust.MIRACLTrust

internal interface Loggable {
    val logger: Logger?
        get() = MIRACLTrust.logger
}