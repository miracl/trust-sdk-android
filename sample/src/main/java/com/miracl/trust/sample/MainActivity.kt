package com.miracl.trust.sample

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.runtime.*
import androidx.core.net.toUri
import com.miracl.trust.sample.ui.theme.MIRACLTrustTheme

class MainActivity : ComponentActivity() {
    private val deepLinkUri = mutableStateOf<Uri?>(null)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()

        deepLinkUri.value = extractVerificationUri(intent)

        setContent {
            MIRACLTrustTheme {
                MIRACLTrustSampleApp(
                    deepLinkUri = deepLinkUri.value,
                    onDeepLinkConsumed = { deepLinkUri.value = null }
                )
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        deepLinkUri.value = extractVerificationUri(intent)
    }

    private fun extractVerificationUri(intent: Intent?): Uri? =
        intent?.data?.takeIf { uri ->
            uri.scheme.equals("https", ignoreCase = true) &&
                    uri.host.equals(BuildConfig.MIRACL_PROJECT_DOMAIN, ignoreCase = true) &&
                    uri.path.orEmpty().startsWith("/verification/confirmation")
        }
}