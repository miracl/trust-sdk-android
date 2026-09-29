package com.miracl.trust.sample.ui.screens

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.Button
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.miracl.trust.MIRACLError
import com.miracl.trust.MIRACLSuccess
import com.miracl.trust.MIRACLTrust
import com.miracl.trust.registration.VerificationException
import kotlinx.coroutines.launch

@Composable
fun RevokedScreen(
    userId: String,
    onEmailSent: (String) -> Unit,
    onError: (String) -> Unit
) {
    var isProcessing by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Spacer(modifier = Modifier.weight(1f))

        Icon(
            imageVector = Icons.Default.Warning,
            contentDescription = null,
            modifier = Modifier.size(64.dp),
            tint = MaterialTheme.colorScheme.error
        )

        Spacer(modifier = Modifier.height(16.dp))

        Text(
            text = "Device disabled",
            style = MaterialTheme.typography.headlineSmall,
            color = MaterialTheme.colorScheme.error,
            fontWeight = FontWeight.Bold,
            textAlign = TextAlign.Center
        )

        Spacer(modifier = Modifier.height(8.dp))

        Text(
            text = userId,
            style = MaterialTheme.typography.titleMedium,
            fontWeight = FontWeight.SemiBold,
            textAlign = TextAlign.Center
        )

        Spacer(modifier = Modifier.height(8.dp))

        Text(
            text = "To re-enable this device, verify your identity again.",
            style = MaterialTheme.typography.bodyMedium,
            textAlign = TextAlign.Center
        )

        Spacer(modifier = Modifier.weight(1f))

        Button(
            enabled = !isProcessing,
            onClick = {
                scope.launch {
                    isProcessing = true
                    when (val result = MIRACLTrust.getInstance().sendVerificationEmail(userId)) {
                        is MIRACLSuccess -> onEmailSent(userId)
                        is MIRACLError -> {
                            val message = when (val exception = result.value) {
                                is VerificationException.RequestBackoff -> {
                                    val currentSeconds = System.currentTimeMillis() / 1000
                                    val remainingSeconds =
                                        (exception.backoff - currentSeconds).coerceAtLeast(1)
                                    "You’ve requested too many verification emails. Try again in $remainingSeconds seconds."
                                }

                                else -> exception.message ?: "Failed to send verification email"
                            }
                            onError(message)
                        }
                    }
                    isProcessing = false
                }
            },
            modifier = Modifier.fillMaxWidth()
        ) {
            Text(if (isProcessing) "Sending..." else "Send Verification Email")
        }
    }
}