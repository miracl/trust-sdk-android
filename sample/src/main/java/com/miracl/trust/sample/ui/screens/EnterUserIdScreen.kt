package com.miracl.trust.sample.ui.screens

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.Button
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import com.miracl.trust.MIRACLError
import com.miracl.trust.MIRACLSuccess
import com.miracl.trust.MIRACLTrust
import com.miracl.trust.registration.VerificationException
import kotlinx.coroutines.launch

@Composable
fun EnterUserIdScreen(
    userId: String,
    onEmailSent: (String) -> Unit,
    onError: (String) -> Unit
) {
    var userId by remember { mutableStateOf(userId) }
    var isProcessing by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        OutlinedTextField(
            value = userId,
            onValueChange = { userId = it },
            modifier = Modifier.fillMaxWidth(),
            label = { Text("User ID (Email)") },
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Email),
            singleLine = true,
            enabled = !isProcessing
        )

        Spacer(modifier = Modifier.weight(1f))

        Button(
            enabled = userId.isNotBlank() && !isProcessing,
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