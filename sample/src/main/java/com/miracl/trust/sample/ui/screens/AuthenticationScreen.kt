package com.miracl.trust.sample.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import com.miracl.trust.MIRACLError
import com.miracl.trust.MIRACLSuccess
import com.miracl.trust.MIRACLTrust
import com.miracl.trust.authentication.AuthenticationException
import com.miracl.trust.delegate.PinConsumer
import com.miracl.trust.model.User
import kotlinx.coroutines.isActive

@Composable
fun AuthenticationScreen(
    userId: String,
    onSuccess: (String) -> Unit,
    onError: (String) -> Unit,
    onRevoked: (String) -> Unit
) {
    var pinConsumer by remember { mutableStateOf<PinConsumer?>(null) }
    var pinCode by remember { mutableStateOf("") }
    var user by remember { mutableStateOf<User?>(null) }
    var isProcessing by remember { mutableStateOf(false) }

    LaunchedEffect(userId) {
        val targetUser = MIRACLTrust.getInstance().getUser(userId) ?: return@LaunchedEffect
        user = targetUser

        try {
            while (isActive) {
                val result = MIRACLTrust.getInstance().authenticate(
                    user = targetUser,
                    pinProvider = { consumer -> pinConsumer = consumer }
                )

                when (result) {
                    is MIRACLSuccess -> {
                        onSuccess(result.value)
                        break
                    }

                    is MIRACLError -> {
                        if (result.value is AuthenticationException.Revoked) {
                            onRevoked(userId)
                            break
                        } else {
                            onError(result.value.message ?: "Failed to authenticate user")
                            pinCode = ""
                            isProcessing = false
                        }
                    }
                }
            }
        } finally {
            pinConsumer?.consume(null)
            pinConsumer = null
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        val consumer = pinConsumer
        val targetUser = user

        if (consumer != null && targetUser != null) {
            Text(
                text = userId,
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.SemiBold
            )

            Spacer(modifier = Modifier.height(16.dp))

            OutlinedTextField(
                value = pinCode,
                onValueChange = { input ->
                    if (input.length <= targetUser.pinLength && input.all { it.isDigit() }) {
                        pinCode = input
                    }
                },
                modifier = Modifier.fillMaxWidth(),
                label = { Text("Enter PIN") },
                visualTransformation = PasswordVisualTransformation(),
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword),
                singleLine = true,
                enabled = !isProcessing
            )

            Spacer(modifier = Modifier.weight(1f))

            Button(
                enabled = pinCode.length == targetUser.pinLength && !isProcessing,
                onClick = {
                    isProcessing = true
                    val activeConsumer = pinConsumer
                    pinConsumer = null
                    activeConsumer?.consume(pinCode)
                },
                modifier = Modifier.fillMaxWidth()
            ) {
                Text(if (isProcessing) "Authenticating..." else "Authenticate")
            }
        } else {
            Column(
                modifier = Modifier.weight(1f),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.Center
            ) {
                CircularProgressIndicator()

                Spacer(modifier = Modifier.height(16.dp))

                Text(
                    text = "Preparing authentication...",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
    }
}