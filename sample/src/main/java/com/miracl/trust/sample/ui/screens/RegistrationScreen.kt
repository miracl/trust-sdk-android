package com.miracl.trust.sample.ui.screens

import android.net.Uri
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
import com.miracl.trust.delegate.PinConsumer
import com.miracl.trust.registration.ActivationTokenException

@Composable
fun RegistrationScreen(
    uri: Uri,
    onSuccess: (String) -> Unit,
    onError: (String) -> Unit,
    onNavigateToResend: (userId: String) -> Unit,
    onNavigateHome: () -> Unit
) {
    var pinConsumer by remember { mutableStateOf<PinConsumer?>(null) }
    var pinCode by remember { mutableStateOf("") }
    var userId by remember { mutableStateOf("") }
    var isProcessing by remember { mutableStateOf(false) }

    LaunchedEffect(uri) {
        val miraclTrust = MIRACLTrust.getInstance()
        try {
            // Step 1: Extract Token
            val tokenResult = miraclTrust.getActivationToken(uri)
            if (tokenResult is MIRACLError) {
                when (val exception = tokenResult.value) {
                    is ActivationTokenException.UnsuccessfulVerification -> {
                        val userId = exception.activationTokenErrorResponse?.userId
                        if (userId != null) {
                            onError("Verification link expired for $userId. Please request a new link.")
                            onNavigateToResend(userId)
                        } else {
                            onError("Invalid or expired verification link.")
                            onNavigateHome()
                        }
                    }

                    else -> {
                        onError(exception.message ?: "Failed to process verification link.")
                        onNavigateHome()
                    }
                }
                return@LaunchedEffect
            }
            val response = (tokenResult as MIRACLSuccess).value
            userId = response.userId

            // Step 2: Register Device
            val regResult = miraclTrust.register(
                userId = response.userId,
                activationToken = response.activationToken,
                pinProvider = { consumer -> pinConsumer = consumer }
            )
            if (regResult is MIRACLError) {
                onError(regResult.value.message ?: "Failed to complete registration")
                return@LaunchedEffect
            }
            val registeredUser = (regResult as MIRACLSuccess).value

            // Step 3: Initial Authentication
            val authResult = miraclTrust.authenticate(
                user = registeredUser,
                pinProvider = { consumer -> consumer.consume(pinCode) }
            )

            when (authResult) {
                is MIRACLSuccess -> onSuccess(authResult.value)
                is MIRACLError -> onError(authResult.value.message ?: "Failed to authenticate user")
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

        if (consumer != null) {
            if (userId.isNotEmpty()) {
                Text(
                    text = userId,
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold
                )

                Spacer(modifier = Modifier.height(16.dp))
            }

            OutlinedTextField(
                value = pinCode,
                onValueChange = { input ->
                    if (input.all { it.isDigit() }) pinCode = input
                },
                modifier = Modifier.fillMaxWidth(),
                label = { Text("Choose PIN") },
                visualTransformation = PasswordVisualTransformation(),
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword),
                singleLine = true,
                enabled = !isProcessing
            )

            Spacer(modifier = Modifier.weight(1f))

            Button(
                enabled = pinCode.isNotBlank() && !isProcessing,
                onClick = {
                    isProcessing = true
                    val activeConsumer = pinConsumer
                    pinConsumer = null
                    activeConsumer?.consume(pinCode)
                },
                modifier = Modifier.fillMaxWidth()
            ) {
                Text(if (isProcessing) "Registering..." else "Register")
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
                    text = "Processing verification link...",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
    }
}