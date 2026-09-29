package com.miracl.trust.sample

import android.net.Uri
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import com.miracl.trust.sample.ui.screens.AuthenticationResultScreen
import com.miracl.trust.sample.ui.screens.AuthenticationScreen
import com.miracl.trust.sample.ui.screens.EmailSentScreen
import com.miracl.trust.sample.ui.screens.EnterUserIdScreen
import com.miracl.trust.sample.ui.screens.HomeScreen
import com.miracl.trust.sample.ui.screens.RegistrationScreen
import com.miracl.trust.sample.ui.screens.RevokedScreen
import kotlinx.coroutines.launch

sealed class Screen(val title: String) {
    data object Home : Screen("MIRACL Trust")
    data class EnterUserId(val userId: String = "") : Screen("Enter User ID")
    data class EmailSent(val userId: String) : Screen("Email Sent")
    data class Registration(val uri: Uri) : Screen("Register Device")
    data class Authentication(val userId: String) : Screen("Authenticate")
    data class AuthenticationResult(val jwtToken: String) : Screen("Authentication Result")
    data class Revoked(val userId: String) : Screen("Disabled")
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun MIRACLTrustSampleApp(
    deepLinkUri: Uri?,
    onDeepLinkConsumed: () -> Unit
) {
    var currentScreen by remember { mutableStateOf<Screen>(Screen.Home) }
    val snackbarHostState = remember { SnackbarHostState() }
    val scope = rememberCoroutineScope()

    val onError: (String) -> Unit = { message ->
        scope.launch { snackbarHostState.showSnackbar(message) }
    }

    LaunchedEffect(deepLinkUri) {
        if (deepLinkUri != null) {
            currentScreen = Screen.Registration(deepLinkUri)
            onDeepLinkConsumed()
        }
    }

    BackHandler(enabled = currentScreen != Screen.Home) {
        currentScreen = Screen.Home
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(currentScreen.title) },
                navigationIcon = {
                    if (currentScreen != Screen.Home && currentScreen !is Screen.AuthenticationResult) {
                        IconButton(onClick = { currentScreen = Screen.Home }) {
                            Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                        }
                    }
                }
            )
        },
        snackbarHost = {
            SnackbarHost(hostState = snackbarHostState, modifier = Modifier.imePadding())
        }
    ) { innerPadding ->
        Box(
            modifier = Modifier
                .padding(innerPadding)
                .fillMaxSize()
                .imePadding()
        ) {
            when (val screen = currentScreen) {
                Screen.Home -> HomeScreen(
                    onRegisterUserId = { currentScreen = Screen.EnterUserId() },
                    onAuthenticateUser = { userId ->
                        currentScreen = Screen.Authentication(userId)
                    },
                    onNavigateToRevoked = { userId -> currentScreen = Screen.Revoked(userId) }
                )

                is Screen.EnterUserId -> EnterUserIdScreen(
                    userId = screen.userId,
                    onEmailSent = { userId -> currentScreen = Screen.EmailSent(userId) },
                    onError = onError
                )

                is Screen.EmailSent -> EmailSentScreen(userId = screen.userId)

                is Screen.Registration -> RegistrationScreen(
                    uri = screen.uri,
                    onSuccess = { jwtToken ->
                        currentScreen = Screen.AuthenticationResult(jwtToken)
                    },
                    onError = onError,
                    onNavigateToResend = { userId -> currentScreen = Screen.EnterUserId(userId) },
                    onNavigateHome = { currentScreen = Screen.Home }
                )

                is Screen.Authentication -> AuthenticationScreen(
                    userId = screen.userId,
                    onSuccess = { jwtToken ->
                        currentScreen = Screen.AuthenticationResult(jwtToken)
                    },
                    onError = onError,
                    onRevoked = { userId -> currentScreen = Screen.Revoked(userId) }
                )

                is Screen.AuthenticationResult -> AuthenticationResultScreen(
                    jwtToken = screen.jwtToken,
                    onDone = { currentScreen = Screen.Home }
                )

                is Screen.Revoked -> RevokedScreen(
                    userId = screen.userId,
                    onEmailSent = { userId -> currentScreen = Screen.EmailSent(userId) },
                    onError = onError
                )
            }
        }
    }
}