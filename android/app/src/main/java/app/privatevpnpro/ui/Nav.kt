package app.privatevpnpro.ui

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.List
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.Icon
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import app.privatevpnpro.core.CoreBridge
import app.privatevpnpro.ui.screens.GatewaysScreen
import app.privatevpnpro.ui.screens.KeyringScreen
import app.privatevpnpro.ui.screens.LogScreen
import app.privatevpnpro.ui.screens.SettingsScreen

enum class Dest(val label: String, val icon: ImageVector) {
    Gateways("Gateways", Icons.Filled.Home),
    Keyring("Keys", Icons.Filled.Lock),
    Log("Log", Icons.AutoMirrored.Filled.List),
    Settings("Settings", Icons.Filled.Settings),
}

/** Top-level navigation: the Gateways screen is the start screen (§11.3). */
@Composable
fun PvpApp() {
    var dest by rememberSaveable { mutableStateOf(Dest.Gateways) }
    val snackbar = remember { SnackbarHostState() }
    LaunchedEffect(Unit) {
        CoreBridge.messages.collect { snackbar.showSnackbar(it) }
    }
    BackHandler(enabled = dest != Dest.Gateways) { dest = Dest.Gateways }

    Scaffold(
        contentWindowInsets = WindowInsets(0, 0, 0, 0),
        snackbarHost = { SnackbarHost(snackbar) },
        bottomBar = {
            NavigationBar {
                Dest.entries.forEach { d ->
                    NavigationBarItem(
                        selected = d == dest,
                        onClick = { dest = d },
                        icon = { Icon(d.icon, contentDescription = null) },
                        label = { Text(d.label) },
                    )
                }
            }
        },
    ) { padding ->
        Box(Modifier.fillMaxSize().padding(padding)) {
            when (dest) {
                Dest.Gateways -> GatewaysScreen(onOpenSettings = { dest = Dest.Settings })
                Dest.Keyring -> KeyringScreen()
                Dest.Log -> LogScreen()
                Dest.Settings -> SettingsScreen(onOpenLog = { dest = Dest.Log })
            }
        }
    }
}
