package app.privatevpn.ui.screens

import android.content.ActivityNotFoundException
import android.content.Context
import android.content.Intent
import android.os.Build
import android.provider.Settings
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Card
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import app.privatevpn.BuildConfig
import app.privatevpn.core.CoreBridge
import app.privatevpn.ui.InfoRow
import app.privatevpn.ui.LOCKDOWN_HOWTO
import app.privatevpn.ui.ScreenScaffold
import app.privatevpn.ui.openVpnSettings
import app.privatevpn.vpn.PvnVpnService

/** Minimal settings: about/version and Android's own VPN settings (always-on, kill switch). */
@Composable
fun SettingsScreen(onOpenLog: () -> Unit) {
    val context = LocalContext.current
    val status by CoreBridge.status.collectAsStateWithLifecycle()
    val mode by PvnVpnService.systemMode.collectAsStateWithLifecycle()

    ScreenScaffold(title = "Settings") { padding ->
        Column(
            Modifier.fillMaxSize().padding(padding).verticalScroll(rememberScrollState()).padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            SettingsCard("Kill switch (Always-on VPN)") {
                Text(
                    "On Android the kill switch is a system setting. With “Always-on VPN” and “Block connections without VPN” " +
                        "turned on for PrivateVPN, Android blocks every app's traffic outside the VPN — even if PrivateVPN is " +
                        "closed or crashes, and right after the phone restarts, before PrivateVPN has reconnected. Without them, " +
                        "apps use your real IP whenever PrivateVPN is not running.",
                    style = MaterialTheme.typography.bodyMedium,
                )
                Text(
                    when {
                        Build.VERSION.SDK_INT < Build.VERSION_CODES.Q ->
                            "This Android version does not let apps check the setting — open VPN settings to verify it."
                        mode == null -> "Current setting: shown while PrivateVPN is connected."
                        else -> "Current setting: Always-on VPN " + (if (mode?.alwaysOn == true) "on" else "off") +
                            " · Block connections without VPN " + (if (mode?.lockdown == true) "on" else "off")
                    },
                    style = MaterialTheme.typography.bodyMedium,
                    fontWeight = FontWeight.SemiBold,
                    color = if (mode != null && mode?.lockdown != true) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurface,
                )
                Text(LOCKDOWN_HOWTO, style = MaterialTheme.typography.bodyMedium)
                Text(
                    "While PrivateVPN runs it never drops the VPN by itself: if the gateway goes offline, apps stay offline " +
                        "(traffic held) until it is back or you tap Disconnect. After a restart PrivateVPN reconnects to the " +
                        "last gateway by itself if you had not disconnected.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                FilledTonalButton(onClick = { openVpnSettings(context) }) {
                    Text("Open VPN settings")
                }
            }
            SettingsCard("Notifications") {
                Text(
                    "While connected, PrivateVPN shows a notification with a Disconnect button.",
                    style = MaterialTheme.typography.bodyMedium,
                )
                OutlinedButton(onClick = {
                    open(
                        context,
                        Intent(Settings.ACTION_APP_NOTIFICATION_SETTINGS).putExtra(Settings.EXTRA_APP_PACKAGE, context.packageName),
                    )
                }) { Text("Notification settings") }
            }
            SettingsCard("Privacy") {
                Text(
                    "PrivateVPN writes no logs to disk; the log is kept in memory only. Network keys stay on this device " +
                        "and are excluded from backups. Android is a client only — it never acts as a gateway.",
                    style = MaterialTheme.typography.bodyMedium,
                )
                OutlinedButton(onClick = onOpenLog) { Text("View log") }
            }
            SettingsCard("About") {
                InfoRow("App", "PrivateVPN ${BuildConfig.VERSION_NAME} (${BuildConfig.VERSION_CODE})")
                InfoRow("Core", status.version)
            }
        }
    }
}

@Composable
private fun SettingsCard(title: String, content: @Composable () -> Unit) {
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(title, style = MaterialTheme.typography.titleMedium)
            content()
        }
    }
}

private fun open(context: Context, intent: Intent) {
    try {
        context.startActivity(intent)
    } catch (_: ActivityNotFoundException) {
        CoreBridge.post("This device has no such settings page.")
    }
}
