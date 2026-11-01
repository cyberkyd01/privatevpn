package app.privatevpnpro.ui.screens

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
import app.privatevpnpro.BuildConfig
import app.privatevpnpro.core.CoreBridge
import app.privatevpnpro.ui.InfoRow
import app.privatevpnpro.ui.LOCKDOWN_HOWTO
import app.privatevpnpro.ui.ScreenScaffold
import app.privatevpnpro.ui.openVpnSettings
import app.privatevpnpro.vpn.PvpVpnService

/** Minimal settings: about/version and Android's own VPN settings (always-on, kill switch). */
@Composable
fun SettingsScreen(onOpenLog: () -> Unit) {
    val context = LocalContext.current
    val status by CoreBridge.status.collectAsStateWithLifecycle()
    val mode by PvpVpnService.systemMode.collectAsStateWithLifecycle()

    ScreenScaffold(title = "Settings") { padding ->
        Column(
            Modifier.fillMaxSize().padding(padding).verticalScroll(rememberScrollState()).padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            SettingsCard("Kill switch (Always-on VPN)") {
                Text(
                    "On Android the kill switch is a system setting. With “Always-on VPN” and “Block connections without VPN” " +
                        "turned on for Private VPN Pro, Android blocks every app's traffic outside the VPN — even if Private VPN Pro is " +
                        "closed or crashes, and right after the phone restarts, before Private VPN Pro has reconnected. Without them, " +
                        "apps use your real IP whenever Private VPN Pro is not running.",
                    style = MaterialTheme.typography.bodyMedium,
                )
                Text(
                    when {
                        Build.VERSION.SDK_INT < Build.VERSION_CODES.Q ->
                            "This Android version does not let apps check the setting — open VPN settings to verify it."
                        mode == null -> "Current setting: shown while Private VPN Pro is connected."
                        else -> "Current setting: Always-on VPN " + (if (mode?.alwaysOn == true) "on" else "off") +
                            " · Block connections without VPN " + (if (mode?.lockdown == true) "on" else "off")
                    },
                    style = MaterialTheme.typography.bodyMedium,
                    fontWeight = FontWeight.SemiBold,
                    color = if (mode != null && mode?.lockdown != true) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurface,
                )
                Text(LOCKDOWN_HOWTO, style = MaterialTheme.typography.bodyMedium)
                Text(
                    "While Private VPN Pro runs it never drops the VPN by itself: if the gateway goes offline, apps stay offline " +
                        "(traffic held) until it is back or you tap Disconnect. After a restart Private VPN Pro reconnects to the " +
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
                    "While connected, Private VPN Pro shows a notification with a Disconnect button.",
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
                    "Private VPN Pro writes no logs to disk; the log is kept in memory only. Network keys stay on this device " +
                        "and are excluded from backups. Android is a client only — it never acts as a gateway.",
                    style = MaterialTheme.typography.bodyMedium,
                )
                OutlinedButton(onClick = onOpenLog) { Text("View log") }
            }
            SettingsCard("About") {
                InfoRow("App", "Private VPN Pro ${BuildConfig.VERSION_NAME} (${BuildConfig.VERSION_CODE})")
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
