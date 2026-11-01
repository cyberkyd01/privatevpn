package app.privatevpnpro.ui

import android.Manifest
import android.app.Activity
import android.content.Context
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.platform.LocalContext
import androidx.core.content.ContextCompat
import androidx.core.content.edit
import app.privatevpnpro.core.CoreBridge
import app.privatevpnpro.vpn.PvpVpnService

private const val PREFS = "ui"
private const val KEY_NOTIF_ASKED = "notifications_asked"

/**
 * The verified-gateway half of the §11.3 connect flow:
 * `VpnService.prepare` consent → POST_NOTIFICATIONS (first connect, 13+) →
 * `startForegroundService(PvpVpnService, gateway_id)`; the service then calls
 * `client.connect`. Locked gateways go through KeyEntrySheet first.
 *
 * Returns `connect(gatewayId, gatewayName)`.
 */
@Composable
fun rememberConnectFlow(): (String, String) -> Unit {
    val context = LocalContext.current
    var pendingId by rememberSaveable { mutableStateOf<String?>(null) }
    var pendingName by rememberSaveable { mutableStateOf("") }

    fun startService() {
        val id = pendingId ?: return
        pendingId = null
        PvpVpnService.connect(context, id, pendingName)
    }

    val notificationLauncher = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) {
        // Denied is fine: the service runs without a visible notification.
        startService()
    }

    fun afterConsent() {
        val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED &&
            !prefs.getBoolean(KEY_NOTIF_ASKED, false)
        ) {
            prefs.edit { putBoolean(KEY_NOTIF_ASKED, true) }
            notificationLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
        } else {
            startService()
        }
    }

    val consentLauncher = rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) { r ->
        if (r.resultCode == Activity.RESULT_OK) {
            afterConsent()
        } else {
            pendingId = null
            CoreBridge.post("Private VPN Pro needs the VPN permission to connect.")
        }
    }

    return { id, name ->
        pendingId = id
        pendingName = name
        val consent = try {
            VpnService.prepare(context)
        } catch (_: RuntimeException) {
            null
        }
        if (consent != null) consentLauncher.launch(consent) else afterConsent()
    }
}
