package app.privatevpnpro.vpn

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

/**
 * Survive restarts: after the phone boots (or the app is updated, which
 * kills the running VPN) reconnect to the last gateway if a session was up
 * and the user had not chosen Disconnect. Only the two protected system
 * broadcasts below are acted on; nothing in the intent is read. See
 * [PvpVpnService.resumeAfterRestart] for the conditions (VPN consent already
 * granted, no always-on VPN — the system starts that one itself).
 *
 * Until the session is back only Android's "Block connections without VPN"
 * keeps apps from using the real IP; the app explains this in Settings.
 */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        when (intent.action) {
            Intent.ACTION_BOOT_COMPLETED, Intent.ACTION_MY_PACKAGE_REPLACED ->
                PvpVpnService.resumeAfterRestart(context)
            else -> Unit
        }
    }
}
