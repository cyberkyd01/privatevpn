package app.privatevpn.ui

import android.content.ActivityNotFoundException
import android.content.Context
import android.content.Intent
import android.os.Build
import android.provider.Settings
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import app.privatevpn.core.ClientStatus
import app.privatevpn.core.CoreBridge
import app.privatevpn.core.CoreStatus
import app.privatevpn.core.Problem
import app.privatevpn.vpn.SystemVpnMode

/** How a client state looks: OK (protected) … DANGER (blocked / leaking). */
enum class Tone { OK, BUSY, WARN, DANGER, IDLE, INFO }

data class StateLook(val title: String, val text: String, val tone: Tone)

/**
 * The five user-facing states (same wording as the desktop UI). [tunMissing]
 * and [lockdown] keep the "blocked" wording honest: without a VPN interface
 * and without Android's lockdown, nothing is actually holding traffic.
 */
fun clientLook(c: ClientStatus, tunMissing: Boolean, lockdown: Boolean): StateLook {
    val gw = c.gatewayName.ifEmpty { "the gateway" }
    if (c.interrupted && tunMissing && !lockdown) {
        return StateLook(
            "VPN interface lost — traffic may not be protected",
            "Android's VPN interface is gone, so apps may be using your real IP right now. Tap Disconnect, then connect again.",
            Tone.DANGER,
        )
    }
    return when (c.state) {
        "connected" -> if (c.isProtected) {
            StateLook("Protected", "All traffic goes through $gw — websites see the gateway's IP address, not yours.", Tone.OK)
        } else {
            StateLook("Connected — not fully protected", "Connected to $gw, but some traffic may leave outside the VPN. See the problems above.", Tone.WARN)
        }
        "joining", "tunnel_up" -> StateLook(
            "Connecting…",
            if (c.state == "tunnel_up") "Tunnel created — waiting for $gw to answer." else "Contacting $gw…",
            Tone.BUSY,
        )
        "degraded" -> StateLook(
            "Connection interrupted — traffic held, reconnecting",
            "Lost contact with $gw. Your traffic is held inside the VPN, so nothing goes out with your real IP, while PrivateVPN reconnects automatically.",
            Tone.WARN,
        )
        "blocked" -> StateLook(
            "Internet blocked to protect your IP",
            "The connection to $gw failed. Apps stay offline so websites cannot see your real IP. Reconnect, or Disconnect to use the Internet without the VPN.",
            Tone.DANGER,
        )
        else -> StateLook(
            "Not protected",
            "The VPN is off: apps use this phone's own connection and websites see your real IP address.",
            Tone.IDLE,
        )
    }
}

/** Shown wherever Android's lockdown setting is explained. */
const val LOCKDOWN_HOWTO =
    "Open VPN settings → PrivateVPN ⚙ → turn on Always-on VPN and Block connections without VPN. " +
        "Together they also keep the phone protected right after a restart, before PrivateVPN has reconnected."

/**
 * status.problems plus what only Kotlin can see: Android's lockdown setting
 * (the kill switch on Android) and a lost VPN interface. Errors first.
 */
fun problemsFor(status: CoreStatus, mode: SystemVpnMode?, tunMissing: Boolean): List<Problem> {
    val c = status.client
    val out = status.problems.toMutableList()
    val tunnelSession = c.active && c.state != "joining"
    if (tunnelSession && tunMissing) {
        out += if (mode?.lockdown == true) {
            Problem(
                "android_tun_lost", "warning",
                "The VPN interface is down. “Block connections without VPN” keeps apps offline until PrivateVPN reconnects — Disconnect and connect again if this persists.",
                "disconnect",
            )
        } else {
            Problem(
                "android_tun_lost", "error",
                "The VPN interface is down, so apps may be using your real IP right now. Disconnect and connect again.",
                "disconnect",
            )
        }
    }
    if (tunnelSession) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            if (mode != null && !mode.lockdown) {
                out += Problem(
                    "android_lockdown_off", "warning",
                    "Android's “Block connections without VPN” is off. If PrivateVPN is closed or crashes, apps will use your real IP. $LOCKDOWN_HOWTO",
                    Problem.ACTION_VPN_SETTINGS,
                )
            }
        } else {
            out += Problem(
                "android_lockdown_unknown", "info",
                "Check that Android's “Block connections without VPN” is on — this Android version does not let apps verify it. " +
                    "If it is off and PrivateVPN is closed or crashes, apps will use your real IP. $LOCKDOWN_HOWTO",
                Problem.ACTION_VPN_SETTINGS,
            )
        }
    }
    return out.sortedBy { it.rank }
}

/** Container/content colours for a tone (amber is not part of Material 3). */
@Composable
fun toneColors(tone: Tone): Pair<Color, Color> {
    val cs = MaterialTheme.colorScheme
    val dark = isSystemInDarkTheme()
    return when (tone) {
        Tone.OK -> cs.primaryContainer to cs.onPrimaryContainer
        Tone.BUSY -> cs.secondaryContainer to cs.onSecondaryContainer
        Tone.WARN -> if (dark) Color(0xFF4A3300) to Color(0xFFFFDDB0) else Color(0xFFFFE8C2) to Color(0xFF3D2800)
        Tone.DANGER -> cs.errorContainer to cs.onErrorContainer
        Tone.IDLE -> cs.surfaceVariant to cs.onSurfaceVariant
        Tone.INFO -> cs.tertiaryContainer to cs.onTertiaryContainer
    }
}

private fun toneOf(p: Problem) = when (p.severity) {
    "error" -> Tone.DANGER
    "warning" -> Tone.WARN
    else -> Tone.INFO
}

private fun actionLabel(p: Problem, disconnecting: Boolean): String? = when (p.action) {
    "disconnect" -> if (disconnecting) "Disconnecting…" else "Disconnect"
    "reconnect" -> "Reconnect"
    "settings" -> "Open Settings"
    Problem.ACTION_VPN_SETTINGS -> "Open VPN settings"
    else -> null // add_firewall is desktop-only
}

/** The list of problems, most severe first, each with its action button. */
@Composable
fun ProblemsCard(problems: List<Problem>, disconnecting: Boolean, onAction: (Problem) -> Unit) {
    val serious = problems.count { it.severity != "info" }
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Text(
            when {
                serious == 1 -> "1 problem"
                serious > 1 -> "$serious problems"
                problems.size == 1 -> "1 note"
                else -> "${problems.size} notes"
            },
            style = MaterialTheme.typography.labelLarge,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        problems.forEach { p ->
            val (bg, fg) = toneColors(toneOf(p))
            Card(colors = CardDefaults.cardColors(containerColor = bg, contentColor = fg)) {
                Row(Modifier.fillMaxWidth().padding(14.dp), verticalAlignment = Alignment.Top) {
                    Icon(
                        if (p.severity == "info") Icons.Filled.Info else Icons.Filled.Warning,
                        contentDescription = null,
                    )
                    Spacer(Modifier.width(12.dp))
                    Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                        Text(
                            when (p.severity) {
                                "error" -> "Problem"
                                "warning" -> "Warning"
                                else -> "Note"
                            },
                            style = MaterialTheme.typography.labelMedium,
                            fontWeight = FontWeight.Bold,
                        )
                        Text(p.message, style = MaterialTheme.typography.bodyMedium)
                        actionLabel(p, disconnecting)?.let { label ->
                            FilledTonalButton(
                                onClick = { onAction(p) },
                                enabled = !(p.action == "disconnect" && disconnecting),
                                modifier = Modifier.padding(top = 4.dp),
                            ) { Text(label) }
                        }
                    }
                }
            }
        }
    }
}

/** Android's VPN settings list (always-on, "Block connections without VPN"). */
fun openVpnSettings(context: Context) {
    try {
        context.startActivity(Intent(Settings.ACTION_VPN_SETTINGS))
    } catch (_: ActivityNotFoundException) {
        CoreBridge.post("This device has no VPN settings page.")
    }
}
