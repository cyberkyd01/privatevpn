@file:OptIn(ExperimentalMaterial3Api::class)

package app.privatevpnpro.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.ModalBottomSheetDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.SideEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import app.privatevpnpro.core.Access
import app.privatevpnpro.core.CoreBridge
import app.privatevpnpro.core.CoreException
import app.privatevpnpro.core.Gateway
import app.privatevpnpro.core.GatewayInfo
import app.privatevpnpro.core.Untrusted
import app.privatevpnpro.ui.Format
import app.privatevpnpro.ui.InfoRow
import app.privatevpnpro.ui.Section
import app.privatevpnpro.ui.Tag
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import org.json.JSONObject
import java.util.Locale
import kotlin.math.abs

private const val INFO_REFRESH_MS = 30_000L

/**
 * The ⓘ panel (§10, §11.3). Members: everything INFO carries, refreshed
 * every 30 s while open, with a live gateway-local clock (§10.6). Locked:
 * only the public beacon fields, the word "unverified" and key entry; no
 * INFO request is made.
 */
@Composable
fun GatewayDetailsSheet(gatewayId: String, onDismiss: () -> Unit, onConnect: (Gateway) -> Unit) {
    val gateways by CoreBridge.gateways.collectAsStateWithLifecycle()
    // A manual entry is listed as "m-<uuid>" until its public key is learned
    // (e.g. by the unlock below), then by that key: follow it by the stable
    // manual id so the open panel survives its own unlock.
    var manualId by rememberSaveable { mutableStateOf<String?>(null) }
    val gw = gateways.firstOrNull { it.id == gatewayId }
        ?: manualId?.let { m -> gateways.firstOrNull { it.manual?.id == m } }
    val currentManual = gw?.manual?.id
    if (currentManual != null && currentManual != manualId) SideEffect { manualId = currentManual }
    val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
    // A locked gateway's panel embeds the key field: no screenshots of it.
    val properties = if (gw != null && gw.access != Access.MEMBER) secureSheetProperties else ModalBottomSheetDefaults.properties

    ModalBottomSheet(onDismissRequest = onDismiss, sheetState = sheetState, properties = properties) {
        Column(
            Modifier
                .fillMaxWidth()
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 20.dp)
                .padding(bottom = 24.dp),
        ) {
            if (gw == null) {
                Text("This gateway is no longer listed.", style = MaterialTheme.typography.bodyLarge)
                return@Column
            }
            Text(gw.title, style = MaterialTheme.typography.headlineSmall)
            Row(horizontalArrangement = Arrangement.spacedBy(4.dp), modifier = Modifier.padding(top = 4.dp, bottom = 8.dp)) {
                when (gw.access) {
                    Access.MEMBER -> Tag("verified", MaterialTheme.colorScheme.primaryContainer, MaterialTheme.colorScheme.onPrimaryContainer)
                    Access.KEY_CHANGED -> {
                        Tag("unverified")
                        Tag("key changed", MaterialTheme.colorScheme.errorContainer, MaterialTheme.colorScheme.onErrorContainer)
                    }
                    Access.LOCKED -> Tag("unverified")
                }
                if (gw.isNew) Tag("new", MaterialTheme.colorScheme.tertiaryContainer, MaterialTheme.colorScheme.onTertiaryContainer)
                if (!gw.online) Tag("offline")
            }
            if (gw.access == Access.MEMBER) MemberDetails(gw, onConnect) else LockedDetails(gw)
            gw.manual?.let { RemoveManual(it.id, onDismiss) }
        }
    }
}

@Composable
private fun MemberDetails(gw: Gateway, onConnect: (Gateway) -> Unit) {
    var info by remember(gw.id) { mutableStateOf<GatewayInfo?>(null) }
    var skewMs by remember(gw.id) { mutableLongStateOf(0L) }
    var fetchedAt by remember(gw.id) { mutableLongStateOf(0L) }
    var endpointUsed by remember(gw.id) { mutableStateOf("") }
    var error by remember(gw.id) { mutableStateOf<String?>(null) }
    var loading by remember(gw.id) { mutableStateOf(true) }
    var refreshTick by remember(gw.id) { mutableIntStateOf(0) }
    val status by CoreBridge.status.collectAsStateWithLifecycle()

    LaunchedEffect(gw.id, refreshTick) {
        while (true) {
            loading = true
            try {
                val r = CoreBridge.call("gateways.info", JSONObject().put("gateway_id", gw.id))
                val parsed = GatewayInfo.parse(r.optJSONObject("info"))
                if (parsed == null) {
                    error = "The gateway sent details this app cannot read."
                } else {
                    val local = System.currentTimeMillis()
                    val fetched = r.optLong("fetched_at_ms", 0L).takeIf { it > 0 } ?: local
                    info = parsed
                    skewMs = if (parsed.nowSec > 0) parsed.nowSec * 1000 - fetched else 0
                    fetchedAt = local
                    endpointUsed = Untrusted.text(r.optString("endpoint_used"), 64)
                    error = null
                }
            } catch (e: CoreException) {
                error = when (e.code) {
                    "timeout", "unreachable" -> "The gateway did not respond."
                    "locked" -> "This gateway is locked — enter its key."
                    "clock_skew" -> "Clock difference too large — check the date and time on both devices."
                    else -> e.message
                }
            } finally {
                loading = false
            }
            delay(INFO_REFRESH_MS)
        }
    }

    Row(verticalAlignment = Alignment.CenterVertically) {
        Text(
            when {
                loading && info == null -> "Loading details…"
                fetchedAt > 0 -> "Updated ${Format.timestamp(fetchedAt)} · refreshes every 30 s"
                else -> ""
            },
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.weight(1f),
        )
        IconButton(onClick = { refreshTick++ }) { Icon(Icons.Filled.Refresh, contentDescription = "Refresh") }
    }
    error?.let { Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodyMedium) }

    val i = info
    if (i != null) {
        Section("Gateway") {
            InfoRow("Name", i.name)
            InfoRow("System", listOf(Format.os(i.os), i.osVersion).filter { it.isNotEmpty() }.joinToString(" "))
            InfoRow("App version", i.appVersion)
            i.uptimeSec?.let { InfoRow("Device uptime", Format.duration(it)) }
            i.gatewayUptimeSec?.let { InfoRow("Gateway uptime", Format.duration(it)) }
            i.clientCount?.let { InfoRow("Connected clients", it.toString()) }
            InfoRow("LAN access", if (i.lanAccess) "Allowed for clients" else "Internet only")
            InfoRow("Subnet", i.subnet, mono = true)
            i.mtu?.let { InfoRow("MTU", it.toString()) }
            InfoRow("Ports", listOfNotNull(i.wgPort?.let { "WireGuard $it" }, i.ctrlPort?.let { "control $it" }).joinToString(", "))
            if (i.dualRole) InfoRow("Exit path", "Clients exit via this device's own connection")
        }
        HorizontalDivider()
        Section("Network") {
            InfoRow("LAN IPs", i.lanIps.joinToString(", "), mono = true)
            InfoRow("Public IP", i.publicIp, mono = true)
            InfoRow("Public IPv6", i.publicIp6, mono = true)
            if (i.publicIpCheckedAt > 0) {
                InfoRow("Last checked", Format.timestamp(i.publicIpCheckedAt) + if (i.stale) " (stale)" else "")
            }
            InfoRow("Reachability", reachability(gw, i))
            InfoRow("Endpoint used", endpointUsed, mono = true)
        }
        HorizontalDivider()
        LocationSection(i)
        HorizontalDivider()
        TimeSection(i, skewMs)
        HorizontalDivider()
    }

    Section("Identity") {
        InfoRow("Fingerprint", gw.fingerprint, mono = true)
        InfoRow("First seen", Format.timestamp(gw.firstSeen))
        InfoRow("Network", gw.networkLabel)
    }

    FilledTonalButton(
        onClick = { onConnect(gw) },
        enabled = gw.canConnect && !(status.client.active && status.client.gatewayId == gw.id),
        modifier = Modifier.padding(top = 12.dp).fillMaxWidth(),
    ) { Text("Connect") }
}

@Composable
private fun LocationSection(i: GatewayInfo) {
    val title = if (i.geoSource == "geoip") "Location — approximate (city-level, from IP)" else "Location"
    Section(title) {
        if (i.geoSource == "none") {
            Text("Location lookup is turned off on this gateway.", style = MaterialTheme.typography.bodyMedium)
            return@Section
        }
        InfoRow("Country", listOf(i.country, i.countryCode.takeIf { it.isNotEmpty() }?.let { "($it)" } ?: "").filter { it.isNotEmpty() }.joinToString(" "))
        InfoRow("Region", i.region)
        InfoRow("City", i.city)
        if (i.lat != null && i.lon != null) {
            val acc = i.accuracyKm?.takeIf { it > 0 }?.let { " (± $it km)" } ?: ""
            val note = if (i.geoSource == "geoip") " — approximate (city-level, from IP)" else ""
            InfoRow("Lat / lon", String.format(Locale.US, "%.4f, %.4f", i.lat, i.lon) + acc + note)
        }
        InfoRow("ISP", i.isp)
        InfoRow("ASN", i.asn)
        InfoRow("Source", if (i.geoSource == "manual") "Set manually on the gateway" else i.geoProvider)
    }
}

/** Live gateway-local clock (§10.6): wall = now + skew + utc_offset, ticking every second. */
@Composable
private fun TimeSection(i: GatewayInfo, skewMs: Long) {
    var now by remember { mutableLongStateOf(System.currentTimeMillis()) }
    LaunchedEffect(Unit) {
        while (true) {
            now = System.currentTimeMillis()
            delay(1_000 - now % 1_000)
        }
    }
    Section("Time") {
        val offset = i.utcOffsetSec
        InfoRow("Time zone", listOf(i.tzName, i.tzAbbrev).filter { it.isNotEmpty() }.joinToString(" · "))
        if (offset != null) {
            InfoRow("UTC offset", Format.utcOffset(offset))
            val (clock, date) = Format.remoteClock(now + skewMs + offset * 1000L)
            Row(verticalAlignment = Alignment.Bottom, modifier = Modifier.padding(vertical = 4.dp)) {
                Text(clock, style = MaterialTheme.typography.displaySmall, fontFamily = FontFamily.Monospace)
                Text(
                    "  $date  ${i.tzName.ifEmpty { Format.utcOffset(offset) }}",
                    style = MaterialTheme.typography.bodyMedium,
                    modifier = Modifier.padding(bottom = 6.dp),
                )
            }
        } else {
            InfoRow("Local time", "unknown (the gateway sent no valid UTC offset)")
        }
        if (abs(skewMs) > 60_000) {
            Text(
                "Device clock differs by ${abs(skewMs) / 1000} s",
                color = MaterialTheme.colorScheme.error,
                style = MaterialTheme.typography.bodyMedium,
            )
        }
    }
}

private fun reachability(gw: Gateway, i: GatewayInfo): String {
    val where = when {
        gw.manual != null -> "Internet (manual)"
        gw.endpoints.any { it.source == "lan" } -> "LAN"
        else -> ""
    }
    val nat = when (i.nat) {
        "nat" -> "Reachable on this LAN. For access from the Internet, forward UDP 51820 and 51821 on your router to this device."
        "cgnat" -> "Reachable on this LAN only (mobile network uses carrier NAT; port forwarding is not possible)."
        "none" -> "The gateway has a public address."
        else -> ""
    }
    return listOf(where, nat).filter { it.isNotEmpty() }.joinToString(" — ")
}

@Composable
private fun LockedDetails(gw: Gateway) {
    Section("Public information") {
        InfoRow("Name", gw.name)
        if (gw.os.isNotEmpty()) InfoRow("System", Format.os(gw.os))
        InfoRow("App version", gw.appVersion)
        if (gw.online) gw.clientCount?.let { InfoRow("Connected clients", it.toString()) }
        val ep = gw.endpoints.firstOrNull()
        InfoRow("Ports", listOfNotNull(ep?.wgPort?.let { "WireGuard $it" }, ep?.ctrlPort?.let { "control $it" }).joinToString(", "))
        if (gw.online) InfoRow(
            "Flags",
            listOf(
                if (gw.accepting) "accepting clients" else "not accepting clients",
                if (gw.lanAccess) "LAN access on" else "",
                if (gw.dualRole) "dual role" else "",
            ).filter { it.isNotEmpty() }.joinToString(", "),
        )
        InfoRow("Fingerprint", gw.fingerprint, mono = true)
        InfoRow("Endpoint", gw.manual?.let { "Manual · ${it.host}" } ?: ep?.let { "LAN ${it.ip}" } ?: "")
        if (gw.lastSeenMs >= 0) InfoRow("Last seen", Format.ago(gw.lastSeenMs / 1000))
        InfoRow("Status", "unverified")
    }
    if (gw.access == Access.KEY_CHANGED) {
        Text(
            "This gateway used to match a key in your keyring. Its key was probably reset — enter the new key.",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.error,
            modifier = Modifier.padding(vertical = 4.dp),
        )
    }
    Text(
        "Enter this gateway's key to see location details and connect",
        style = MaterialTheme.typography.bodyLarge,
        modifier = Modifier.padding(vertical = 8.dp),
    )
    // Unlocking here only stores the key; the list's Connect then works directly.
    KeyEntryContent(mode = KeyEntryMode.Unlock(gw.id, gw.title), onDone = {})
}

@Composable
private fun RemoveManual(manualId: String, onDismiss: () -> Unit) {
    val scope = rememberCoroutineScope()
    TextButton(
        onClick = {
            scope.launch {
                try {
                    CoreBridge.call("gateways.manual_remove", JSONObject().put("id", manualId))
                    CoreBridge.refreshGateways()
                    onDismiss()
                } catch (e: CoreException) {
                    CoreBridge.post("Could not remove: ${e.message}")
                }
            }
        },
        modifier = Modifier.padding(top = 8.dp),
    ) { Text("Remove this manually added gateway", color = MaterialTheme.colorScheme.error) }
}
