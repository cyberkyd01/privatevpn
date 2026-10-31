package app.privatevpn.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import app.privatevpn.core.Access
import app.privatevpn.core.ClientStatus
import app.privatevpn.core.CoreBridge
import app.privatevpn.core.CoreException
import app.privatevpn.core.Gateway
import app.privatevpn.core.Problem
import app.privatevpn.core.Untrusted
import app.privatevpn.ui.Format
import app.privatevpn.ui.ProblemsCard
import app.privatevpn.ui.ScreenScaffold
import app.privatevpn.ui.StateLook
import app.privatevpn.ui.Tag
import app.privatevpn.ui.clientLook
import app.privatevpn.ui.openVpnSettings
import app.privatevpn.ui.problemsFor
import app.privatevpn.ui.rememberConnectFlow
import app.privatevpn.ui.toneColors
import app.privatevpn.vpn.PvnVpnService
import app.privatevpn.vpn.SystemVpnMode
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import org.json.JSONObject

/**
 * Start screen (§11.3): the problems (if any), the connection state, then
 * every gateway on the LAN.
 */
@Composable
fun GatewaysScreen(onOpenSettings: () -> Unit) {
    val context = LocalContext.current
    val gateways by CoreBridge.gateways.collectAsStateWithLifecycle()
    val status by CoreBridge.status.collectAsStateWithLifecycle()
    val mode by PvnVpnService.systemMode.collectAsStateWithLifecycle()
    val tunMissing by PvnVpnService.tunMissing.collectAsStateWithLifecycle()
    val client = status.client
    val scope = rememberCoroutineScope()
    val connect = rememberConnectFlow()
    val problems = remember(status, mode, tunMissing) { problemsFor(status, mode, tunMissing) }
    val look = clientLook(client, tunMissing, mode?.lockdown == true)

    var detailsId by rememberSaveable { mutableStateOf<String?>(null) }
    var keyForId by rememberSaveable { mutableStateOf<String?>(null) }
    var menuOpen by remember { mutableStateOf(false) }
    var addOpen by rememberSaveable { mutableStateOf(false) }
    var disconnecting by remember { mutableStateOf(false) }
    var lastTriedId by rememberSaveable { mutableStateOf("") }

    // Counters and handshake age while a session exists.
    LaunchedEffect(client.active) {
        while (client.active) {
            delay(2_000)
            CoreBridge.refreshStatus()
        }
    }

    fun onConnect(gw: Gateway) {
        // Locked → key prompt first (asked once per network); never connect to unverified entries.
        if (gw.access != Access.MEMBER) {
            keyForId = gw.id
        } else {
            lastTriedId = gw.id
            connect(gw.id, gw.title)
        }
    }

    fun onDisconnect() {
        if (disconnecting) return
        disconnecting = true
        PvnVpnService.forgetResume(context)
        scope.launch {
            disconnect()
            disconnecting = false
        }
    }

    // The session's gateway, else the one last tried here; else let the user pick.
    fun onReconnect() {
        val id = client.gatewayId.ifEmpty { lastTriedId }
        val gw = gateways.firstOrNull { it.id == id }
        when {
            gw != null && gw.access == Access.MEMBER && !gw.isSelf -> connect(gw.id, gw.title)
            client.gatewayId.isNotEmpty() -> connect(client.gatewayId, client.gatewayName)
            else -> CoreBridge.post("Choose a gateway below to connect.")
        }
    }

    fun onProblemAction(p: Problem) {
        when (p.action) {
            "disconnect" -> onDisconnect()
            "reconnect" -> onReconnect()
            "settings" -> onOpenSettings()
            Problem.ACTION_VPN_SETTINGS -> openVpnSettings(context)
            else -> Unit
        }
    }

    ScreenScaffold(
        title = "PrivateVPN",
        actions = {
            IconButton(onClick = { menuOpen = true }) { Icon(Icons.Filled.MoreVert, contentDescription = "More") }
            DropdownMenu(expanded = menuOpen, onDismissRequest = { menuOpen = false }) {
                DropdownMenuItem(text = { Text("Add gateway by address") }, onClick = {
                    menuOpen = false
                    addOpen = true
                })
                DropdownMenuItem(text = { Text("Refresh") }, onClick = {
                    menuOpen = false
                    scope.launch { CoreBridge.refreshGateways() }
                })
            }
        },
    ) { padding ->
        LazyColumn(
            modifier = Modifier.fillMaxSize().padding(padding),
            contentPadding = PaddingValues(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            if (problems.isNotEmpty()) {
                item(key = "problems") {
                    ProblemsCard(problems, disconnecting, ::onProblemAction)
                }
            }
            item(key = "status") {
                StatusCard(
                    c = client,
                    look = look,
                    mode = mode,
                    disconnecting = disconnecting,
                    onDisconnect = ::onDisconnect,
                    onReconnect = ::onReconnect,
                )
            }
            if (gateways.isEmpty()) {
                item(key = "empty") { EmptyState() }
            }
            items(gateways, key = { it.id }) { gw ->
                GatewayCard(
                    gw = gw,
                    sessionTag = if (client.active && client.gatewayId == gw.id) sessionTag(client) else null,
                    onConnect = { onConnect(gw) },
                    onInfo = { detailsId = gw.id },
                )
            }
        }
    }

    detailsId?.let { id ->
        GatewayDetailsSheet(
            gatewayId = id,
            onDismiss = { detailsId = null },
            onConnect = { gw ->
                detailsId = null
                onConnect(gw)
            },
        )
    }

    keyForId?.let { id ->
        val gw = gateways.firstOrNull { it.id == id }
        KeyEntrySheet(
            mode = KeyEntryMode.Unlock(id, gw?.title ?: "this gateway"),
            onDismiss = { keyForId = null },
            onDone = { unlockedId ->
                keyForId = null
                // The key verified; continue straight into the verified-gateway
                // flow. gateways.unlock reports the entry's current id (a manual
                // entry is listed as "m-<uuid>" until its public key is learned
                // — which the unlock just did); without it, look the entry up
                // again (the list was refreshed before onDone).
                val list = CoreBridge.gateways.value
                val target = unlockedId?.let { u -> list.firstOrNull { it.id == u } }
                    ?: list.firstOrNull { it.id == id }
                    ?: gw?.manual?.id?.let { m -> list.firstOrNull { it.manual?.id == m } }
                val title = target?.title ?: gw?.title ?: "gateway"
                when {
                    unlockedId != null -> {
                        lastTriedId = unlockedId
                        connect(unlockedId, title)
                    }
                    target != null && target.access == Access.MEMBER -> {
                        lastTriedId = target.id
                        connect(target.id, title)
                    }
                    else -> CoreBridge.post("Key accepted. Tap Connect to start.")
                }
            },
        )
    }

    if (addOpen) AddGatewayDialog(onDismiss = { addOpen = false })
}

private suspend fun disconnect() {
    try {
        CoreBridge.call("client.disconnect")
    } catch (e: CoreException) {
        CoreBridge.post("Disconnect failed: ${e.message}")
    }
}

/**
 * This phone's connection in one of five states: Protected, Connecting…,
 * Connection interrupted (traffic held), Internet blocked, Not protected.
 * Disconnect is always offered while a session exists.
 */
@Composable
private fun StatusCard(
    c: ClientStatus,
    look: StateLook,
    mode: SystemVpnMode?,
    disconnecting: Boolean,
    onDisconnect: () -> Unit,
    onReconnect: () -> Unit,
) {
    val (bg, fg) = toneColors(look.tone)
    Card(colors = CardDefaults.cardColors(containerColor = bg, contentColor = fg)) {
        Column(Modifier.fillMaxWidth().padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text("This phone", style = MaterialTheme.typography.labelLarge)
            Text(look.title, style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.SemiBold)
            Text(look.text, style = MaterialTheme.typography.bodyMedium)
            if (c.active && c.gatewayName.isNotEmpty()) {
                Text(
                    "Gateway: ${c.gatewayName}" + if (c.networkLabel.isNotEmpty()) " · ${c.networkLabel}" else "",
                    style = MaterialTheme.typography.bodyMedium,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.padding(top = 4.dp),
                )
            }
            if (c.active && c.state != "joining") {
                if (c.assignedIp.isNotEmpty()) Text("Tunnel address: ${c.assignedIp}", style = MaterialTheme.typography.bodyMedium)
                Text(
                    "Handshake: " + if (c.handshakeAgeSec >= 0) Format.ago(c.handshakeAgeSec) else "none yet",
                    style = MaterialTheme.typography.bodyMedium,
                )
                Text("Received ${Format.bytes(c.rx)} · Sent ${Format.bytes(c.tx)}", style = MaterialTheme.typography.bodyMedium)
                if (c.interrupted && c.degradedSince > 0) {
                    Text("Interrupted since ${Format.timestamp(c.degradedSince)}", style = MaterialTheme.typography.bodySmall)
                } else if (c.since > 0) {
                    Text("Since ${Format.timestamp(c.since)}", style = MaterialTheme.typography.bodySmall)
                }
            }
            if (mode != null && c.active) {
                Text(
                    "Block connections without VPN: " + if (mode.lockdown) "on" else "off",
                    style = MaterialTheme.typography.bodySmall,
                )
            }
            if (c.active) {
                Row(
                    Modifier.fillMaxWidth().padding(top = 8.dp),
                    horizontalArrangement = Arrangement.spacedBy(8.dp, Alignment.End),
                ) {
                    if (c.state == "blocked") Button(onClick = onReconnect, enabled = !disconnecting) { Text("Reconnect") }
                    val label = if (disconnecting) "Disconnecting…" else "Disconnect"
                    if (c.state == "blocked") {
                        OutlinedButton(onClick = onDisconnect, enabled = !disconnecting) { Text(label) }
                    } else {
                        Button(onClick = onDisconnect, enabled = !disconnecting) { Text(label) }
                    }
                }
            } else {
                Text(
                    "Choose a gateway below to connect.",
                    style = MaterialTheme.typography.bodySmall,
                    modifier = Modifier.padding(top = 4.dp),
                )
            }
        }
    }
}

@Composable
private fun EmptyState() {
    Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)) {
        Text(
            "Gateways on your network appear here. To connect, enter the gateway's key once — shown on the gateway's PrivateVPN page.",
            style = MaterialTheme.typography.bodyLarge,
            modifier = Modifier.padding(16.dp),
        )
    }
}

private fun sessionTag(c: ClientStatus): String = when (c.state) {
    "connected" -> if (c.isProtected) "Protected" else "Connected"
    "degraded" -> "Interrupted"
    "blocked" -> "Blocked"
    else -> "Connecting…"
}

@Composable
private fun GatewayCard(gw: Gateway, sessionTag: String?, onConnect: () -> Unit, onInfo: () -> Unit) {
    val locked = gw.access != Access.MEMBER
    Card {
        Column(Modifier.fillMaxWidth().padding(start = 16.dp, end = 4.dp, top = 12.dp, bottom = 12.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(
                    imageVector = when (gw.access) {
                        Access.MEMBER -> Icons.Filled.CheckCircle
                        Access.KEY_CHANGED -> Icons.Filled.Warning
                        Access.LOCKED -> Icons.Filled.Lock
                    },
                    contentDescription = when (gw.access) {
                        Access.MEMBER -> "Verified"
                        Access.KEY_CHANGED -> "Key changed"
                        Access.LOCKED -> "Locked"
                    },
                    tint = when (gw.access) {
                        Access.MEMBER -> MaterialTheme.colorScheme.primary
                        Access.KEY_CHANGED -> MaterialTheme.colorScheme.error
                        Access.LOCKED -> MaterialTheme.colorScheme.onSurfaceVariant
                    },
                )
                Spacer(Modifier.width(12.dp))
                Column(Modifier.weight(1f)) {
                    Text(gw.title, style = MaterialTheme.typography.titleMedium, maxLines = 1, overflow = TextOverflow.Ellipsis)
                    Row(horizontalArrangement = Arrangement.spacedBy(4.dp), modifier = Modifier.padding(top = 2.dp)) {
                        if (gw.access == Access.LOCKED) Tag("unverified")
                        if (gw.access == Access.KEY_CHANGED) {
                            Tag("key changed", MaterialTheme.colorScheme.errorContainer, MaterialTheme.colorScheme.onErrorContainer)
                        }
                        if (gw.isNew) Tag("new", MaterialTheme.colorScheme.tertiaryContainer, MaterialTheme.colorScheme.onTertiaryContainer)
                        if (!gw.online) Tag("offline")
                        if (gw.isSelf) Tag("this device")
                    }
                }
                IconButton(onClick = onInfo) { Icon(Icons.Filled.Info, contentDescription = "Details") }
            }
            Text(
                subtitle(gw),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(top = 6.dp, end = 12.dp),
            )
            Row(Modifier.fillMaxWidth().padding(top = 8.dp, end = 12.dp), horizontalArrangement = Arrangement.End) {
                if (sessionTag != null) {
                    Tag(sessionTag, MaterialTheme.colorScheme.primaryContainer, MaterialTheme.colorScheme.onPrimaryContainer)
                } else {
                    FilledTonalButton(onClick = onConnect, enabled = gw.canConnect) {
                        if (locked) {
                            Icon(Icons.Filled.Lock, contentDescription = null, modifier = Modifier.padding(end = 6.dp))
                        }
                        Text("Connect")
                    }
                }
            }
        }
    }
}

private fun subtitle(gw: Gateway): String = buildList {
    if (gw.os.isNotEmpty()) add(Format.os(gw.os) + if (gw.appVersion.isNotEmpty()) " · v${gw.appVersion}" else "")
    // Counts and flags come from a live beacon/INFO; a never-reached manual entry has none.
    if (gw.online) gw.clientCount?.let { add(if (it == 1) "1 client" else "$it clients") }
    when {
        gw.manual != null -> add("Manual · ${gw.manual.host}")
        gw.endpoints.any { it.source == "lan" } -> add("LAN")
    }
    if (gw.access == Access.MEMBER && gw.networkLabel.isNotEmpty()) add(gw.networkLabel)
    if (gw.online && !gw.accepting) add("not accepting clients")
}.joinToString(" · ")

private val hostRe = Regex("^[A-Za-z0-9.-]{1,253}$")

/** "host", "host:port", "[v6]:port" or a bare IPv6 literal → host + optional port. */
internal fun parseHostPort(input: String): Pair<String, Int?>? {
    val t = input.trim()
    if (t.isEmpty()) return null
    val host: String
    val portText: String?
    when {
        t.startsWith("[") -> {
            val end = t.indexOf(']')
            if (end < 0) return null
            host = t.substring(1, end)
            val rest = t.substring(end + 1)
            portText = if (rest.isEmpty()) null else if (rest.startsWith(":")) rest.substring(1) else return null
        }
        t.count { it == ':' } == 1 -> {
            host = t.substringBefore(':')
            portText = t.substringAfter(':')
        }
        else -> {
            host = t
            portText = null
        }
    }
    val validHost = hostRe.matches(host) || Untrusted.isIPv6(host)
    if (!validHost) return null
    val port = portText?.let { it.toIntOrNull()?.takeIf { p -> p in 1024..65535 } ?: return null }
    return host to port
}

@Composable
private fun AddGatewayDialog(onDismiss: () -> Unit) {
    var address by rememberSaveable { mutableStateOf("") }
    var label by rememberSaveable { mutableStateOf("") }
    var error by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()

    AlertDialog(
        onDismissRequest = { if (!busy) onDismiss() },
        title = { Text("Add gateway by address") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(
                    "For a gateway that is not on this network: its host name or public IP, " +
                        "optionally with the control port (default 51821).",
                    style = MaterialTheme.typography.bodyMedium,
                )
                OutlinedTextField(
                    value = address,
                    onValueChange = { address = it.take(270); error = null },
                    label = { Text("Address (host[:port])") },
                    singleLine = true,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri, autoCorrectEnabled = false),
                )
                OutlinedTextField(
                    value = label,
                    onValueChange = { label = it.take(32) },
                    label = { Text("Label (optional)") },
                    singleLine = true,
                )
                error?.let { Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall) }
            }
        },
        confirmButton = {
            TextButton(enabled = !busy, onClick = {
                val hp = parseHostPort(address)
                if (hp == null) {
                    error = "Enter a host name or IP address, optionally with a port between 1024 and 65535."
                    return@TextButton
                }
                busy = true
                scope.launch {
                    val args = JSONObject()
                        .put("label", label.trim().ifEmpty { hp.first.take(32) })
                        .put("host", hp.first)
                    hp.second?.let { args.put("ctrl_port", it) }
                    try {
                        CoreBridge.call("gateways.manual_add", args)
                        CoreBridge.refreshGateways()
                        CoreBridge.post("Gateway added. It is checked against your keys in the background.")
                        onDismiss()
                    } catch (e: CoreException) {
                        error = e.message
                    } finally {
                        busy = false
                    }
                }
            }) { Text("Add") }
        },
        dismissButton = { TextButton(enabled = !busy, onClick = onDismiss) { Text("Cancel") } },
    )
}
