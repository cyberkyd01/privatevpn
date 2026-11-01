package app.privatevpnpro.ui.screens

import android.content.ClipData
import android.content.ClipboardManager
import android.os.PersistableBundle
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExtendedFloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
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
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.DialogProperties
import androidx.compose.ui.window.SecureFlagPolicy
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import app.privatevpnpro.core.CoreBridge
import app.privatevpnpro.core.CoreException
import app.privatevpnpro.core.KeyringEntry
import app.privatevpnpro.core.Untrusted
import app.privatevpnpro.ui.Format
import app.privatevpnpro.ui.ScreenScaffold
import app.privatevpnpro.ui.Tag
import kotlinx.coroutines.launch
import org.json.JSONObject

/** Keyring (§11.3): label, rename, remove, "Show key" (text only, after confirmation), add. */
@Composable
fun KeyringScreen() {
    val entries by CoreBridge.keyring.collectAsStateWithLifecycle()
    val scope = rememberCoroutineScope()
    var adding by rememberSaveable { mutableStateOf(false) }
    var renaming by remember { mutableStateOf<KeyringEntry?>(null) }
    var removing by remember { mutableStateOf<KeyringEntry?>(null) }
    var confirmReveal by remember { mutableStateOf<KeyringEntry?>(null) }
    var revealed by remember { mutableStateOf<Pair<KeyringEntry, String>?>(null) }

    LaunchedEffect(Unit) { CoreBridge.refreshKeyring() }

    ScreenScaffold(
        title = "Keys",
        floatingActionButton = {
            ExtendedFloatingActionButton(
                onClick = { adding = true },
                icon = { Icon(Icons.Filled.Add, contentDescription = null) },
                text = { Text("Add key") },
            )
        },
    ) { padding ->
        LazyColumn(
            modifier = Modifier.fillMaxSize().padding(padding),
            contentPadding = PaddingValues(start = 16.dp, end = 16.dp, top = 16.dp, bottom = 96.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            if (entries.isEmpty()) {
                item(key = "empty") {
                    Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)) {
                        Text(
                            "No network keys yet. A key is added the first time you connect to a locked gateway, " +
                                "or here with \"Add key\". Keys are created on a desktop gateway — Android never creates one.",
                            modifier = Modifier.padding(16.dp),
                            style = MaterialTheme.typography.bodyLarge,
                        )
                    }
                }
            }
            items(entries, key = { it.id }) { e ->
                KeyringCard(
                    e,
                    onRename = { renaming = e },
                    onReveal = { confirmReveal = e },
                    onRemove = { removing = e },
                )
            }
        }
    }

    if (adding) {
        KeyEntrySheet(KeyEntryMode.AddToKeyring, onDismiss = { adding = false }, onDone = { adding = false })
    }

    renaming?.let { e ->
        RenameDialog(e, onDismiss = { renaming = null })
    }

    removing?.let { e ->
        AlertDialog(
            onDismissRequest = { removing = null },
            title = { Text("Remove \"${e.label}\"?") },
            text = {
                Text(
                    "Gateways of this network will be locked again until you enter the key. " +
                        "A connection that uses this network is disconnected.",
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    removing = null
                    scope.launch {
                        try {
                            CoreBridge.call("keyring.remove", JSONObject().put("id", e.id))
                            CoreBridge.refreshKeyring()
                            CoreBridge.refreshGateways()
                        } catch (ex: CoreException) {
                            CoreBridge.post("Could not remove: ${ex.message}")
                        }
                    }
                }) { Text("Remove", color = MaterialTheme.colorScheme.error) }
            },
            dismissButton = { TextButton(onClick = { removing = null }) { Text("Cancel") } },
        )
    }

    confirmReveal?.let { e ->
        AlertDialog(
            onDismissRequest = { confirmReveal = null },
            title = { Text("Show the key for \"${e.label}\"?") },
            text = {
                Text(
                    "Anyone with this key can connect to this network's gateways and use their Internet connection. " +
                        "Share it only with devices you own or people you trust.",
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    confirmReveal = null
                    scope.launch {
                        try {
                            val r = CoreBridge.call("keyring.reveal", JSONObject().put("id", e.id))
                            val key = Untrusted.text(r.optString("key_text"), 100)
                            if (key.isNotEmpty()) revealed = e to key
                        } catch (ex: CoreException) {
                            CoreBridge.post("Could not show the key: ${ex.message}")
                        }
                    }
                }) { Text("Show key") }
            },
            dismissButton = { TextButton(onClick = { confirmReveal = null }) { Text("Cancel") } },
        )
    }

    revealed?.let { (e, key) -> RevealDialog(e, key, onDismiss = { revealed = null }) }
}

@Composable
private fun KeyringCard(e: KeyringEntry, onRename: () -> Unit, onReveal: () -> Unit, onRemove: () -> Unit) {
    var menu by remember { mutableStateOf(false) }
    Card {
        Row(Modifier.fillMaxWidth().padding(start = 16.dp, top = 12.dp, bottom = 12.dp, end = 4.dp)) {
            Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                Text(e.label, style = MaterialTheme.typography.titleMedium)
                if (e.createdHere) Tag("created on this device")
                Text(
                    "Added ${Format.timestamp(e.createdAt)} · last used ${Format.timestamp(e.lastUsed)}",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Text(
                    if (e.gatewaysSeen == 1) "1 gateway seen" else "${e.gatewaysSeen} gateways seen",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            Box {
                IconButton(onClick = { menu = true }) { Icon(Icons.Filled.MoreVert, contentDescription = "Actions") }
                DropdownMenu(expanded = menu, onDismissRequest = { menu = false }) {
                    DropdownMenuItem(text = { Text("Rename") }, onClick = { menu = false; onRename() })
                    DropdownMenuItem(text = { Text("Show key") }, onClick = { menu = false; onReveal() })
                    DropdownMenuItem(text = { Text("Remove") }, onClick = { menu = false; onRemove() })
                }
            }
        }
    }
}

@Composable
private fun RenameDialog(e: KeyringEntry, onDismiss: () -> Unit) {
    var label by remember { mutableStateOf(e.label) }
    var error by remember { mutableStateOf<String?>(null) }
    val scope = rememberCoroutineScope()
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Rename network") },
        text = {
            Column {
                OutlinedTextField(
                    value = label,
                    onValueChange = { label = it.take(32); error = null },
                    label = { Text("Label") },
                    singleLine = true,
                )
                error?.let { Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall) }
            }
        },
        confirmButton = {
            TextButton(onClick = {
                scope.launch {
                    try {
                        CoreBridge.call("keyring.rename", JSONObject().put("id", e.id).put("label", label.trim()))
                        CoreBridge.refreshKeyring()
                        onDismiss()
                    } catch (ex: CoreException) {
                        error = ex.message
                    }
                }
            }, enabled = label.isNotBlank()) { Text("Save") }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}

/** Key as text only (no QR on Android, §11.1); screenshots blocked while shown. */
@Composable
private fun RevealDialog(e: KeyringEntry, key: String, onDismiss: () -> Unit) {
    val context = LocalContext.current
    AlertDialog(
        onDismissRequest = onDismiss,
        properties = DialogProperties(securePolicy = SecureFlagPolicy.SecureOn),
        title = { Text(e.label) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                SelectionContainer {
                    Text(key, fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodyLarge)
                }
                Text(
                    "Type or paste this into the other device. Anyone with this key can use this network's gateways.",
                    style = MaterialTheme.typography.bodySmall,
                )
            }
        },
        confirmButton = { TextButton(onClick = onDismiss) { Text("Done") } },
        dismissButton = {
            TextButton(onClick = {
                val clip = ClipData.newPlainText("Private VPN Pro key", key)
                // Keeps the key out of clipboard previews (honoured on Android 13+).
                clip.description.extras = PersistableBundle().apply { putBoolean("android.content.extra.IS_SENSITIVE", true) }
                context.getSystemService(ClipboardManager::class.java)?.setPrimaryClip(clip)
                CoreBridge.post("Key copied.")
            }) { Text("Copy") }
        },
    )
}
