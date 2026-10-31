@file:OptIn(ExperimentalMaterial3Api::class)

package app.privatevpn.ui.screens

import android.Manifest
import android.content.ClipboardManager
import android.content.pm.PackageManager
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.ModalBottomSheetProperties
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.SecureFlagPolicy
import androidx.core.content.ContextCompat
import app.privatevpn.core.CoreBridge
import app.privatevpn.core.CoreException
import app.privatevpn.core.Untrusted
import app.privatevpn.core.str
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions
import kotlinx.coroutines.launch
import org.json.JSONObject

/** What the entered key is for. */
sealed interface KeyEntryMode {
    /** Connect / ⓘ on a locked gateway → `gateways.unlock`. */
    data class Unlock(val gatewayId: String, val gatewayName: String) : KeyEntryMode

    /** Keyring screen "Add key" → `keyring.add`. */
    data object AddToKeyring : KeyEntryMode
}

/** Longest accepted key input: the §5.1 text is 70 chars; allow stray spaces/dashes. */
private const val KEY_INPUT_CAP = 120

/**
 * Window flags for a sheet that shows a network key in clear: FLAG_SECURE
 * keeps it out of screenshots, screen recordings and the recents thumbnail.
 */
val secureSheetProperties: ModalBottomSheetProperties
    get() = ModalBottomSheetProperties(
        shouldDismissOnBackPress = true,
        shouldDismissOnClickOutside = true,
        securePolicy = SecureFlagPolicy.SecureOn,
    )

/**
 * Bottom sheet around [KeyEntryContent]; [onDone] runs after the key was
 * accepted, with the gateway's current list id from `gateways.unlock` (null
 * for [KeyEntryMode.AddToKeyring] or an older core).
 */
@Composable
fun KeyEntrySheet(mode: KeyEntryMode, onDismiss: () -> Unit, onDone: (String?) -> Unit) {
    val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
    ModalBottomSheet(onDismissRequest = onDismiss, sheetState = sheetState, properties = secureSheetProperties) {
        Column(
            Modifier
                .fillMaxWidth()
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 20.dp)
                .padding(bottom = 24.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Text(
                when (mode) {
                    is KeyEntryMode.Unlock -> "Enter the key for ${mode.gatewayName}"
                    KeyEntryMode.AddToKeyring -> "Add a network key"
                },
                style = MaterialTheme.typography.titleLarge,
            )
            Text(
                "The key is shown on the gateway's PrivateVPN page (as text and QR code). " +
                    "You enter it once per network; it stays only on this device.",
                style = MaterialTheme.typography.bodyMedium,
            )
            KeyEntryContent(mode, onDone)
        }
    }
}

/**
 * Key field + "Scan QR" (zxing ScanContract, CAMERA requested at runtime) +
 * "Paste". The key text lives only in this composition (not in saved
 * instance state) and is cleared once accepted.
 */
@Composable
fun KeyEntryContent(mode: KeyEntryMode, onDone: (String?) -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var keyText by remember { mutableStateOf("") }
    var label by remember { mutableStateOf("") }
    var error by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }

    val scanLauncher = rememberLauncherForActivityResult(ScanContract()) { result ->
        // A QR code can hold anything (a URL, a script, 4 KB of junk): only a
        // §5.1 key text ("PVN1-…", 70 chars) is taken over into the field.
        val raw = result.contents?.trim()
        when {
            raw == null -> Unit // cancelled
            raw.length <= KEY_INPUT_CAP && raw.startsWith("PVN1", ignoreCase = true) -> {
                keyText = Untrusted.text(raw, KEY_INPUT_CAP)
                error = null
            }
            else -> error = "That QR code is not a PrivateVPN key."
        }
    }
    fun launchScan() {
        scanLauncher.launch(
            ScanOptions()
                .setDesiredBarcodeFormats(ScanOptions.QR_CODE)
                .setPrompt("Scan the key QR code shown on the gateway")
                .setBeepEnabled(false)
                .setOrientationLocked(false),
        )
    }
    val cameraLauncher = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
        if (granted) launchScan() else error = "Camera permission denied — paste the key instead."
    }

    fun submit() {
        val text = keyText.trim()
        if (text.isEmpty()) {
            error = "Enter or scan the key first."
            return
        }
        busy = true
        error = null
        scope.launch {
            try {
                var unlockedId: String? = null
                when (mode) {
                    is KeyEntryMode.Unlock -> {
                        val r = CoreBridge.call(
                            "gateways.unlock",
                            JSONObject().put("gateway_id", mode.gatewayId).put("key_text", text),
                        )
                        CoreBridge.post(
                            if (r.optBoolean("replaced")) "Key updated — ${mode.gatewayName} had reset its key."
                            else "Key accepted for ${mode.gatewayName}.",
                        )
                        // For a manual entry the id changes from "m-<uuid>" to its public key.
                        unlockedId = r.str("gateway_id", 64).ifEmpty { null }
                    }
                    KeyEntryMode.AddToKeyring -> {
                        val args = JSONObject().put("key_text", text)
                        if (label.isNotBlank()) args.put("label", label.trim())
                        val r = CoreBridge.call("keyring.add", args)
                        CoreBridge.post(if (r.optBoolean("existing")) "That key is already in your keyring." else "Key added.")
                    }
                }
                keyText = ""
                CoreBridge.refreshGateways()
                CoreBridge.refreshKeyring()
                onDone(unlockedId)
            } catch (e: CoreException) {
                val name = (mode as? KeyEntryMode.Unlock)?.gatewayName ?: "the gateway"
                error = when (e.code) {
                    "key_format" -> "That is not a valid PrivateVPN key. Check for typos — it starts with PVN1-."
                    "key_mismatch" -> "This key does not match $name."
                    "unreachable", "timeout" -> "Could not reach $name to check the key. Make sure it is online and try again."
                    "keyring_full" -> "Your keyring is full (16 networks). Remove one on the Keys screen first."
                    "not_found" -> "$name is no longer listed."
                    else -> e.message
                }
            } finally {
                busy = false
            }
        }
    }

    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        OutlinedTextField(
            value = keyText,
            onValueChange = { keyText = it.take(KEY_INPUT_CAP); error = null },
            label = { Text("Network key") },
            placeholder = { Text("PVN1-XXXXX-XXXXX-…") },
            textStyle = TextStyle(fontFamily = FontFamily.Monospace),
            minLines = 2,
            // Password keyboard: no suggestions, no learning of the secret.
            keyboardOptions = KeyboardOptions(
                capitalization = KeyboardCapitalization.Characters,
                autoCorrectEnabled = false,
                keyboardType = KeyboardType.Password,
            ),
            isError = error != null,
            enabled = !busy,
            modifier = Modifier.fillMaxWidth(),
        )
        if (mode == KeyEntryMode.AddToKeyring) {
            OutlinedTextField(
                value = label,
                onValueChange = { label = it.take(32) },
                label = { Text("Label (optional)") },
                singleLine = true,
                enabled = !busy,
                modifier = Modifier.fillMaxWidth(),
            )
        }
        error?.let { Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodyMedium) }
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedButton(enabled = !busy, onClick = {
                if (ContextCompat.checkSelfPermission(context, Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED) {
                    launchScan()
                } else {
                    cameraLauncher.launch(Manifest.permission.CAMERA)
                }
            }) { Text("Scan QR") }
            OutlinedButton(enabled = !busy, onClick = {
                val cm = context.getSystemService(ClipboardManager::class.java)
                val clip = cm?.primaryClip?.takeIf { it.itemCount > 0 }?.getItemAt(0)?.coerceToText(context)?.toString()
                if (clip.isNullOrBlank()) error = "The clipboard is empty." else keyText = Untrusted.text(clip, KEY_INPUT_CAP)
            }) { Text("Paste") }
        }
        Text(
            "Anyone with this key can use the network's gateways. Only enter keys from gateways you trust.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Button(enabled = !busy, onClick = { submit() }, modifier = Modifier.fillMaxWidth()) {
            Text(
                when {
                    busy -> "Checking…"
                    mode is KeyEntryMode.Unlock -> "Unlock"
                    else -> "Add key"
                },
            )
        }
    }
}
