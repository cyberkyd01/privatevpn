package app.privatevpn.ui.screens

import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import app.privatevpn.core.CoreBridge
import app.privatevpn.ui.ScreenScaffold

/** The core's in-memory ring buffer (§12.1), live. Nothing here is written anywhere. */
@Composable
fun LogScreen() {
    val lines by CoreBridge.log.collectAsStateWithLifecycle()
    val listState = rememberLazyListState()

    LaunchedEffect(Unit) { CoreBridge.refreshLog() }
    LaunchedEffect(lines.size) {
        if (lines.isNotEmpty()) listState.scrollToItem(lines.lastIndex)
    }

    ScreenScaffold(title = "Log") { padding ->
        if (lines.isEmpty()) {
            Text(
                "No log lines yet.",
                modifier = Modifier.padding(padding).padding(16.dp),
                style = MaterialTheme.typography.bodyLarge,
            )
        } else {
            SelectionContainer(Modifier.fillMaxSize().padding(padding)) {
                LazyColumn(state = listState, contentPadding = PaddingValues(12.dp)) {
                    itemsIndexed(lines) { _, line ->
                        Text(line, fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodySmall)
                    }
                }
            }
        }
    }
}
