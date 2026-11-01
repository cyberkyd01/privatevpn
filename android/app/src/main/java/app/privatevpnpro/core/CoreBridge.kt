package app.privatevpnpro.core

import android.content.Context
import app.privatevpnpro.BuildConfig
import app.privatevpnpro.mobile.Mobile
import app.privatevpnpro.net.MulticastLockHolder
import app.privatevpnpro.net.NetworkWatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.channels.BufferOverflow
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import org.json.JSONException
import org.json.JSONObject
import java.io.File

/** A failed core method: [code] is the §14 error code ("key_mismatch", "locked", …). */
class CoreException(val code: String, message: String) : Exception(message)

/**
 * The only path from Kotlin into the Go core (ARCHITECTURE §11.1, §14).
 *
 * * [call] runs one method of the §14.4 table on a background dispatcher and
 *   returns the parsed JSON result.
 * * Go events (§14.3) arrive through [CoreCallbacks.onEvent] and are folded
 *   into the StateFlows below, which the UI and the VPN service observe.
 * * The core runs while someone holds it ([acquire]/[release]): the UI while
 *   any Activity is started, the VPN service while it runs (§11.4). When the
 *   last holder goes, the MulticastLock is released and `Mobile.stop()` is
 *   called.
 */
object CoreBridge {
    private const val MAX_LOG_LINES = 1000
    private const val STOP_GRACE_MS = 3_000L
    private const val START_WAIT_MS = 10_000L

    private lateinit var appContext: Context
    private lateinit var callbacks: CoreCallbacks
    private lateinit var multicast: MulticastLockHolder
    private lateinit var network: NetworkWatcher

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

    @OptIn(ExperimentalCoroutinesApi::class)
    private val lifecycleDispatcher = Dispatchers.IO.limitedParallelism(1)

    private val holders = mutableSetOf<String>()

    private val _running = MutableStateFlow(false)
    val running: StateFlow<Boolean> = _running.asStateFlow()

    private val _status = MutableStateFlow(CoreStatus())
    val status: StateFlow<CoreStatus> = _status.asStateFlow()

    private val _gateways = MutableStateFlow<List<Gateway>>(emptyList())
    val gateways: StateFlow<List<Gateway>> = _gateways.asStateFlow()

    private val _keyring = MutableStateFlow<List<KeyringEntry>>(emptyList())
    val keyring: StateFlow<List<KeyringEntry>> = _keyring.asStateFlow()

    private val logLock = Any()
    private val logBuffer = ArrayDeque<String>()
    private val _log = MutableStateFlow<List<String>>(emptyList())
    val log: StateFlow<List<String>> = _log.asStateFlow()

    private val _messages = MutableSharedFlow<String>(extraBufferCapacity = 8, onBufferOverflow = BufferOverflow.DROP_OLDEST)
    /** Short user-facing messages (snackbars): core "error" events, connect failures. */
    val messages: SharedFlow<String> = _messages.asSharedFlow()

    fun init(context: Context) {
        appContext = context.applicationContext
        callbacks = CoreCallbacks(appContext)
        multicast = MulticastLockHolder(appContext)
        network = NetworkWatcher(appContext) { notifyNetworkChanged() }
    }

    // ---- lifecycle -------------------------------------------------------

    fun acquire(holder: String) {
        val first = synchronized(holders) { holders.add(holder) && holders.size == 1 }
        if (first) scope.launch(lifecycleDispatcher) { startIfHeld() }
    }

    fun release(holder: String) {
        val last = synchronized(holders) { holders.remove(holder) && holders.isEmpty() }
        if (last) {
            scope.launch(lifecycleDispatcher) {
                delay(STOP_GRACE_MS) // a quick Activity switch or service hand-over keeps the core
                stopIfUnheld()
            }
        }
    }

    private fun held() = synchronized(holders) { holders.isNotEmpty() }

    private fun startIfHeld() {
        if (_running.value || !held()) return
        val dir = File(appContext.filesDir, "pvp")
        dir.mkdirs()
        try {
            Mobile.start(dir.absolutePath, BuildConfig.VERSION_NAME, callbacks)
        } catch (e: Exception) {
            post("Private VPN Pro core failed to start: ${errorOf(e).message}")
            return
        }
        multicast.acquire()
        network.start()
        _running.value = true
        scope.launch { refreshAll() }
    }

    private fun stopIfUnheld() {
        if (!_running.value || held()) return
        network.stop()
        multicast.release()
        _running.value = false
        Mobile.stop()
        _status.value = CoreStatus(version = _status.value.version)
    }

    // ---- methods -----------------------------------------------------------

    /** Runs one §14.4 method. Throws [CoreException] with the core's error code. */
    suspend fun call(method: String, args: JSONObject = JSONObject()): JSONObject = withContext(Dispatchers.IO) {
        withTimeoutOrNull(START_WAIT_MS) { running.first { it } }
            ?: throw CoreException("not_started", "Private VPN Pro core is not running")
        val res = try {
            Mobile.call(method, args.toString())
        } catch (e: Exception) {
            throw errorOf(e)
        }
        try {
            if (res.isNullOrEmpty()) JSONObject() else JSONObject(res)
        } catch (e: JSONException) {
            throw CoreException("internal", "malformed response from core")
        }
    }

    /** Fire-and-forget variant for callers without a coroutine (service teardown, network changes). */
    fun callAsync(method: String, args: JSONObject = JSONObject()) {
        scope.launch {
            try {
                call(method, args)
            } catch (_: CoreException) {
            }
        }
    }

    fun disconnect() = callAsync("client.disconnect")

    fun post(message: String) {
        _messages.tryEmit(Untrusted.text(message, 300))
    }

    private fun errorOf(e: Throwable): CoreException {
        if (e is CoreException) return e
        val msg = e.message.orEmpty()
        return try {
            val o = JSONObject(msg)
            CoreException(o.str("code", 32).ifEmpty { "internal" }, o.str("message", 300).ifEmpty { "error" })
        } catch (_: JSONException) {
            CoreException("internal", Untrusted.text(msg, 300).ifEmpty { "error" })
        }
    }

    suspend fun refreshAll() {
        refreshStatus()
        refreshGateways()
        refreshKeyring()
        refreshLog()
    }

    suspend fun refreshStatus() {
        try {
            _status.value = CoreStatus.parse(call("status.get"))
        } catch (_: CoreException) {
        }
    }

    suspend fun refreshGateways() {
        try {
            setGateways(call("gateways.list"))
        } catch (_: CoreException) {
        }
    }

    suspend fun refreshKeyring() {
        try {
            setKeyring(call("keyring.list"))
        } catch (_: CoreException) {
        }
    }

    suspend fun refreshLog() {
        try {
            val lines = call("log.get").optJSONArray("lines").mapStrings(MAX_LOG_LINES) { Untrusted.text(it, 600) }
            synchronized(logLock) {
                logBuffer.clear()
                logBuffer.addAll(lines.takeLast(MAX_LOG_LINES))
                _log.value = logBuffer.toList()
            }
        } catch (_: CoreException) {
        }
    }

    private fun notifyNetworkChanged() {
        if (_running.value) callAsync("sys.network_changed")
    }

    // ---- events (called on a Go thread) ------------------------------------

    internal fun onEvent(json: String) {
        val ev = try {
            JSONObject(json)
        } catch (_: JSONException) {
            return
        }
        when (ev.optString("type")) {
            "status" -> _status.value = CoreStatus.parse(ev.obj("status"))
            "gateways" -> setGateways(ev)
            "keyring" -> setKeyring(ev)
            "log" -> appendLog(ev.str("line", 600))
            "error" -> {
                val msg = ev.str("message", 300)
                post(msg.ifEmpty { ev.str("code", 32) })
            }
            else -> Unit // elevation_needed is desktop-only; unknown types ignored
        }
    }

    private fun setGateways(o: JSONObject) {
        _gateways.value = o.optJSONArray("gateways").mapObjects(256, Gateway::parse).sortedWith(Gateway.ordering)
    }

    private fun setKeyring(o: JSONObject) {
        _keyring.value = o.optJSONArray("entries").mapObjects(16, KeyringEntry::parse)
    }

    private fun appendLog(line: String) {
        if (line.isEmpty()) return
        synchronized(logLock) {
            logBuffer.addLast(line)
            while (logBuffer.size > MAX_LOG_LINES) logBuffer.removeFirst()
            _log.value = logBuffer.toList()
        }
    }
}
