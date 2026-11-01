package app.privatevpnpro.vpn

import android.Manifest
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.app.ServiceCompat
import androidx.core.content.ContextCompat
import androidx.core.content.edit
import app.privatevpnpro.R
import app.privatevpnpro.core.Access
import app.privatevpnpro.core.ClientStatus
import app.privatevpnpro.core.CoreBridge
import app.privatevpnpro.core.CoreException
import app.privatevpnpro.core.TunConfig
import app.privatevpnpro.core.Untrusted
import app.privatevpnpro.ui.MainActivity
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull
import org.json.JSONObject

/**
 * Android's per-app VPN settings for Private VPN Pro, as the running service sees
 * them (VpnService.isAlwaysOn / isLockdownEnabled, API 29+). Lockdown
 * ("Block connections without VPN") is Android's kill switch: with it, the
 * system blocks every app's traffic outside the VPN even when Private VPN Pro is
 * not running.
 */
data class SystemVpnMode(val alwaysOn: Boolean, val lockdown: Boolean)

/**
 * Client-mode VPN (§9.5, §11.3). Started with a gateway id by the UI (or by
 * the system for always-on VPN, or after a restart by [BootReceiver]), it
 * goes foreground immediately, runs `client.connect` off the main thread and
 * lets Go call back into [establishTun] for the TUN fd.
 *
 * Fail closed: while a session exists — including `degraded` (traffic held,
 * reconnecting) and `blocked` (the connection failed; traffic stays held) —
 * the service keeps running and keeps the TUN, so apps cannot fall back to
 * the real network. It stops only once the core reports `idle`: after an
 * explicit Disconnect (app, notification, revoke) or a failure before any
 * tunnel existed.
 */
class PvpVpnService : VpnService() {

    companion object {
        const val ACTION_CONNECT = "app.privatevpnpro.action.CONNECT"
        const val ACTION_DISCONNECT = "app.privatevpnpro.action.DISCONNECT"
        const val EXTRA_GATEWAY_ID = "gateway_id"
        const val EXTRA_GATEWAY_NAME = "gateway_name"
        /** Set by [resumeAfterRestart]: wait for the network and retry instead of failing at once. */
        const val EXTRA_RESUME = "resume"

        private const val CHANNEL_ID = "vpn"
        private const val NOTIFICATION_ID = 1
        private const val HOLDER = "vpn"
        private const val PREFS = "ui"
        private const val KEY_LAST_GATEWAY = "last_gateway_id"
        private const val KEY_LAST_GATEWAY_NAME = "last_gateway_name"
        // "resume": a session was up and the user had not disconnected; the
        // next boot (or app update) reconnects to the last gateway.
        private const val KEY_RESUME = "resume_session"
        // Last value of isAlwaysOn() seen while running: the system starts
        // an always-on VPN itself after a restart.
        private const val KEY_SYSTEM_ALWAYS_ON = "system_always_on"
        private const val IDLE_STOP_DELAY_MS = 1_500L
        private const val CONNECT_GRACE_MS = 20_000L
        private const val MODE_POLL_MS = 5_000L
        private const val RESUME_WAIT_MS = 120_000L
        private const val RESUME_RETRY_MS = 5_000L

        @Volatile
        private var instance: PvpVpnService? = null

        private val _systemMode = MutableStateFlow<SystemVpnMode?>(null)

        /** Always-on / lockdown while the service runs (API 29+); null = unknown. */
        val systemMode: StateFlow<SystemVpnMode?> = _systemMode.asStateFlow()

        private val _tunMissing = MutableStateFlow(false)

        /**
         * A session exists but Android's VPN interface is gone (the core
         * closed it and could not create a new one): apps are not held
         * inside the VPN unless lockdown is on.
         */
        val tunMissing: StateFlow<Boolean> = _tunMissing.asStateFlow()

        /** The running service, used by CoreCallbacks.establishTun/closeTun. */
        fun current(): PvpVpnService? = instance

        /** Starts the service and a session to [gatewayId]; VPN consent must already be granted. */
        fun connect(context: Context, gatewayId: String, gatewayName: String, resume: Boolean = false) {
            val intent = Intent(context, PvpVpnService::class.java)
                .setAction(ACTION_CONNECT)
                .putExtra(EXTRA_GATEWAY_ID, gatewayId)
                .putExtra(EXTRA_GATEWAY_NAME, gatewayName)
                .putExtra(EXTRA_RESUME, resume)
            ContextCompat.startForegroundService(context, intent)
        }

        /** The user chose Disconnect: do not reconnect after the next restart. */
        fun forgetResume(context: Context) {
            prefs(context).edit { putBoolean(KEY_RESUME, false) }
        }

        /**
         * After a restart or an app update: reconnect to the last gateway if
         * a session was up when the device went down. Never prompts — it
         * needs VPN consent already granted — and leaves an always-on VPN to
         * the system, which starts the service itself.
         */
        fun resumeAfterRestart(context: Context) {
            val p = prefs(context)
            if (!p.getBoolean(KEY_RESUME, false)) return
            val id = Untrusted.text(p.getString(KEY_LAST_GATEWAY, null), 64)
            if (id.isEmpty() || instance != null || p.getBoolean(KEY_SYSTEM_ALWAYS_ON, false)) return
            val consent = try {
                VpnService.prepare(context)
            } catch (_: RuntimeException) {
                return
            }
            if (consent != null) return // consent revoked, or another VPN app is selected
            try {
                connect(context, id, Untrusted.text(p.getString(KEY_LAST_GATEWAY_NAME, null), 32), resume = true)
            } catch (_: RuntimeException) {
                // Not allowed to start a foreground service now (should not
                // happen for BOOT_COMPLETED / MY_PACKAGE_REPLACED).
            }
        }

        private fun prefs(context: Context) = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
    }

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
    private var connectJob: Job? = null
    private var graceJob: Job? = null
    private var idleStopJob: Job? = null
    private var seenActive = false
    private var stopping = false
    private var gatewayName = ""
    private var lastNotification = ""
    private var shownNotification = ""

    /** A VPN interface established by this service is open (Go owns its fd). */
    @Volatile
    private var tunOpen = false

    override fun onCreate() {
        super.onCreate()
        instance = this
        CoreBridge.acquire(HOLDER)
        createChannel()
        scope.launch { CoreBridge.status.collect { onStatus(it.client) } }
        scope.launch {
            // The user can change always-on / lockdown in system Settings at
            // any time; isAlwaysOn() and isLockdownEnabled() are cheap.
            while (isActive) {
                readSystemMode()
                delay(MODE_POLL_MS)
            }
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_DISCONNECT) {
            forgetResume(this)
            scope.launch { disconnectAndStop() }
            return START_NOT_STICKY
        }
        // ACTION_CONNECT from the UI or BootReceiver, or SERVICE_INTERFACE
        // from the system (always-on).
        gatewayName = Untrusted.text(intent?.getStringExtra(EXTRA_GATEWAY_NAME), 32)
        stopping = false
        readSystemMode()
        if (!goForeground(buildNotification(null))) {
            stopVpn()
            return START_NOT_STICKY
        }
        // A null intent means the system restarted us after the process was
        // killed mid-session (START_STICKY): reconnect like a boot resume.
        val restarted = intent == null
        startConnect(intent?.getStringExtra(EXTRA_GATEWAY_ID), restarted || intent?.getBooleanExtra(EXTRA_RESUME, false) == true)
        return START_STICKY
    }

    override fun onRevoke() {
        // Another VPN took over or the user revoked us in Settings.
        forgetResume(this)
        scope.launch { disconnectAndStop() }
    }

    override fun onDestroy() {
        instance = null
        tunOpen = false
        _tunMissing.value = false
        _systemMode.value = null
        // Not a user Disconnect (that clears "resume" first): if the system
        // tears the service down, the next boot may still resume.
        if (CoreBridge.status.value.client.active) CoreBridge.disconnect()
        scope.cancel()
        CoreBridge.release(HOLDER)
        super.onDestroy()
    }

    private fun readSystemMode() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) return
        val mode = try {
            SystemVpnMode(alwaysOn = isAlwaysOn, lockdown = isLockdownEnabled)
        } catch (_: RuntimeException) {
            return
        }
        if (_systemMode.value != mode) {
            _systemMode.value = mode
            prefs(this).edit { putBoolean(KEY_SYSTEM_ALWAYS_ON, mode.alwaysOn) }
        }
    }

    // ---- called from Go threads via CoreCallbacks -------------------------

    /** VpnService.Builder per §9.5; returns the detached fd (Go owns it). */
    fun establishTun(cfg: TunConfig): Int {
        val b = Builder()
            .setSession("Private VPN Pro")
            .addAddress(cfg.address, cfg.prefixLength)
            .addRoute("0.0.0.0", 0)
        if (cfg.sinkIpv6) b.addRoute("::", 0) // IPv6 is sunk inside the tunnel (D14)
        cfg.dns.forEach { b.addDnsServer(it) }
        b.setMtu(cfg.mtu)
        b.setBlocking(true)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) b.setMetered(false)
        // Our own sockets (control plane, WireGuard UDP) bypass the VPN (§7.4).
        b.addDisallowedApplication(packageName)
        b.setConfigureIntent(openAppIntent())
        val pfd = b.establish() ?: throw IllegalStateException("VPN permission is not granted")
        tunOpen = true
        _tunMissing.value = false
        return pfd.detachFd()
    }

    /**
     * Go closed the device: after a Disconnect (state goes idle → stop), or
     * while rebuilding the tunnel (a new interface follows at once). If a
     * session is still up but no interface came back, say so — the service
     * keeps running either way (fail closed).
     */
    fun onTunClosedByCore() {
        tunOpen = false
        scope.launch {
            delay(IDLE_STOP_DELAY_MS)
            CoreBridge.refreshStatus()
            val c = CoreBridge.status.value.client
            if (!c.active && connectJob?.isActive != true) {
                stopVpn()
            } else if (!tunOpen && c.state != "joining") {
                _tunMissing.value = true
                updateNotification(c)
            }
        }
    }

    // ---- session ----------------------------------------------------------

    private fun startConnect(requestedId: String?, resume: Boolean) {
        connectJob?.cancel()
        graceJob?.cancel()
        idleStopJob?.cancel()
        seenActive = false
        connectJob = scope.launch {
            val id = requestedId ?: pickAlwaysOnGateway()
            if (id == null) {
                CoreBridge.post("Open Private VPN Pro and choose a gateway to connect.")
                stopVpn()
                return@launch
            }
            try {
                if (resume) connectWithRetry(id) else CoreBridge.call("client.connect", JSONObject().put("gateway_id", id))
                prefs(this@PvpVpnService).edit {
                    putString(KEY_LAST_GATEWAY, id)
                    putString(KEY_LAST_GATEWAY_NAME, gatewayName)
                    putBoolean(KEY_RESUME, true)
                }
            } catch (e: CoreException) {
                CoreBridge.post(connectErrorText(e))
                // A resume that could not reach the gateway stays armed: the
                // user never chose Disconnect.
                if (!CoreBridge.status.value.client.active) stopVpn(keepResume = resume)
                return@launch
            }
            // client.connect may return before the state machine moves; give
            // it time, then stop if nothing ever happened.
            graceJob = scope.launch {
                delay(CONNECT_GRACE_MS)
                if (!seenActive && !CoreBridge.status.value.client.active) stopVpn()
            }
        }
    }

    /**
     * Resume after a restart: the network and gateway discovery may not be
     * up yet, so wait for the gateway to be listed and retry for a while.
     */
    private suspend fun connectWithRetry(id: String) {
        val deadline = System.currentTimeMillis() + RESUME_WAIT_MS
        withTimeoutOrNull(RESUME_WAIT_MS / 4) {
            CoreBridge.gateways.first { l -> l.any { it.id == id && it.canConnect } }
        }
        while (true) {
            try {
                CoreBridge.call("client.connect", JSONObject().put("gateway_id", id))
                return
            } catch (e: CoreException) {
                if (e.code == "locked" || System.currentTimeMillis() + RESUME_RETRY_MS > deadline) throw e
            }
            delay(RESUME_RETRY_MS)
        }
    }

    private fun connectErrorText(e: CoreException): String = when (e.code) {
        "locked" -> "Enter this gateway's key first."
        "not_found" -> "That gateway is no longer listed."
        "unreachable", "timeout" -> "The gateway did not respond. Check that it is online and reachable."
        else -> "Could not connect: ${e.message}"
    }

    private suspend fun pickAlwaysOnGateway(): String? {
        val last = prefs(this).getString(KEY_LAST_GATEWAY, null)
        // Beacons arrive every 3 s; the core may have just started.
        val list = withTimeoutOrNull(10_000) {
            CoreBridge.gateways.first { l -> l.any { it.access == Access.MEMBER && it.online } }
        } ?: return null
        // Only ever verified (member) entries — never auto-connect to a locked one (T13).
        val gw = list.firstOrNull { it.id == last && it.access == Access.MEMBER }
            ?: list.firstOrNull { it.access == Access.MEMBER && it.online }
            ?: return null
        gatewayName = gw.title
        return gw.id
    }

    private fun onStatus(c: ClientStatus) {
        if (stopping) return
        if (c.active) {
            seenActive = true
            idleStopJob?.cancel()
            idleStopJob = null
            if (c.gatewayName.isNotEmpty()) gatewayName = c.gatewayName
            if (tunOpen || c.state == "joining") _tunMissing.value = false
            updateNotification(c)
        } else if (seenActive && connectJob?.isActive != true && idleStopJob?.isActive != true) {
            // idle again: the user disconnected, or the attempt failed before
            // any tunnel existed. Degraded/blocked never get here.
            idleStopJob = scope.launch {
                delay(IDLE_STOP_DELAY_MS)
                if (!CoreBridge.status.value.client.active && connectJob?.isActive != true) stopVpn()
            }
        }
    }

    private suspend fun disconnectAndStop() {
        connectJob?.cancel()
        try {
            CoreBridge.call("client.disconnect")
        } catch (_: CoreException) {
        }
        stopVpn()
    }

    private fun stopVpn(keepResume: Boolean = false) {
        if (stopping) return
        stopping = true
        graceJob?.cancel()
        idleStopJob?.cancel()
        // No session is left to resume after a restart.
        if (!keepResume) forgetResume(this)
        _tunMissing.value = false
        ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    // ---- foreground notification ------------------------------------------

    private fun goForeground(n: Notification): Boolean = try {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(NOTIFICATION_ID, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SYSTEM_EXEMPTED)
        } else {
            startForeground(NOTIFICATION_ID, n)
        }
        true
    } catch (_: RuntimeException) {
        CoreBridge.post("Android did not allow the VPN service to start.")
        false
    }

    private fun createChannel() {
        val nm = getSystemService(NotificationManager::class.java) ?: return
        val ch = NotificationChannel(CHANNEL_ID, getString(R.string.vpn_channel_name), NotificationManager.IMPORTANCE_LOW)
        ch.description = getString(R.string.vpn_channel_description)
        ch.setShowBadge(false)
        nm.createNotificationChannel(ch)
    }

    private fun buildNotification(c: ClientStatus?): Notification {
        val name = gatewayName.ifEmpty { "gateway" }
        val lockdown = _systemMode.value?.lockdown == true
        // §11.4: state and gateway only. The tunnel address stays in the app
        // (a notification is readable on the lock screen and by listeners).
        val (title, text) = when {
            c != null && c.interrupted && _tunMissing.value && !lockdown ->
                "VPN interface lost — apps may use your real IP" to "Open Private VPN Pro, or tap Disconnect and connect again."
            c?.state == "degraded" -> "Connection lost — traffic blocked to protect your IP" to "Reconnecting to $name…"
            c?.state == "blocked" -> "Connection lost — traffic blocked to protect your IP" to "Open Private VPN Pro to reconnect, or tap Disconnect."
            c?.state == "connected" -> "Protected · connected to $name" to
                (c.networkLabel.takeIf { it.isNotEmpty() }?.let { "Network: $it" } ?: "Private VPN Pro")
            else -> "Connecting to $name…" to "Private VPN Pro"
        }
        lastNotification = "$title|$text"
        val disconnect = PendingIntent.getService(
            this, 1,
            Intent(this, PvpVpnService::class.java).setAction(ACTION_DISCONNECT),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_notification)
            .setContentTitle(title)
            .setContentText(text)
            .setStyle(NotificationCompat.BigTextStyle().bigText(text))
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setShowWhen(false)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setContentIntent(openAppIntent())
            .addAction(0, "Disconnect", disconnect)
            .setForegroundServiceBehavior(NotificationCompat.FOREGROUND_SERVICE_IMMEDIATE)
            .build()
    }

    private fun updateNotification(c: ClientStatus) {
        val n = buildNotification(c)
        val key = lastNotification
        if (key == shownNotification) return
        shownNotification = key
        // The notification permission may have been denied (13+); the
        // service keeps running without a visible notification (§11.4).
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) return
        getSystemService(NotificationManager::class.java)?.notify(NOTIFICATION_ID, n)
    }

    private fun openAppIntent(): PendingIntent = PendingIntent.getActivity(
        this, 0,
        Intent(this, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP),
        PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
    )
}
