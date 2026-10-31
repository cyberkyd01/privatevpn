package app.privatevpn.core

import android.content.Context
import android.os.Build
import app.privatevpn.mobile.Callbacks
import app.privatevpn.net.NetworkWatcher
import app.privatevpn.vpn.PvnVpnService
import org.json.JSONArray
import org.json.JSONException
import org.json.JSONObject
import java.util.TimeZone

/**
 * Implements the Go-side `mobile.Callbacks` interface (§11.2). Every method
 * is called on a Go thread and must neither block for long nor throw
 * anything Go cannot turn into an error. Nothing received here is ever
 * written to logcat (§12.1).
 */
class CoreCallbacks(private val context: Context) : Callbacks {

    override fun onEvent(eventJSON: String?) {
        if (eventJSON == null) return
        try {
            CoreBridge.onEvent(eventJSON)
        } catch (_: Throwable) {
            // Never let a UI-side parsing problem unwind into Go.
        }
    }

    /**
     * Builds the VPN interface for the §9.1 TunnelConfig and returns its
     * detached fd; Go owns (and closes) the fd from then on. Any exception
     * becomes the Go error.
     */
    override fun establishTun(configJSON: String?): Long {
        val service = PvnVpnService.current()
            ?: throw IllegalStateException("VPN service is not running")
        val cfg = TunConfig.parse(configJSON ?: "")
        return service.establishTun(cfg).toLong()
    }

    override fun closeTun() {
        try {
            PvnVpnService.current()?.onTunClosedByCore()
        } catch (_: Throwable) {
            // closeTun has no error return: an exception left pending on the
            // JNI thread would abort the process on Go's next JNI call.
        }
    }

    override fun systemInfo(): String = try {
        JSONObject()
            .put("os_version", Build.VERSION.RELEASE.orEmpty())
            .put("model", Build.MODEL.orEmpty())
            .put("tz", TimeZone.getDefault().id.orEmpty())
            .put("dns", JSONArray(NetworkWatcher.underlyingDns(context)))
            .toString()
    } catch (_: Throwable) {
        "{}"
    }
}

/**
 * The parts of the §9.1 TunnelConfig that VpnService.Builder needs. The
 * document also carries the session private key and the PSK (consumed by
 * Go, not by Kotlin): it is parsed here only for address/dns/mtu and never
 * kept, logged or persisted.
 */
data class TunConfig(
    val address: String,
    val prefixLength: Int,
    val dns: List<String>,
    val mtu: Int,
    val sinkIpv6: Boolean,
) {
    companion object {
        fun parse(json: String): TunConfig {
            val o = try {
                JSONObject(json)
            } catch (_: JSONException) {
                throw IllegalArgumentException("invalid tunnel config")
            }
            val addr = o.optString("address")
            val slash = addr.indexOf('/')
            val ip = if (slash > 0) addr.substring(0, slash) else addr
            val len = if (slash > 0) addr.substring(slash + 1).toIntOrNull() else 32
            require(Untrusted.isIPv4(ip) && len != null && len in 8..32) { "invalid tunnel address" }
            val dns = o.optJSONArray("dns").mapStrings(4) { Untrusted.ip(it) }
            val mtu = o.optInt("mtu", 1280)
            require(mtu in 576..1420) { "invalid tunnel mtu" }
            return TunConfig(ip, len, dns, mtu, o.optBoolean("sink_ipv6", true))
        }
    }
}
