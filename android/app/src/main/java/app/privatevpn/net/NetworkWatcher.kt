package app.privatevpn.net

import android.content.Context
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.os.Handler
import android.os.Looper

/**
 * Watches the physical (non-VPN) networks and reports changes to the core as
 * `sys.network_changed` (§10.3), debounced by one second. Also provides the
 * DNS servers of the underlying network for `SystemInfo()` (§11.2).
 */
class NetworkWatcher(context: Context, private val onChanged: () -> Unit) {
    private val cm = context.getSystemService(ConnectivityManager::class.java)
    private val main = Handler(Looper.getMainLooper())
    private val fire = Runnable { onChanged() }
    private var callback: ConnectivityManager.NetworkCallback? = null

    @Synchronized
    fun start() {
        if (callback != null || cm == null) return
        val cb = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) = changed()
            override fun onLost(network: Network) = changed()
            override fun onLinkPropertiesChanged(network: Network, linkProperties: LinkProperties) = changed()
        }
        val request = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            .build()
        try {
            cm.registerNetworkCallback(request, cb)
            callback = cb
        } catch (_: RuntimeException) {
            // TooManyRequestsException / SecurityException: discovery still
            // works, only the re-join after a network switch is slower.
        }
    }

    @Synchronized
    fun stop() {
        main.removeCallbacks(fire)
        val cb = callback ?: return
        callback = null
        try {
            cm?.unregisterNetworkCallback(cb)
        } catch (_: RuntimeException) {
        }
    }

    private fun changed() {
        main.removeCallbacks(fire)
        main.postDelayed(fire, 1_000)
    }

    companion object {
        /**
         * DNS servers of the underlying non-VPN network. Our own package is
         * excluded from the VPN (§9.5), so `activeNetwork` is normally already
         * the physical network; other networks are checked as a fallback.
         */
        fun underlyingDns(context: Context): List<String> {
            val cm = context.getSystemService(ConnectivityManager::class.java) ?: return emptyList()
            val candidates = LinkedHashSet<Network>()
            cm.activeNetwork?.let(candidates::add)
            @Suppress("DEPRECATION")
            cm.allNetworks.forEach(candidates::add)
            for (n in candidates) {
                val caps = cm.getNetworkCapabilities(n) ?: continue
                if (caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) continue
                if (!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)) continue
                if (!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) continue
                val dns = cm.getLinkProperties(n)?.dnsServers?.mapNotNull { it.hostAddress }?.take(4).orEmpty()
                if (dns.isNotEmpty()) return dns
            }
            return emptyList()
        }
    }
}
