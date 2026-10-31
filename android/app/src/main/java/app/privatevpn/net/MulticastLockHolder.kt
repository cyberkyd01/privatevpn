package app.privatevpn.net

import android.content.Context
import android.net.wifi.WifiManager

/**
 * Holds `WifiManager.MulticastLock("pvn-discovery")` while the Go beacon
 * receiver runs (§11.4): Wi-Fi drivers filter multicast without it.
 */
class MulticastLockHolder(context: Context) {
    private val lock: WifiManager.MulticastLock? =
        (context.applicationContext.getSystemService(Context.WIFI_SERVICE) as? WifiManager)
            ?.createMulticastLock("pvn-discovery")
            ?.apply { setReferenceCounted(false) }

    @Synchronized
    fun acquire() {
        try {
            if (lock?.isHeld == false) lock.acquire()
        } catch (_: RuntimeException) {
        }
    }

    @Synchronized
    fun release() {
        try {
            if (lock?.isHeld == true) lock.release()
        } catch (_: RuntimeException) {
        }
    }
}
