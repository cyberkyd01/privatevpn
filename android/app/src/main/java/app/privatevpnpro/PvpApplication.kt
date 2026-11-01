package app.privatevpnpro

import android.app.Application
import androidx.lifecycle.DefaultLifecycleObserver
import androidx.lifecycle.LifecycleOwner
import androidx.lifecycle.ProcessLifecycleOwner
import app.privatevpnpro.core.CoreBridge

/**
 * Starts the Go core (`Mobile.start(filesDir/pvp, VERSION_NAME, CoreCallbacks)`)
 * while any Activity is started; PvpVpnService holds it as well while it runs
 * (§11.4). When neither holds it, the core is stopped and the MulticastLock
 * released.
 */
class PvpApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        CoreBridge.init(this)
        ProcessLifecycleOwner.get().lifecycle.addObserver(object : DefaultLifecycleObserver {
            override fun onStart(owner: LifecycleOwner) = CoreBridge.acquire(HOLDER_UI)
            override fun onStop(owner: LifecycleOwner) = CoreBridge.release(HOLDER_UI)
        })
    }

    private companion object {
        const val HOLDER_UI = "ui"
    }
}
