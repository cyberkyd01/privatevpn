package app.privatevpnpro.ui

import java.time.Instant
import java.time.ZoneId
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter
import java.util.Locale
import kotlin.math.abs

/** Display helpers. Inputs are numbers that were already range-checked. */
object Format {
    private val dateTime = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm", Locale.US)
    private val utcClock = DateTimeFormatter.ofPattern("HH:mm:ss", Locale.US).withZone(ZoneOffset.UTC)
    private val utcDate = DateTimeFormatter.ofPattern("yyyy-MM-dd", Locale.US).withZone(ZoneOffset.UTC)

    fun bytes(n: Long): String {
        if (n < 1024) return "$n B"
        val units = arrayOf("KiB", "MiB", "GiB", "TiB")
        var v = n / 1024.0
        var i = 0
        while (v >= 1024 && i < units.lastIndex) {
            v /= 1024
            i++
        }
        return String.format(Locale.US, if (v < 10) "%.1f %s" else "%.0f %s", v, units[i])
    }

    /** "3d 4h", "2h 5m", "4m 10s", "12s". */
    fun duration(seconds: Long): String {
        if (seconds < 0) return "–"
        val d = seconds / 86_400
        val h = (seconds % 86_400) / 3_600
        val m = (seconds % 3_600) / 60
        val s = seconds % 60
        return when {
            d > 0 -> "${d}d ${h}h"
            h > 0 -> "${h}h ${m}m"
            m > 0 -> "${m}m ${s}s"
            else -> "${s}s"
        }
    }

    fun ago(seconds: Long): String = if (seconds < 0) "never" else "${duration(seconds)} ago"

    /** Unix seconds (or milliseconds, tolerated) → local "yyyy-MM-dd HH:mm". */
    fun timestamp(t: Long): String {
        if (t <= 0) return "–"
        val ms = if (t > 100_000_000_000L) t else t * 1000
        return dateTime.format(Instant.ofEpochMilli(ms).atZone(ZoneId.systemDefault()))
    }

    /** Seconds since a unix time (s or ms). */
    fun ageOf(t: Long, nowMs: Long = System.currentTimeMillis()): Long {
        if (t <= 0) return -1
        val ms = if (t > 100_000_000_000L) t else t * 1000
        return ((nowMs - ms) / 1000).coerceAtLeast(0)
    }

    fun utcOffset(sec: Int): String {
        val sign = if (sec < 0) "-" else "+"
        val a = abs(sec)
        return String.format(Locale.US, "UTC%s%02d:%02d", sign, a / 3600, (a % 3600) / 60)
    }

    /** Wall clock of a remote zone, rendered as a UTC clock of the shifted instant (§10.6). */
    fun remoteClock(wallMs: Long): Pair<String, String> {
        val i = Instant.ofEpochMilli(wallMs)
        return utcClock.format(i) to utcDate.format(i)
    }

    fun os(os: String): String = when (os) {
        "windows" -> "Windows"
        "macos" -> "macOS"
        "linux" -> "Linux"
        "android" -> "Android"
        "" -> "Unknown OS"
        else -> os
    }
}
