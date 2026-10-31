package app.privatevpn.core

import org.json.JSONArray
import org.json.JSONObject

/**
 * Every string that comes out of Go (events, method results, INFO from a
 * remote gateway, beacon fields from anyone on the LAN) is untrusted
 * (ARCHITECTURE §10.6, T13). It is cleaned here once, at parse time, and the
 * UI renders it only with plain `Text()`.
 */
object Untrusted {

    /** Removes C0/C1 controls and bidi controls, trims, caps at [cap] code points (+ "…"). */
    fun text(raw: String?, cap: Int): String {
        if (raw.isNullOrEmpty()) return ""
        val sb = StringBuilder(minOf(raw.length, cap * 2 + 1))
        var count = 0
        var truncated = false
        var i = 0
        while (i < raw.length) {
            val cp = raw.codePointAt(i)
            i += Character.charCount(cp)
            if (isStripped(cp)) continue
            if (count == cap) {
                truncated = true
                break
            }
            // Lone surrogates cannot be rendered meaningfully; drop them.
            if (cp in 0xD800..0xDFFF) continue
            sb.appendCodePoint(if (cp == 0x2028 || cp == 0x2029) ' '.code else cp)
            count++
        }
        val out = sb.toString().trim()
        return if (truncated) "$out…" else out
    }

    private fun isStripped(cp: Int): Boolean =
        cp < 0x20 || cp in 0x7F..0x9F ||            // C0, DEL, C1
            cp in 0x202A..0x202E ||                  // LRE, RLE, PDF, LRO, RLO
            cp in 0x2066..0x2069 ||                  // LRI, RLI, FSI, PDI
            cp == 0x200E || cp == 0x200F ||          // LRM, RLM
            cp == 0x061C ||                          // ALM
            cp == 0xFEFF ||                          // BOM / ZWNBSP
            // Invisible format characters: a hostile name could hide text or
            // imitate another gateway's name with them (T13). ZWJ (U+200D) is
            // kept for emoji sequences.
            cp == 0x200B || cp == 0x200C ||          // ZWSP, ZWNJ
            cp in 0x2060..0x2064 ||                  // WJ, invisible operators
            cp == 0x180E ||                          // Mongolian vowel separator
            cp in 0xFFF9..0xFFFB ||                  // interlinear annotation
            cp in 0xE0000..0xE007F                   // tag characters

    private val ipv4 = Regex("""^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$""")
    private val hextet = Regex("^[0-9A-Fa-f]{1,4}$")

    fun isIPv4(s: String): Boolean = s.length <= 15 && ipv4.matches(s)

    /** Strict textual IPv6 check (no zone ids, no DNS lookups). */
    fun isIPv6(s: String): Boolean {
        if (s.length !in 2..45 || !s.contains(':')) return false
        var body = s
        val groupsNeeded = 8
        val lastColon = body.lastIndexOf(':')
        val tail = body.substring(lastColon + 1)
        if (tail.contains('.')) {
            if (!isIPv4(tail)) return false
            body = body.substring(0, lastColon + 1) + "0:0"
        }
        val parts = body.split("::")
        if (parts.size > 2) return false
        fun groups(p: String): List<String>? =
            if (p.isEmpty()) emptyList() else p.split(':').takeIf { g -> g.all { hextet.matches(it) } }
        return if (parts.size == 2) {
            val a = groups(parts[0]) ?: return false
            val b = groups(parts[1]) ?: return false
            a.size + b.size <= groupsNeeded - 1
        } else {
            val a = groups(parts[0]) ?: return false
            a.size == groupsNeeded
        }
    }

    /** Returns the address if it is a valid IPv4/IPv6 literal, else null. */
    fun ip(raw: String?): String? {
        val s = raw?.trim() ?: return null
        return if (isIPv4(s) || isIPv6(s)) s else null
    }

    /** "a.b.c.d/n" with a valid IPv4 address and prefix length. */
    fun ipv4Prefix(raw: String?): String? {
        val s = raw?.trim() ?: return null
        val slash = s.indexOf('/')
        if (slash <= 0) return null
        val len = s.substring(slash + 1).toIntOrNull() ?: return null
        return if (isIPv4(s.substring(0, slash)) && len in 0..32) s else null
    }
}

// --- org.json helpers (JSONObject.optString returns "null" for JSON null) ---

internal fun JSONObject.str(key: String, cap: Int): String =
    if (!has(key) || isNull(key)) "" else Untrusted.text(optString(key), cap)

internal fun JSONObject.long(key: String, default: Long = 0): Long =
    if (!has(key) || isNull(key)) default else optLong(key, default)

internal fun JSONObject.int(key: String, range: IntRange): Int? {
    if (!has(key) || isNull(key)) return null
    val v = optLong(key, Long.MIN_VALUE)
    return if (v >= range.first && v <= range.last) v.toInt() else null
}

internal fun JSONObject.double(key: String, range: ClosedFloatingPointRange<Double>): Double? {
    if (!has(key) || isNull(key)) return null
    val v = optDouble(key)
    return if (v.isFinite() && v in range) v else null
}

internal fun JSONObject.bool(key: String): Boolean = optBoolean(key, false)

internal fun JSONObject.obj(key: String): JSONObject? = if (isNull(key)) null else optJSONObject(key)

internal inline fun <T> JSONArray?.mapObjects(limit: Int, f: (JSONObject) -> T?): List<T> {
    if (this == null) return emptyList()
    val out = ArrayList<T>()
    for (i in 0 until minOf(length(), limit)) {
        val o = optJSONObject(i) ?: continue
        f(o)?.let(out::add)
    }
    return out
}

internal inline fun <T> JSONArray?.mapStrings(limit: Int, f: (String) -> T?): List<T> {
    if (this == null) return emptyList()
    val out = ArrayList<T>()
    for (i in 0 until minOf(length(), limit)) {
        if (isNull(i)) continue
        f(optString(i))?.let(out::add)
    }
    return out
}
