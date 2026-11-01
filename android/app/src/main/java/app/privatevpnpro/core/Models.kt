package app.privatevpnpro.core

import org.json.JSONObject

/*
 * UI models for the JSON documents of ARCHITECTURE §13.3 (gateway list),
 * §14.1 (status, keyring) and §10.5 (INFO). Parsing never throws on bad
 * fields: strings are cleaned and capped, numbers range-checked, addresses
 * validated; anything invalid becomes empty/null.
 */

enum class Access { MEMBER, KEY_CHANGED, LOCKED;
    companion object {
        fun parse(s: String) = when (s) {
            "member" -> MEMBER
            "key_changed" -> KEY_CHANGED
            else -> LOCKED
        }
    }
}

data class ClientStatus(
    // idle | joining | tunnel_up | connected | degraded | blocked. Once a
    // tunnel exists the core never removes it by itself (fail closed):
    // "degraded" holds traffic while reconnecting, "blocked" keeps it held
    // until the user reconnects or disconnects.
    val state: String = "idle",
    val gatewayId: String = "",
    val gatewayName: String = "",
    val networkLabel: String = "",
    val assignedIp: String = "",
    val since: Long = 0,
    val rx: Long = 0,
    val tx: Long = 0,
    val handshakeAgeSec: Long = -1,
    val degradedSince: Long = 0,
    /** Connected and the core reports no leak. */
    val isProtected: Boolean = false,
    /** "os" on Android: the kill switch is the system's "Block connections without VPN". */
    val killSwitch: String = "",
    val error: String = "",
    val errorCode: String = "",
) {
    /** A session (and on desktop possibly a block) exists; the VPN service must keep running. */
    val active: Boolean get() = state != "idle" && state.isNotEmpty()

    /** Traffic is held inside the tunnel instead of reaching the gateway. */
    val interrupted: Boolean get() = state == "degraded" || state == "blocked"

    companion object {
        private val states = setOf("idle", "joining", "tunnel_up", "connected", "degraded", "blocked")

        fun parse(o: JSONObject?): ClientStatus {
            if (o == null) return ClientStatus()
            val st = o.str("state", 16).let { if (it in states) it else if (it.isEmpty()) "idle" else it }
            val ip = o.str("assigned_ip", 18).let { Untrusted.ip(it.substringBefore('/'))?.let { _ -> it } ?: "" }
            return ClientStatus(
                state = st,
                gatewayId = o.str("gateway_id", 64),
                gatewayName = o.str("gateway_name", 32),
                networkLabel = o.str("network_label", 32),
                assignedIp = ip,
                since = o.long("since").coerceAtLeast(0),
                rx = o.long("rx").coerceAtLeast(0),
                tx = o.long("tx").coerceAtLeast(0),
                handshakeAgeSec = if (o.has("handshake_age_sec")) o.long("handshake_age_sec", -1) else -1,
                degradedSince = o.long("degraded_since").coerceAtLeast(0),
                isProtected = o.bool("protected"),
                killSwitch = o.str("kill_switch", 8),
                error = o.str("error", 300),
                errorCode = o.str("error_code", 40),
            )
        }
    }
}

/**
 * One entry of status.problems: something the user should know is wrong,
 * in plain words, with a suggested action. Kotlin adds its own entries
 * (e.g. [ACTION_VPN_SETTINGS] for Android's lockdown setting).
 */
data class Problem(
    val code: String,
    val severity: String, // error | warning | info
    val message: String,
    val action: String,   // disconnect | reconnect | settings | add_firewall | vpn_settings | ""
) {
    val rank: Int get() = when (severity) {
        "error" -> 0
        "warning" -> 1
        else -> 2
    }

    companion object {
        const val ACTION_VPN_SETTINGS = "vpn_settings"
        private val codeRe = Regex("^[a-z0-9_]{1,40}$")
        private val severities = setOf("error", "warning", "info")
        private val actions = setOf("disconnect", "reconnect", "settings", "add_firewall")

        fun parse(o: JSONObject): Problem? {
            val message = o.str("message", 400)
            if (message.isEmpty()) return null
            val code = o.str("code", 40)
            return Problem(
                code = if (codeRe.matches(code)) code else "",
                severity = o.str("severity", 8).let { if (it in severities) it else "warning" },
                message = message,
                action = o.str("action", 16).let { if (it in actions) it else "" },
            )
        }
    }
}

data class CoreStatus(
    val version: String = "",
    val client: ClientStatus = ClientStatus(),
    val problems: List<Problem> = emptyList(),
) {
    companion object {
        fun parse(o: JSONObject?): CoreStatus {
            if (o == null) return CoreStatus()
            return CoreStatus(
                version = o.str("version", 32),
                client = ClientStatus.parse(o.obj("client")),
                problems = o.optJSONArray("problems").mapObjects(16, Problem::parse).sortedBy { it.rank },
            )
        }
    }
}

data class Endpoint(
    val ip: String,
    val ctrlPort: Int?,
    val wgPort: Int?,
    val source: String,   // lan | manual | …
    val verified: Boolean,
)

data class ManualRef(val id: String, val label: String, val host: String, val ctrlPort: Int?)

data class Gateway(
    val id: String,
    val name: String,
    val os: String,
    val appVersion: String,
    val online: Boolean,
    val lastSeenMs: Long,
    val clientCount: Int?,
    val accepting: Boolean,
    val lanAccess: Boolean,
    val dualRole: Boolean,
    val access: Access,
    val networkId: String,
    val networkLabel: String,
    val endpoints: List<Endpoint>,
    val manual: ManualRef?,
    val fingerprint: String,
    val firstSeen: Long,
    val isNew: Boolean,
    val isSelf: Boolean,
) {
    /**
     * Connect is offered for manual entries always (a locked one opens the
     * key prompt, verified by INFO trial) and for LAN entries while their
     * beacon is fresh and says "accepting".
     */
    val canConnect: Boolean get() = !isSelf && (manual != null || (online && accepting))

    /** Display name; manual entries without a known pubkey are listed by label. */
    val title: String get() = name.ifEmpty { manual?.label?.ifEmpty { manual.host } ?: "" }.ifEmpty { "Unnamed gateway" }

    companion object {
        fun parse(o: JSONObject): Gateway? {
            val id = o.str("id", 64)
            if (id.isEmpty()) return null
            val flags = o.obj("flags")
            val network = o.obj("network")
            val manual = o.obj("manual")?.let {
                ManualRef(
                    id = it.str("id", 64),
                    label = it.str("label", 32),
                    host = it.str("host", 253),
                    ctrlPort = it.int("ctrl_port", 1..65535),
                )
            }
            return Gateway(
                id = id,
                name = o.str("name", 32),
                os = o.str("os", 16),
                appVersion = o.str("app_version", 16),
                online = o.bool("online"),
                lastSeenMs = o.long("last_seen_ms", -1),
                clientCount = o.int("client_count", 0..253),
                accepting = flags?.optBoolean("accepting", true) ?: true,
                lanAccess = flags?.bool("lan_access") ?: false,
                dualRole = flags?.bool("dual_role") ?: false,
                access = Access.parse(o.str("access", 16)),
                networkId = network?.str("id", 64) ?: "",
                networkLabel = network?.str("label", 32) ?: "",
                endpoints = o.optJSONArray("endpoints").mapObjects(3) { e ->
                    val ip = Untrusted.ip(e.str("ip", 45)) ?: return@mapObjects null
                    Endpoint(
                        ip = ip,
                        ctrlPort = e.int("ctrl_port", 1..65535),
                        wgPort = e.int("wg_port", 1..65535),
                        source = e.str("source", 16),
                        verified = e.bool("verified"),
                    )
                },
                manual = manual,
                fingerprint = o.str("fingerprint", 16),
                firstSeen = o.long("first_seen"),
                isNew = o.bool("is_new"),
                isSelf = o.bool("is_self"),
            )
        }

        /** §13.3 ordering: member (online first), then key_changed, then locked; by name. */
        val ordering: Comparator<Gateway> = compareBy<Gateway>(
            {
                when (it.access) {
                    Access.MEMBER -> if (it.online) 0 else 1
                    Access.KEY_CHANGED -> 2
                    Access.LOCKED -> 3
                }
            },
            { it.title.lowercase() },
            { it.id },
        )
    }
}

data class KeyringEntry(
    val id: String,
    val label: String,
    val createdHere: Boolean,
    val createdAt: Long,
    val lastUsed: Long,
    val gatewaysSeen: Int,
) {
    companion object {
        fun parse(o: JSONObject): KeyringEntry? {
            val id = o.str("id", 64)
            if (id.isEmpty()) return null
            return KeyringEntry(
                id = id,
                label = o.str("label", 32).ifEmpty { "Unnamed network" },
                createdHere = o.bool("created_here"),
                createdAt = o.long("created_at"),
                lastUsed = o.long("last_used"),
                gatewaysSeen = o.int("gateways_seen", 0..100_000) ?: 0,
            )
        }
    }
}

/** INFO document (§10.5), validated per §10.6. */
data class GatewayInfo(
    val name: String,
    val os: String,
    val osVersion: String,
    val appVersion: String,
    val uptimeSec: Long?,
    val gatewayUptimeSec: Long?,
    val clientCount: Int?,
    val lanAccess: Boolean,
    val dualRole: Boolean,
    val subnet: String,
    val mtu: Int?,
    val wgPort: Int?,
    val ctrlPort: Int?,
    val lanIps: List<String>,
    val publicIp: String,
    val publicIp6: String,
    val publicIpCheckedAt: Long,
    val stale: Boolean,
    val nat: String,
    val geoSource: String,      // geoip | manual | none
    val geoProvider: String,
    val country: String,
    val countryCode: String,
    val region: String,
    val city: String,
    val lat: Double?,
    val lon: Double?,
    val accuracyKm: Int?,
    val isp: String,
    val asn: String,
    val geoCheckedAt: Long,
    val tzName: String,
    val utcOffsetSec: Int?,
    val tzAbbrev: String,
    val nowSec: Long,
) {
    companion object {
        private val countryCodeRe = Regex("^[A-Z]{2}$")

        /** Returns null when the document must be rejected as a whole (§10.6). */
        fun parse(o: JSONObject?): GatewayInfo? {
            if (o == null) return null
            if (o.optInt("v", -1) != 1) return null
            val geo = o.obj("geo") ?: JSONObject()
            val tz = o.obj("tz") ?: JSONObject()
            val source = geo.str("source", 16).let { if (it == "geoip" || it == "manual") it else "none" }
            val lat = geo.double("lat", -90.0..90.0)
            val lon = geo.double("lon", -180.0..180.0)
            val hasCoords = source != "none" && lat != null && lon != null
            return GatewayInfo(
                name = o.str("name", 32),
                os = o.str("os", 16),
                osVersion = o.str("os_version", 32),
                appVersion = o.str("app_version", 16),
                uptimeSec = o.long("uptime_sec", -1).takeIf { it >= 0 },
                gatewayUptimeSec = o.long("gateway_uptime_sec", -1).takeIf { it >= 0 },
                clientCount = o.int("client_count", 0..253),
                lanAccess = o.bool("lan_access"),
                dualRole = o.bool("dual_role"),
                subnet = Untrusted.ipv4Prefix(o.str("subnet", 18)) ?: "",
                mtu = o.int("mtu", 576..9000),
                wgPort = o.int("wg_port", 1..65535),
                ctrlPort = o.int("ctrl_port", 1..65535),
                lanIps = o.optJSONArray("lan_ips").mapStrings(8) { s ->
                    Untrusted.text(s, 15).takeIf(Untrusted::isIPv4)
                },
                publicIp = Untrusted.ip(o.str("public_ip", 45)) ?: "",
                publicIp6 = Untrusted.ip(o.str("public_ip6", 45))?.takeIf { it.contains(':') } ?: "",
                publicIpCheckedAt = o.long("public_ip_checked_at"),
                stale = o.bool("stale"),
                nat = o.str("nat", 16).let { if (it in setOf("none", "nat", "cgnat")) it else "unknown" },
                geoSource = source,
                geoProvider = geo.str("provider", 32),
                country = geo.str("country", 64),
                countryCode = geo.str("country_code", 2).takeIf { countryCodeRe.matches(it) } ?: "",
                region = geo.str("region", 64),
                city = geo.str("city", 64),
                lat = if (hasCoords) lat else null,
                lon = if (hasCoords) lon else null,
                accuracyKm = geo.int("accuracy_km", 0..20_000),
                isp = geo.str("isp", 64),
                asn = geo.str("asn", 16),
                geoCheckedAt = geo.long("checked_at"),
                tzName = tz.str("name", 64),
                utcOffsetSec = tz.int("utc_offset_sec", -16 * 3600..16 * 3600),
                tzAbbrev = tz.str("abbrev", 8),
                nowSec = o.long("now"),
            )
        }
    }
}
