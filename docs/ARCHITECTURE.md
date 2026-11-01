# Private VPN Pro — Architecture and Protocol Specification (v1)

Status: **normative for v1.0**. Implementers build directly from this document. Where this document and an implementer's intuition disagree, this document wins; where this document is silent, choose the simplest option that keeps every security property in §4 and write it down in `docs/DECISIONS.md`.

Repository: `private-vpn-pro` (Go module path `github.com/OWNER/private-vpn-pro`; replace `OWNER` once at bootstrap, nothing else depends on it).

### Revision 2 (2026-11-01) — changelog

Two product decisions, applied throughout:

1. **"Anyone can see gateways; connecting needs the key."** Beacons are now **cleartext + a 16-byte HMAC membership tag** (§5.6, §6.2) so every Private VPN Pro device on the LAN lists every gateway; devices hold a **keyring** of up to 16 network keys (§5.1, §12.2); a gateway without a matching key is listed **locked** and the key is asked for once, at Connect (§13.3, §14). Entered keys are verified locally against the gateway's latest beacon tag. Location/public-IP details (INFO) stay members-only. New threat rows T13–T14 (§4). Device names are broadcast in cleartext, so the default name is non-identifying (`PC-1A2B`) and editable (D27).
2. **Android is client-only.** Android gateway mode, its foreground service, locks, battery prompt, GPS source and Android dual role are removed (§11). Gateways are Windows/macOS/Linux; clients are all four; pairing matrix is 3 × 4.

**Unchanged contracts** (implementation already in progress): §8 gateway engine/gwstack, §9 client/tunnel per OS, §13.5 privileged helper. The control-plane envelope and every control message (§6.1, §6.3–6.7) are byte-for-byte unchanged; only BEACON changed. One sentence in §8.6 ("Android: list passed by Kotlin…") is now moot and harmless.

---

Everything in this document that names a Go import path, function or constant was verified on 2026-11-01 against the module versions in §15.3 (`go doc` + cross-compilation of a probe program for linux/amd64, darwin/arm64, windows/amd64, windows/arm64 and android/arm64). Items marked **[verify]** were not probed and must be confirmed by the implementer before relying on them.

---

## 0. Reading guide

| If you are implementing… | Read |
|---|---|
| Anything | §1 (what it is), §2 (decisions), §4 (threat model), §12 (no-logs rules) |
| Crypto / wire protocol | §5, §6 |
| Gateway engine (netstack, forwarding, DNS, policy) | §7, §8 |
| Client engine, per-OS tunnel, privileged helper | §7, §9, §13.5 |
| Gateway details (ⓘ panel), geo / public IP | §10 |
| Desktop app (tray, web UI, local API) | §13, §14 |
| Android app (Kotlin, gomobile facade) | §11, §14.4 |
| CI / release | §15 |
| Scope / milestones / tests | §16, §17 |

---

## 1. What Private VPN Pro is

A private mesh of personal VPN gateways. Every installed app is the same product:

* **Gateway mode** ("act as VPN gateway") — **Windows, macOS and Linux only**: this device accepts tunnels from devices that hold its network's key and forwards their Internet traffic through its own connection. Gateways announce themselves on the LAN with a public beacon and are listed on **every** Private VPN Pro device's connection page, with a ⓘ details panel (location, public IP, time zone, local time, … — visible only to key holders).
* **Client mode** ("connect") — **Windows, macOS, Linux and Android**: this device routes all of its traffic through a chosen gateway. Android is client-only by product decision (Revision 2).

**Every pairing must work**: 3 gateway OSes × 4 client OSes, including same-OS pairs and a desktop device that is both at once (§7.4). The first real-world test (Windows gateway ← Android client on one Wi-Fi) is only the first milestone (§16), not a design boundary.

**Seeing** gateways requires nothing. **Connecting** requires that gateway's **Network Key** (§5) — a 256-bit secret created by the desktop gateway, shown as text + QR, scanned or pasted once on each device and kept in that device's **keyring**. A gateway whose key you do not hold is listed with a lock; tapping Connect asks for the key one time. **The Network Key is the only thing gating access** — there are no per-device accounts, certificates or passwords. Share it only with devices you own or people you trust with your Internet connection; the UI must say this at the moment the key is shown. Revoking = resetting the key on the gateway; every device must then enter the new one.

Clients are **ephemeral and anonymous**: a client presents a freshly generated per-session WireGuard key and nothing else; gateways hold client state in memory only and never write any of it anywhere (§12).

---

## 2. Decision register

Each row: the decision, the one-line reason, and what was rejected. Rows marked ⚠ overrule or sharpen the initial leaning that this document was asked to challenge.

| # | Decision | Why | Rejected |
|---|---|---|---|
| D1 | One Go core (`core/…`) for all four OSes; data plane is `golang.zx2c4.com/wireguard` (wireguard-go). | One protocol implementation, one test suite; wireguard-go is the reference userspace WG. | Kernel WireGuard (needs root everywhere); OpenVPN/IPsec (heavier, no userspace story). |
| D2 | Gateway mode is **fully userspace**: wireguard-go writes decrypted packets into a gVisor `tcpip` stack that we run as a *router* (promiscuous + spoofing NIC, TCP/UDP forwarders that dial real destinations with ordinary OS sockets). No TUN, no OS NAT, no admin rights. | Identical on Windows/macOS/Linux; Windows NAT/ICS is unreliable; no privileges → gateway mode can never be the cause of a UAC prompt. | OS NAT (`iptables`/ICS/`pf`): privileged, three different implementations. |
| D3 | Client mode uses a real TUN (wintun / utun / `/dev/net/tun` / `VpnService`). | Only way to capture all traffic of the device. | tun2socks-style per-app proxying (does not capture everything). |
| D4 ⚠ | Desktop client mode runs in a **privileged helper subprocess** (`private-vpn-pro tunnel-helper`) spawned on demand (UAC / admin password / polkit); the tray + web UI + gateway engine stay unprivileged. Linux may skip the helper when the binary has `cap_net_admin`. | Least privilege, browser launched from an unprivileged process, gateway mode never needs elevation, no service installer in v1. | `requireAdministrator` manifest (UAC on every launch, autostart blocked by UAC, elevated browser); relaunching the whole app elevated (same problems); a Windows service / launchd daemon (right long-term, too much for v1; the helper's IPC is designed so that it can later be hosted by a service unchanged). |
| D5 | Membership = 32-byte random **Network Key** (NK) per network; subkeys via HKDF-SHA256 with domain-separated labels (§5.2). No PAKE, no PKI. Devices keep a **keyring** of ≤ 16 keys; a desktop gateway serves exactly one network. | 256-bit entropy → no offline attack; one secret → frictionless onboarding (QR / paste, asked once per network). | PAKE (unneeded with high-entropy key); per-device certificates (enrollment UX, revocation infra); one key per device (cannot use two friends' gateways). |
| D6 | Transport crypto for beacons and control = **XChaCha20-Poly1305** with 192-bit random nonces. | Many devices encrypt under the same key with no coordination; random 192-bit nonces are safe, 96-bit are not. | ChaCha20-Poly1305 (nonce coordination), AES-GCM (same + no hardware AES on some phones). |
| D7 ⚠ | WireGuard peers additionally use a network-wide **PresharedKey** derived from NK (§5.2). | A non-member who somehow learns a public key still cannot complete a handshake; cheap post-quantum hedge for passive attackers. | — |
| D8 ⚠ | Discovery = **cleartext** UDP beacons carrying a 16-byte **HMAC membership tag** (§5.6), sent to multicast `239.255.77.77:51822` **and** subnet-directed broadcast on every physical IPv4 interface, every 3 s. Every Private VPN Pro device lists every gateway; the tag tells a key holder which of its keys matches. | Product requirement "see gateways without the key"; a MAC (not AEAD) keeps the body public while proving membership and enabling instant local "wrong key" feedback; tag reveals nothing to non-holders. | Encrypted beacons (Revision 1; invisible without the key); mDNS/DNS-SD (extra dependency, no membership proof); multicast only (dropped by many APs/phones). |
| D9 ⚠ | Control plane = **UDP** on port 51821 (separate from WG 51820); every request is padded so that the response is never larger than the request (amplification factor ≤ 1). | Stateless server, nothing to exhaust, silent to non-members; TCP would need connection limits and TLS-less framing. | TCP (connection state, SYN floods); multiplexing on the WG port (would require a custom `conn.Bind`). |
| D10 | Rich gateway details travel in a separate **INFO** request/response (JSON inside AEAD), not in the beacon. | Beacons stay small and constant; details are needed for manually added gateways too; details refresh independently. | Inline in beacon (≈4× beacon size, every 3 s, cannot serve manual gateways). |
| D11 ⚠ | Per-gateway tunnel subnet is **derived from the gateway's public key**: `10.77.H.0/24`, H ∈ 1..254 (§7.2). | Dual-role devices and multi-gateway networks get distinct subnets without configuration. | Fixed `10.77.0.0/24` (collides when a device is both client and gateway). |
| D12 ⚠ | **Dual role allowed on desktop** with *direct-exit* semantics: a device that is both gateway and client serves its clients through its **own** physical connection; it never chains them through its upstream gateway. (Android has no gateway mode, so no dual role there.) | Chaining creates forwarding loops that cannot be detected (clients are anonymous) and buys little (any client can reach the far gateway directly). Direct-exit needs only socket/route exclusions that are required anyway. | Forbid dual role (worse UX); chaining (loop hazard, needs upstream-disclosure in beacons). |
| D13 ⚠ | Gateway policy: **clients get Internet only by default**; "Allow my local network" is a per-gateway toggle; the gateway host itself (loopback, all its interface addresses, link-local, multicast, the tunnel subnets) is **always** unreachable from clients. | Least privilege; a member is not necessarily trusted with your LAN; the host block prevents clients from reaching the local web UI or host services via the forwarder. | LAN open by default. |
| D14 | IPv4 inside the tunnel only; IPv6 is *sunk* (client routes `::/0` into the tunnel and drops it; gateway's DNS forwarder answers AAAA with an empty answer). | Removes v6 leaks and v6 timeouts without implementing v6 forwarding in v1. | Dual-stack forwarding (later). |
| D15 | Tunnel MTU **1280** everywhere. | Works over every underlay (mobile, PPPoE, v6) without PMTU discovery; throughput loss is < 5 %. | 1420 (breaks on some mobile and v6 underlays). |
| D16 | Gateway acts as **DNS forwarder** on its tunnel IP (`10.77.H.1:53`, UDP+TCP), upstream = the gateway host's resolvers. | Clients get working DNS with no leak to their own ISP; gateway host does no caching and keeps no query log. | Pushing the gateway's upstream resolvers to clients (leaks client queries to a resolver that sees them unencrypted on the gateway's LAN; breaks for `127.0.0.53`-style local stubs). |
| D17 | Desktop UI = tray icon (`fyne.io/systray`) + loopback web UI (`127.0.0.1:47771`, Go `net/http`, vanilla HTML/JS embedded with `go:embed`). | No GUI toolkit per OS; "tray only"; no npm supply chain. | Fyne/Wails/Electron windows (dock/taskbar presence, size). |
| D18 | Web UI auth: tray opens a URL with a **single-use 60 s token in the fragment**, exchanged for a `SameSite=Strict`, `HttpOnly` session cookie + in-memory CSRF token; strict `Host`/`Origin` checks; strict CSP. | Defeats DNS rebinding, CSRF, clickjacking and other local users; same-user malware is out of scope (§4). | Random port as the only secret (port scans), Basic auth (phishable, no CSRF story). |
| D19 | Android = Kotlin + Jetpack Compose (Material 3), minSdk 26, Go core via `gomobile bind` AAR. **Kotlin contains zero protocol or crypto code.** | Single protocol implementation; Kotlin only does what only Kotlin can (VpnService, foreground service, MulticastLock, camera). | Views/XML (more boilerplate); Flutter/RN (second runtime). |
| D20 ⚠ | Android runs exactly one foreground service: the `VpnService`, declared `systemExempted`. | Android is client-only (D26); the VPN exemption is the only FGS type we need. | `connectedDevice` gateway service (Revision 1, removed). |
| D21 | QR: desktop shows the key as text + QR (generated in Go); Android scans with `zxing-android-embedded` and can also paste. | The natural enrol flow (show on PC, scan with phone) is cheap to include. | Text only in v1. |
| D22 | Persistence = one JSON file per device, `0600` in a `0700` directory (per-OS paths in §12.2); Android app-private storage with backup disabled. OS keystore wrapping (DPAPI / Keychain / Android Keystore) is v1.1. | Simplest correct thing; keystore wrapping adds a per-OS test matrix without changing the trust boundary (same-user access). | — |
| D23 | Zero-knowledge directory/rendezvous server for off-LAN discovery: **specified in outline (§6.8), not in v1**. Manual `host:port` is the v1 off-LAN path. | Needs hosting, a second deployable, and NAT traversal to be truly useful. | — |
| D24 | Logging: in-memory ring buffer only; wireguard-go runs at `LogLevelSilent` on gateways. | wireguard-go's own log lines contain peer key prefixes and endpoints. | File logs. |
| D25 ⚠ | **Public beacon, private details.** Non-holders see the beacon body (name, OS, version, ports, flags, client count, gateway public key) and its source IP; everything in the ⓘ panel beyond that (public IP, country/region/city, lat/lon, time zone, live time, ISP, LAN IPs, uptime) stays in INFO under `K_ctrl`, i.e. key holders only. A locked ⓘ panel shows the public fields plus "Enter the key to see location details and connect". | The public part is exactly what a new device needs to recognise a gateway and decide to enter its key; location and public IP are sensitive and gain nothing by being public. | Everything public (location leak on shared LANs); everything private (contradicts the product decision). |
| D26 ⚠ | **Android is client-only.** No gateway engine runs on Android; no gateway service, locks, battery prompt, GPS or dual role. | Product decision; also removes the least reliable component (background survival on vendor ROMs). | Android gateway (Revision 1). |
| D27 | Default gateway name is non-identifying: `PC-xxxx` / `Mac-xxxx` / `Linux-xxxx` with `xxxx` = first 4 hex chars of the key fingerprint; user-editable; the Gateway page says the name is visible to every Private VPN Pro device on the LAN. | Names are now cleartext on any LAN the gateway is on. | Hostname default (often a person's name). |

---

## 3. System overview

```
                 LAN (Wi-Fi / Ethernet)                        Internet
   ┌──────────────┐  beacons (UDP 51822, multicast+bcast)  ┌──────────────┐
   │  Member A    │ ◄───────────────────────────────────── │              │
   │ (client)     │  JOIN/RENEW/INFO (UDP 51821, AEAD)     │  Member B    │ ──► public IP of B
   │              │ ─────────────────────────────────────► │ (gateway)    │
   │  TUN 10.77.H.2 ═══ WireGuard (UDP 51820) ═══════════► │ gVisor stack │
   └──────────────┘                                        │  10.77.H.1   │
                                                           └──────────────┘
```

Roles are per device and independent:

| Role | OSes | Needs privileges? | Listens on | Persists |
|---|---|---|---|---|
| Device (always) | all four | no | 51822/udp (beacon receiver) | keyring, device name (desktop), settings, known gateways |
| Gateway | Windows, macOS, Linux | no (plus a firewall allow-rule on Windows/macOS) | 51820/udp (WG), 51821/udp (control), beacon sender | its static WG key pair, which keyring entry it serves, gateway settings |
| Client | all four | yes (TUN) — via helper on desktop, VpnService on Android | ephemeral WG port | nothing about sessions |

Process model per OS:

| OS | Processes |
|---|---|
| Windows / macOS / Linux | `private-vpn-pro` (tray, web UI, core: discovery, gateway engine, control client) + on demand `private-vpn-pro tunnel-helper` (elevated; TUN + client WG device + routes/DNS). |
| Android | one app process: Kotlin UI + `PvpVpnService` (client) + Go core (AAR). The gateway engine is compiled out of the mobile build (`//go:build !android` on `core/gateway`, `core/gwstack`, `core/geo`). |

---

## 4. Threat model

Assets: the Network Key; the gateway's Internet connection and LAN; client traffic contents and metadata; client identity (must never be recorded anywhere); the gateway host itself (its services, its loopback); the local web UI.

| # | Attacker | Capability | Mitigation / explicit acceptance |
|---|---|---|---|
| T1 | **Non-holder on the LAN** (any device without the key, incl. hostile ones) | Sniff, inject, replay, flood; spoof source addresses | **By design (Revision 2) sees the public beacon**: gateway name, OS, app version, ports, flags, client *count*, gateway WG public key, source IP. Cannot: read or forge control messages (AEAD under `K_ctrl`); complete a WG handshake (static-key auth + network PSK, D7); learn which network a gateway belongs to or whether two gateways share one (the tag is an HMAC under an unknown key — indistinguishable from random); see INFO details (location, public IP, LAN IPs…). Replays: beacon `(instance_id, counter)` monotonic check for verified entries; control messages carry a 24-byte nonce (cached 120 s) and ±60 s timestamp; lease operations need a 16-byte lease token. Floods: cheap magic/length filtering, token-bucket limits (§6.7). **Accepted:** the public beacon fields are public; WG packet sizes/timing observable. |
| T2 | **Internet scanner** hitting a port-forwarded gateway | Probes, floods | Both UDP listeners are silent to anything that does not authenticate (WG is silent by design; control drops on AEAD failure, never answers). **Accepted:** CPU for one AEAD open per probe (≈1 µs), bounded by the global token bucket. |
| T3 | **Malicious or compromised key holder** (holds one network's NK) | Everything a member of that network can do | Can run a rogue gateway *that verifies* for that network and MITM/observe any client that chooses it → UI shows a gateway's key fingerprint and a "new gateway" badge for keys never seen before (TOFU hint, §13.3). Can use your Internet connection (that is the feature) and, if you enabled it, your LAN. Cannot reach your host (D13), cannot see other clients (per-peer WG keys; client-to-client traffic blocked), cannot evict others (lease tokens), cannot exhaust the gateway (per-source and global limits, address pool of 253). Learns nothing about the victim's **other** keyring networks (tags under other keys are opaque). **Revocation = Reset key** on the gateway (regenerate; re-enter on the devices you keep — their old key stops verifying and the gateway shows locked again). **Accepted:** holding a key is trust; the UI says so. |
| T4 | **Compromised gateway host** | Sees client traffic in clear | Inherent to any VPN; it is the member's own device. Not mitigated. |
| T5 | **Other local users** on a desktop host | Connect to `127.0.0.1:47771`; read process lists | No session without a token; tokens are 256-bit, single-use, 60 s; `/api/v1/session` rate-limited; state file is `0600`. **Accepted:** on multi-user Unix hosts the single-use token is briefly visible in `xdg-open`/`open` argv; the window is one process spawn and the token dies on first use. |
| T6 | **Same-user malware** | Read our files/memory, talk to our pipe | Out of scope: it is the same trust domain as the app. Hardening (keystore-wrapped keys) in v1.1 does not change this. |
| T7 | **Malicious web page** in the user's browser | DNS rebinding, CSRF, clickjacking, XSS, port probing | `Host` must equal `127.0.0.1:<port>` exactly; cookie `SameSite=Strict`; `Origin`/`Sec-Fetch-Site` check + CSRF header on every non-GET; no CORS headers; CSP `default-src 'self'`, no inline script, `frame-ancestors 'none'`; all untrusted strings rendered with `textContent` (§10.6). Port probing learns only "an HTTP server with a login page". |
| T8 | **DoS / resource exhaustion** against a gateway | Join floods, flow floods, slowloris via forwarder, memory blow-up | Address pool cap (253), lease expiry (120 s), per-client flow caps (1024 TCP / 512 UDP), global caps (8192 / 4096), new-flow rate limit, TCP pending-SYN cap (`maxInFlight` 256), UDP idle timeouts, bounded gVisor buffers, control-plane token buckets (§8.7). |
| T9 | **Key theft at rest** | Read the state file from disk image / backup | `0600`/`0700`; Windows path is `%LOCALAPPDATA%` (never Roaming); Android `allowBackup=false` + `dataExtractionRules` exclude everything; no cloud sync. v1.1: DPAPI / Keychain / Android Keystore wrapping. **Accepted in v1:** full-disk access by an attacker with the user's rights = key theft. |
| T10 | **Supply chain** | Malicious dependency / build | `go.sum` pinned; wintun zip pinned by SHA-256; GitHub Actions pinned by commit SHA; no npm; release artifacts carry `SHA256SUMS`. |
| T11 | **Traffic attribution** | Client's actions appear to come from the gateway's IP | Inherent. UI text when enabling gateway mode: "Members' traffic will exit from your Internet connection and carry your public IP." |
| T12 | **Clock skew** | Wrong clocks make timestamps fail | Explicit error "clock difference too large" surfaced to the user; windows are ±60 s (control) and ±120 s (beacons). |
| T13 | **Beacon spoofing / list spam** (anyone on the LAN) | Forge beacons with any name, OS, ports or public key; impersonate a real gateway's public key from another source IP; flood thousands of fake gateways | A forged beacon can only ever produce a **locked, unverified** entry: a verified entry requires a tag under a key in the receiver's keyring. Connecting to a forged entry is harmless: JOIN/INFO are AEAD under `K_ctrl`, so a fake gateway cannot answer and the client times out ("gateway did not respond"); a client never auto-connects to unverified entries. Impersonation of a verified key: once a public key has a verified beacon, unverified beacons for that key are ignored. Spam: unverified entries capped at 16 total / 4 per source IP, ≤ 2 unverified beacons/s accepted per source, LRU eviction, verified entries never evicted by unverified ones (§6.2). UI: verified entries first; locked entries carry a lock badge and the word "unverified" in the ⓘ panel. **Accepted:** a hostile LAN can show you fake names; it cannot make you connect anywhere real. |
| T14 | **Cleartext names and metadata** on shared LANs | Learn that a person runs a gateway, its name, OS, version, client count | Default name is non-identifying (D27) and the Gateway page states what is broadcast; the user may stop beacons by turning gateway mode off. Version disclosure is accepted (needed for compatibility hints); client count is a count only. **Accepted:** presence of a gateway on the LAN is public. |

---

## 5. Keys and cryptography

### 5.1 Network Key (NK)

* 32 bytes from `crypto/rand`, generated by a desktop gateway ("Create network", or implicitly on first gateway enable).
* **String form** (shown as text and as QR, pasted or scanned on other devices):

  ```
  raw   = NK(32) || check(2)       where check = SHA-256("pvp1 key check" || NK)[0:2]
  body  = Base32(raw)              RFC 4648 alphabet A–Z2–7, no padding → 55 chars
  text  = "PVP1-" + body split into 11 groups of 5 joined by "-"
  e.g.  PVP1-K7Q2M-ZB3XW-… (70 chars total)
  ```

  Parsing: strip whitespace and `-`, uppercase, require prefix `PVP1`, decode 55 chars, verify check. Accept the QR payload byte-for-byte equal to `text`.
* **Keyring**: a device holds up to **16** network keys (§12.2), each with a local label and timestamps. Keys are created only by desktop gateways ("Create network" happens implicitly when gateway mode is first enabled with an empty keyring, or explicitly from the Networks page). Clients never create keys. Adding a key that is byte-identical to an existing entry reuses that entry.
* A **desktop gateway serves exactly one network** (`gateway.network_id` → keyring entry). Switching it restarts the gateway (all peers drop).
* The key is displayed only on explicit user action ("Show key") and copied to the clipboard only on explicit action.

### 5.2 Derived keys (HKDF-SHA256, Go `crypto/hkdf`)

All derivations: `hkdf.Key(sha256.New, NK, salt, info, length)` with `salt = []byte("PrivateVPNPro-v1")`.

| Name | `info` label | Length | Used for |
|---|---|---|---|
| `K_beacon` | `"pvp1 beacon"` | 32 | **HMAC-SHA256 key** for the beacon membership tag (§5.6) — beacons are cleartext |
| `K_ctrl` | `"pvp1 control"` | 32 | AEAD key for all control messages (JOIN/RENEW/LEAVE/INFO/ERROR) |
| `K_psk` | `"pvp1 wg psk"` | 32 | WireGuard `preshared_key` on every peer of every tunnel in the network |
| `K_dir` | `"pvp1 directory"` | 32 | (v1.1) directory blob encryption |
| `DirID` | `"pvp1 directory id"` | 16 | (v1.1) opaque network identifier sent to a directory server |

No cleartext network identifier is ever transmitted on the LAN. Receivers trial-verify each beacon's tag against every key in their keyring (≤ 16 HMACs over 100 bytes — negligible); control responses are trial-decrypted only when a client has sent a request under a specific key (the client knows which key it used).

### 5.3 AEAD

`golang.org/x/crypto/chacha20poly1305.NewX(key)` — XChaCha20-Poly1305, 24-byte nonce from `crypto/rand` for every message, 16-byte tag. Associated data is defined per message in §6.1.

### 5.4 WireGuard keys

* Gateway: one static X25519 key pair generated when gateway mode is first enabled, persisted (§12.2). Its public key is the gateway's identity (`gateway_id` = base64url, fingerprint = first 10 hex chars of SHA-256(pubkey)).
* Client: a **fresh** X25519 key pair per session (`crypto/ecdh.X25519()` or `device.NewPrivateKey`), held in memory, discarded on disconnect. Never persisted, never reused.
* Every peer entry carries `preshared_key = K_psk`.

### 5.5 Randomness and zeroisation

`crypto/rand` only. Go cannot guarantee zeroisation; we overwrite key slices on disconnect as best effort and do not claim more.

### 5.6 Beacon membership tag

```
tag = HMAC-SHA256(K_beacon, beacon[0:100])[0:16]      // header (4) + cleartext body (96)
```

Verified with `hmac.Equal` (constant time). Properties: without `K_beacon` the tag is indistinguishable from random, so non-holders cannot tell which network a gateway serves or whether two gateways share one; a holder gets a yes/no per keyring entry; a replay is detected by the covered `(instance_id, counter)`; a forged body cannot carry a valid tag. The tag also gives **instant local verification of a typed/scanned key**: derive `K_beacon` from the candidate key and check it against the gateway's most recent raw beacon (§13.3) — no network round trip.

---

## 6. Wire protocol

All multi-byte integers are **big-endian**. All messages are single UDP datagrams. Max datagram size on the wire: **1200 bytes** (QUIC-safe; never fragments).

### 6.1 Envelopes

Every datagram starts with the same 4-byte header. **Control messages** (types 0x10–0x7F) continue with a nonce and AEAD ciphertext; the **BEACON** (0x01) continues with a cleartext body and a membership tag (§6.2).

```
Control envelope (unchanged from Revision 1):
offset  size  field
0       2     magic      = 0x50 0x56  ("PV")
2       1     version    = 0x01
3       1     type       (table below)
4       24    nonce      (random, XChaCha20-Poly1305)
28      n+16  ciphertext = XChaCha20-Poly1305.Seal(key, nonce, plaintext, ad)
```

| type | name | key | direction | plaintext size | datagram size |
|---|---|---|---|---|---|
| 0x01 | BEACON | `K_beacon` (HMAC tag only; body is cleartext) | gateway → LAN | 96 cleartext | 116 |
| 0x10 | JOIN_REQ | `K_ctrl` | client → gateway | 132 fixed | 176 |
| 0x11 | JOIN_RESP | `K_ctrl` | gateway → client | 132 fixed | 176 |
| 0x12 | RENEW_REQ | `K_ctrl` | client → gateway | 64 fixed | 108 |
| 0x13 | RENEW_RESP | `K_ctrl` | gateway → client | 64 fixed | 108 |
| 0x14 | LEAVE | `K_ctrl` | client → gateway | 64 fixed | 108 (no response) |
| 0x20 | INFO_REQ | `K_ctrl` | member → gateway | 1156 fixed | 1200 |
| 0x21 | INFO_RESP | `K_ctrl` | gateway → member | 10 + json (≤ 1100) | ≤ 1154 |
| 0x7F | ERROR | `K_ctrl` | gateway → requester | 16 fixed | 60 |

**Associated data (AD) for control messages:**
* Requests and LEAVE: the 28-byte envelope header (bytes 0–27).
* Responses (JOIN_RESP, RENEW_RESP, INFO_RESP, ERROR): the 28-byte header **followed by the 24-byte nonce of the request being answered** (52 bytes). A response therefore authenticates only for the request it answers; replaying it against a different request fails.

**Receiver pre-checks before any AEAD/HMAC work** (cheap drop of junk/floods): datagram length ≥ 44 (control) or = 116 (beacon) and ≤ 1200; magic and version match; type known; length equals the fixed size for that type (or within bounds for INFO_RESP). On any failure: drop silently, count in metrics, never respond.

Padding bytes are zero on encode and ignored on decode. Unknown flag bits are ignored. Fields marked *reserved* are zero.

### 6.2 BEACON (0x01) — cleartext body + membership tag, 116 bytes total

```
offset size  field
0      2     magic         = 0x50 0x56 ("PV")
2      1     version       = 0x01
3      1     type          = 0x01
--- body (cleartext, 96 bytes) ---
4      32    gw_pubkey     gateway's static WireGuard public key
36     8     ts            unix seconds (uint64)
44     8     instance_id   random per gateway-engine start
52     4     counter       uint32, +1 per beacon sent, starts at 1
56     2     wg_port       UDP port of the WireGuard listener
58     2     ctrl_port     UDP port of the control listener
60     2     flags         bit0 accepting_clients, bit1 lan_access, bit2 details_available, bit3 dual_role (gateway is itself connected to a gateway)
62     1     os            1 windows, 2 macos, 3 linux (4 android, 5 ios reserved — never sent in v1)
63     1     client_count  0..255 (count only)
64     3     app_version   major, minor, patch
67     1     name_len      0..32
68     32    name          UTF-8 gateway name, zero padded
--- tag ---
100    16    tag           = HMAC-SHA256(K_beacon, bytes[0:100])[0:16]
```

All body fields are **public** (D25). Flags are low-sensitivity and are kept public so the list can show "LAN access" / "dual role" hints before a key is entered.

Sending: every **3 s ± 10 % jitter** per physical IPv4 interface (up, non-loopback, not our own tunnel interface) to **both** `239.255.77.77:51822` (TTL 1, `IP_MULTICAST_IF` = that interface) and the interface's **subnet-directed broadcast** (`SO_BROADCAST`). Source port = the control port. Beacons are sent only while gateway mode is enabled, under the `K_beacon` of the gateway's one network.

Receiving (**every device**, always, while the app runs): one `UDPConn` on `0.0.0.0:51822` with `SO_REUSEADDR` (+`SO_REUSEPORT` on Unix) and `golang.org/x/net/ipv4.PacketConn.JoinGroup` on every eligible interface (re-join on network change). Android holds a `MulticastLock` while this socket is open (§11.4). Processing order:

1. Pre-checks (§6.1); `|now − ts| ≤ 120 s`; ignore our own `gw_pubkey`.
2. **Tag trial**: compute the tag under each keyring entry's `K_beacon` (most recently used first); the first match makes the beacon **verified** for that `network_id`. No match → **unverified**.
3. **Verified beacon**: accept if `(instance_id, counter)` is strictly greater than the last accepted pair for that `gw_pubkey` (compare `instance_id` equality first: a new instance resets the counter). Update the table entry: `verified=true`, `network_id`, endpoint = source IP + body ports (keep ≤ 3 endpoints per key, one per source IP, newest first), `last_seen = now`, store the raw 116-byte datagram as `last_beacon` for that endpoint. Any unverified beacon for a `gw_pubkey` that currently has a verified entry is **ignored**.
4. **Unverified beacon**: subject to spam limits — ≤ 2 accepted/s per source IP, ≤ 4 unverified keys per source IP, ≤ 16 unverified entries in total (LRU eviction among unverified only); monotonic-counter check per `(gw_pubkey, source IP)`; otherwise same table update with `verified=false`, `network_id=null`, and `last_beacon` stored (needed for local key verification, §13.3).
5. A gateway is *online* while `now − last_seen ≤ 10 s`; entries not seen for 5 min are dropped from the live table (manual and "known" entries stay as offline). Max 64 live entries (verified entries are never evicted to make room for unverified ones).

A verified entry whose beacons **stop verifying** (the gateway reset its key, or the user deleted the keyring entry) becomes locked again after its next accepted unverified beacon; the UI shows `access: "key_changed"` when the public key is in `known_gateways` with a `network_id` (§13.3).

### 6.3 JOIN_REQ (0x10) — plaintext, 132 bytes

```
0    32  client_pubkey    ephemeral per-session WireGuard public key
32   8   ts               unix seconds
40   2   mtu_hint         client's maximum acceptable tunnel MTU (0 = no preference)
42   2   client_flags     reserved
44   88  padding
```

The client sends **nothing else**: no name, no OS, no identifier, no persistent key. The gateway may observe the source IP:port (needed to reply) and must never persist or log it.

Retry: send, wait 1 s, resend with a **new nonce and timestamp** up to 4 times (1, 1, 2, 2 s). JOIN is idempotent per `client_pubkey`: a repeated JOIN for a pubkey that already has a lease returns the same assignment and refreshes the lease.

### 6.4 JOIN_RESP (0x11) — plaintext, 132 bytes

```
0    1   status           0 = OK (errors use ERROR type instead)
1    1   flags            bit0 lan_access, bit1 reserved(ipv6)
2    8   ts               gateway unix seconds
10   4   assigned_ipv4    client's tunnel address
14   1   prefix_len       24
15   4   gateway_ipv4     gateway's tunnel address (also the DNS server)
19   4   dns_ipv4         = gateway_ipv4 in v1
23   32  gateway_pubkey   gateway's static WireGuard public key
55   2   wg_port          UDP port to send WireGuard to (may differ from ctrl port)
57   2   mtu              1280, or min(1280, mtu_hint) when mtu_hint ≠ 0 (§7.3)
59   2   keepalive_sec    25
61   4   lease_sec        120
65   16  lease_token      random; required in RENEW/LEAVE
81   51  padding
```

Gateway side, on a valid JOIN_REQ: rate-limit check → if `client_pubkey` has a lease, refresh and return it; else allocate an address (§8.2), create `lease_token`, add the WireGuard peer (`public_key`, `preshared_key=K_psk`, `allowed_ip=<assigned>/32`), store the lease in memory, respond. The gateway does **not** set `endpoint` on the peer; WireGuard learns it from the client's first handshake (roaming).

Client side: verify `status == 0`, `prefix_len == 24`, addresses are in the same /24, `gateway_pubkey` non-zero, `mtu ∈ [1280, 1420]`, `lease_sec ∈ [30, 3600]`. Then bring up the tunnel (§9).

### 6.5 RENEW_REQ (0x12) / RENEW_RESP (0x13) / LEAVE (0x14) — plaintext, 64 bytes

```
RENEW_REQ / LEAVE
0    32  client_pubkey
32   8   ts
40   16  lease_token
56   8   padding

RENEW_RESP
0    1   status           0 = OK
1    1   flags            bit0 lan_access (may change at runtime; client updates its UI only)
2    8   ts
10   4   lease_sec        new lease length from now
14   50  padding
```

* Client renews every **30 s**; if 3 consecutive renews get no answer, the session is *degraded* (tunnel stays up — this is the kill-switch behaviour, traffic is held, UI shows "Reconnecting"); the client retries JOIN with the **same** session key every 5 s; after 10 min of failure it offers "Disconnect".
* Gateway expires leases with no RENEW for `lease_sec` (sweep every 5 s): removes the WireGuard peer, closes that client's flows, returns the address to the pool. LEAVE does the same immediately. A RENEW/LEAVE whose `lease_token` does not match → ERROR `unknown_lease` (to a valid member only).

### 6.6 INFO_REQ (0x20) / INFO_RESP (0x21) / ERROR (0x7F)

```
INFO_REQ  (plaintext 1156 bytes)
0    8   ts
8    1148 padding                       ← makes the request ≥ the largest response

INFO_RESP (plaintext 10 + L bytes)
0    8   ts
8    2   json_len L   (≤ 1100)
10   L   json         UTF-8, schema in §10.5

ERROR     (plaintext 16 bytes)
0    1   code      1 pool_full, 2 not_accepting, 3 unknown_lease, 4 bad_request, 5 rate_limited, 6 subnet_conflict(reserved)
1    8   ts
9    7   padding
```

INFO needs no lease: any key holder may ask any gateway of that network. The gateway answers at most **2 INFO/s per source IP and 20/s total**; excess is dropped (not ERRORed). Clients cache an INFO result for 30 s and re-request every 30 s while the details panel is open. INFO is never answered for a locked gateway (the client has no `K_ctrl` for it) — the locked ⓘ panel shows beacon fields only (D25).

**INFO as key trial** (manual gateways, which have no beacon): when a manual entry is added without an explicit `keyring_id`, or when a key is entered for a manual gateway, the client sends INFO_REQ under the candidate key(s) — at most one key in flight, ≤ 2 per second, most recently used first, ≤ 16 attempts — and binds the first key whose INFO_RESP authenticates. Failed trials look like ordinary AEAD failures to the gateway (≤ 16, below the 30/min lockout in §6.7).

### 6.7 Timestamps, replay, rate limits (gateway control listener)

| Check | Rule |
|---|---|
| Timestamp | control: `|now − ts| ≤ 60 s`; beacon: ≤ 120 s. Failure → drop (no ERROR; clock-skew is reported to the *client* when its own JOINs time out and the gateway is visibly online). |
| Nonce replay | keep every accepted request nonce for 120 s in a bounded set (8192 entries, evict oldest). Duplicate → drop. |
| Global | 200 datagrams/s token bucket (burst 400) before AEAD. |
| Per source IP | JOIN 5/s burst 10; INFO 2/s burst 4; RENEW/LEAVE 10/s. |
| Auth failures | ≥ 30 AEAD failures from one source IP within 60 s → ignore that IP for 60 s. |
| Address pool | 253 addresses; `pool_full` ERROR when exhausted. |

Counters only (no addresses) are exported to the UI/log.

### 6.8 (v1.1, outline) Directory / rendezvous server

Stateless HTTPS service, self-hostable, zero-knowledge. `PUT /v1/net/<DirID hex>/<gw_pubkey b64url>` with body = XChaCha20-Poly1305(`K_dir`, nonce, JSON{endpoints[], ts, name…}) and a header `X-Sig` = Ed25519 signature by a key derived from the gateway's WG key **[verify derivation]**; `GET /v1/net/<DirID>` returns all blobs < 10 min old. The server learns `DirID`, gateway public keys and source IPs — nothing about clients. Not built in v1; nothing in v1 precludes it.

---

## 7. Network plan

### 7.1 Ports (defaults, each configurable per gateway)

| Port | Proto | Purpose | Listener |
|---|---|---|---|
| 51820 | UDP | WireGuard | gateway, `0.0.0.0` and `[::]` (wireguard-go `StdNetBind` / `WinRingBind` bind both) |
| 51821 | UDP | Control (JOIN/RENEW/LEAVE/INFO) + beacon source port | gateway |
| 51822 | UDP | Beacons; multicast group `239.255.77.77` | every member (receiver) |
| 47771 | TCP | Local web UI, `127.0.0.1` only (fallback 47772–47780 if busy) | desktop app |

Clients use ephemeral source ports for everything.

### 7.2 Addresses

* Gateway subnet: `10.77.H.0/24` with `H = 1 + (SHA-256("pvp1 subnet" || gw_pubkey)[0] mod 254)`. Override in gateway settings (`gateway.subnet`, any `/24` inside `10.0.0.0/8`, `172.16.0.0/12` or `192.168.0.0/16`).
* Gateway: `.1`. Clients: `.2`–`.254`, allocated **least-recently-released first** (a freed address is not reused while a fresher one is free).
* A client refuses a JOIN_RESP whose subnet overlaps a subnet it is itself serving (dual role, §7.4) or one of its own physical LAN subnets, with the UI error "address conflict — change the gateway's subnet in its settings".

### 7.3 MTU

* Tunnel MTU **1280** (gateway side fixed; a client may ask for less via `mtu_hint` ≥ 576; the gateway returns `min(1280, mtu_hint)` when `mtu_hint ≠ 0`).
* The gVisor NIC MTU equals the tunnel MTU; TCP MSS follows automatically. WireGuard overhead (60/80 bytes) keeps underlay packets ≤ 1360.

### 7.4 Dual role (gateway and client on the same device) — direct-exit semantics

Allowed on Windows, macOS and Linux (Android has no gateway mode). The device's **own** traffic goes through its upstream gateway; traffic the device forwards **for its clients** exits through the device's **physical** connection, never through the upstream tunnel. The device's clients therefore see the device's public IP (the INFO panel says "Clients exit via this device's own connection").

Required mechanics (all also needed for single-role correctness, so this adds little):

| OS | Replies to this device's clients (WG + control listeners) | This device's forwarded flows, DNS upstream, geo lookup |
|---|---|---|
| Android (client-only; listed for the exclusion mechanism) | n/a — no gateway listeners. `VpnService.Builder.addDisallowedApplication(ownPackage)` makes the app's own WG, control and beacon sockets bypass the VPN. | n/a |
| Linux | WG client bind uses `SetMark(0x5056)`; policy routing: `ip rule add not fwmark 0x5056 table 5056`, `ip rule add table main suppress_prefixlength 0`, `ip route add default dev pvp0 table 5056`. All gateway sockets set `SO_MARK 0x5056` via `net.ListenConfig/Dialer.Control`. Marked traffic uses the main table → physical. | same mark |
| Windows | LAN clients: the physical interface's on-link `/24` beats the tunnel's `/1` routes (longest prefix). Off-LAN clients: on JOIN the gateway asks the helper to add a `/32` route for the client's endpoint via the physical default gateway (`route_add`, §13.5); removed when the lease ends. | `IP_UNICAST_IF` / `IPV6_UNICAST_IF` (`golang.org/x/sys/windows`, value 31 / 31) set to the physical default interface index via `Dialer.Control` — only for destinations outside RFC1918/on-link ranges. Geo HTTP client and DNS upstream dialer always bound. |
| macOS | as Windows (`/32` host routes via helper) | `IP_BOUND_IF` (0x19) / `IPV6_BOUND_IF` (0x7d) from `golang.org/x/sys/unix`, same rule. |

"Physical default interface" = the interface carrying the lowest-metric default route **excluding our own tunnel interface**; recomputed on every network-change event (§10.3). The gateway's **WireGuard listener itself is never interface-bound** (binding it would break LAN clients on a second interface).

Subnet rules: the device's client-tunnel subnet is added to the always-deny list for its own clients (§8.5), so its clients cannot reach its upstream gateway. DNS forwarder upstream in dual role = the resolvers saved by the helper **before** it overrode system DNS (§9), bound to the physical interface.

Loops are impossible by construction (forwarded traffic never enters a tunnel). Chaining (clients exiting via the upstream gateway) is **out of scope**; if ever added it needs an upstream-pubkey disclosure in INFO for loop detection.

UI: both switches are independent. Status shows two lines ("You → Alice's PC", "2 clients → your connection").

### 7.5 DNS

* Clients get exactly one resolver: the gateway's tunnel IP (`dns_ipv4`). Client-side system DNS is pointed there (§9 per OS); on Windows, other resolvers are blocked by WFP for the tunnel's lifetime (§9.2).
* Gateway forwarder (§8.6) handles UDP and TCP on `10.77.H.1:53`.

### 7.6 IPv6

v1 carries no IPv6. Clients route `::/0` (as `::/1` + `8000::/1` on desktop) into the tunnel interface, which has no v6 address and no v6 peer → packets are dropped locally (wireguard-go drops packets with no matching peer). The gateway's DNS forwarder answers AAAA with `NOERROR`, empty answer, so applications do not wait on v6. The WG peer AllowedIPs on the client are `0.0.0.0/0` only.

---

## 8. Gateway engine (`core/gateway`, `core/gwstack`)

### 8.1 Structure

```
UDP 51820 ──► wireguard-go device ──► gwstack.Device (tun.Device impl) ──► gVisor stack (NIC 1)
                                                                             │ promiscuous + spoofing, forwarding OFF
                                              ┌──────────────────────────────┤
                                              ▼                              ▼
                                      tcp.Forwarder                   udp.Forwarder
                                 (dial dst with net.Dialer)     (per-flow net.UDPConn)
                                              │                              │
                                              └────── OS sockets ────────────┘ ──► Internet / LAN
```

* `gwstack.Device` implements `golang.zx2c4.com/wireguard/tun.Device` exactly like `tun/netstack` does (use `tun/netstack/tun.go` as the template: `channel.New(512, mtu, "")`, `AddNotify`, `InjectInbound` on `Write`, `ReadContext` → `Read`; `BatchSize() = 1`; `Events()` sends `tun.EventUp` once; `Name()` = `"pvp-gw"`; `File()` = nil).
* Stack options: `NetworkProtocols: ipv4.NewProtocol` (**no ipv6**), `TransportProtocols: tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol4`, `HandleLocal: false`. After `CreateNIC(1, ep)`: `AddProtocolAddress(1, 10.77.H.1/24)`, `SetPromiscuousMode(1, true)`, `SetSpoofing(1, true)`, route table `{Destination: header.IPv4EmptySubnet, NIC: 1}`, `TCPSACKEnabled(true)`. Forwarding stays off (we are not an IP router; the forwarders terminate flows).
* `tcp.NewForwarder(stack, 0 /*default rcv window*/, 256 /*maxInFlight*/, handler)` registered with `SetTransportProtocolHandler(tcp.ProtocolNumber, fwd.HandlePacket)`; `udp.NewForwarder(stack, handler)` likewise.
* wireguard-go device: `device.NewDevice(gwDev, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))` then `IpcSet` with `private_key`, `listen_port`, and per-client `public_key`/`preshared_key`/`allowed_ip` lines (`replace_peers` never; remove with `remove=true`).

### 8.2 Lease table (memory only)

```go
type lease struct {
    pubkey   [32]byte
    ip       netip.Addr
    token    [16]byte
    expires  time.Time
    flows    flowCounters // tcp, udp counts; new-flow token bucket
    offLAN   bool         // endpoint not on an on-link subnet (dual role: a /32 route was added)
}
```
Map by pubkey and by IP. No field is ever serialised. `client_count` = len(table).

### 8.3 TCP forwarding

For each `ForwarderRequest r` with `id = r.ID()` (local = original destination, remote = client):
1. Source must be a leased address (else `r.Complete(true)` → RST). Policy check on `id.LocalAddress:LocalPort` (§8.5); denied → RST.
2. Per-client and global caps/rate (§8.7); exceeded → RST.
3. `net.Dialer{Timeout: 10 s, Control: netbind.Control(dst)}` dial `dst:port`. Failure → `r.Complete(true)`.
4. `ep, err := r.CreateEndpoint(&wq)`; `r.Complete(false)`; `c := gonet.NewTCPConn(&wq, ep)`.
5. Splice both directions with 32 KiB buffers (`io.Copy`), propagate half-close (`CloseWrite`), close both on error. Idle (no bytes either way) 30 min → close. Set `SetKeepAlive(true)` on the OS side.

### 8.4 UDP forwarding

For each `udp.ForwarderRequest r`: source must be leased; policy check; flow caps. Create endpoint → `gonet.NewUDPConn`; dial OS `net.UDPConn` to `dst` (bound per §7.4). Two goroutines copy datagrams (buffer 65535). Flow idle timeout **60 s** (**10 s** when dst port 53). Per-client flow cap 512.

`dst == 10.77.H.1:53` is not forwarded; it is the DNS forwarder (§8.6). Any other `dst` inside `10.77.H.0/24` is denied.

### 8.5 Destination policy (evaluated per new flow)

Always **deny** (regardless of settings):
`0.0.0.0/8`, `127.0.0.0/8`, `169.254.0.0/16` (incl. `169.254.169.254` metadata), `224.0.0.0/4`, `240.0.0.0/4` (incl. `255.255.255.255`), every address currently configured on any interface of the gateway host (refreshed on network change), this gateway's tunnel subnet (except `.1:53` and ICMP echo to `.1`), the device's own client-tunnel subnet when in dual role, and destination port 0.

If `lan_access == false` (default) also deny: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `100.64.0.0/10`.

If `lan_access == true`: the four private ranges are allowed **except** the host's own addresses (already in the always-deny list).

Denied TCP → RST; denied UDP → silent drop. No ICMP unreachable is generated (not available from userspace portably).

### 8.6 DNS forwarder

Served from the UDP forwarder (dst `.1:53`) and the TCP forwarder (dst `.1:53`, length-prefixed stream, one query per connection is enough).

* Validate: length 12..1232, `QR=0`, `QDCOUNT=1`, `OPCODE=0`; parse with `golang.org/x/net/dns/dnsmessage`. Malformed → `FORMERR`.
* `QTYPE=AAAA` → respond `NOERROR`, empty answer, `RA=1`, copy question (D14). `ANY` → `NOTIMP`.
* Otherwise forward verbatim to the upstream over a **fresh** OS UDP socket per query (random port, random transaction ID rewrite on the way out and back), 5 s timeout, first upstream that answers wins; TC bit → retry over TCP to the upstream. Response ≤ 4096 bytes.
* Upstream list, in order: (dual role) resolvers saved by the helper before override → OS resolvers (Linux/macOS `/etc/resolv.conf`; Windows `winipcfg.LUID.DNS()` of the physical default interface; Android: list passed by Kotlin from the *underlying* network's `LinkProperties`) → fallback `1.1.1.1`, `9.9.9.9`. Setting `gateway.dns_upstream` overrides. Loopback upstreams (`127.0.0.53`) are skipped on the gateway because the forwarder socket is interface-bound in dual role; otherwise allowed.
* Rate: 50 queries/s per client (burst 100). No cache. **No logging of names, ever** — not even at debug level.

### 8.7 Limits (constants in `core/gateway/limits.go`)

| Limit | Value |
|---|---|
| Clients | 253 (pool) |
| TCP flows per client / global | 1024 / 8192 |
| UDP flows per client / global | 512 / 4096 |
| New flows per client | 200/s burst 400 |
| TCP pending (SYN received, dial in progress) | 256 (`maxInFlight`) |
| TCP dial timeout / idle | 10 s / 30 min |
| UDP idle / DNS idle | 60 s / 10 s |
| gVisor TCP receive buffer | default (`tcpip.TCPReceiveBufferSizeRangeOption` left at defaults; max 4 MiB) |
| Beacon table on clients | 64 gateways |

### 8.8 ICMP

Echo requests to `10.77.H.1` are answered by gVisor's ICMPv4 implementation (address is local to the NIC). Echo to any other destination is dropped; `ping 8.8.8.8` from a client does not work and the client UI's connectivity test uses DNS + a TCP connect to a well-known port instead.

### 8.9 Lifecycle

Enable: load/generate static key → open control socket → open WG bind → build stack → start beacon sender → start geo refresher (§10) → emit `gateway.state=on`. Disable: stop beacons, send nothing to clients (they notice via RENEW failures), close WG (peers vanish), close sockets, free stack. Address allocations, leases and flow tables are dropped from memory.

---

## 9. Client engine (`core/client`, `core/tunnel`) and per-OS tunnels

### 9.1 Session state machine

```
idle ─connect(gw)─► joining ─JOIN_RESP─► tunnel_up ─first handshake─► connected
   ▲                  │ timeout×4             │ renew fails ×3            │ disconnect/LEAVE
   └──────────────────┴──────────────────────► degraded ◄────────────────┘
                                                  │ JOIN ok (same key)
                                                  └──► tunnel_up
```

`connect`: pick endpoint (prefer the LAN endpoint from the beacon; manual entries resolve `host` with the OS resolver first), generate session key pair, send JOIN_REQ, on JOIN_RESP validate (§6.4), then `tunnel.Up(cfg)`. Handshake success is detected by polling `IpcGet` for `last_handshake_time_sec` every second (≤ 30 s, else report "no handshake — check firewall/port on the gateway"). Disconnect: `LEAVE` (best effort, once) then `tunnel.Down()`.

`TunnelConfig` (JSON, used on the wire to the helper and to Kotlin):

```json
{"private_key":"<b64>", "address":"10.77.H.2/24", "dns":["10.77.H.1"], "mtu":1280,
 "peer":{"public_key":"<b64>","preshared_key":"<b64>","endpoint":"192.168.1.10:51820","allowed_ips":["0.0.0.0/0"],"keepalive":25},
 "sink_ipv6":true, "fwmark":20566}
```

WireGuard UAPI for the client device: `private_key`, `listen_port=0`, `fwmark=<Linux only>`, peer `public_key`, `preshared_key`, `endpoint`, `allowed_ip=0.0.0.0/0`, `persistent_keepalive_interval=25`.

### 9.2 Windows (in `private-vpn-pro tunnel-helper`, elevated)

* TUN: `tun.CreateTUNWithRequestedGUID("Private VPN Pro", &fixedGUID, 1280)` — `fixedGUID = {B6F0C2A1-7D3E-4C6A-9E2B-5A1F3D8C0E77}` so Windows keeps one interface profile. `wintun.dll` must sit **next to `private-vpn-pro.exe`** (the `golang.zx2c4.com/wintun` loader uses `LOAD_LIBRARY_SEARCH_APPLICATION_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32` only). First use installs the Wintun driver (needs admin — the helper is admin).
* `luid := winipcfg.LUID(dev.(*tun.NativeTun).LUID())`.
* Address: `luid.SetIPAddresses([]netip.Prefix{addr})`. Interface metric: `row, _ := luid.IPInterface(windows.AF_INET); row.UseAutomaticMetric=false; row.Metric=0; row.NLMTU=1280; row.Set()` (mirror `tunnel/addressconfig.go` in `golang.zx2c4.com/wireguard/windows` — read it).
* Routes: `luid.SetRoutes` with `0.0.0.0/1` and `128.0.0.0/1` (next hop `0.0.0.0`, metric 0); IPv6 sink `::/1`, `8000::/1` on the same LUID (interfaces have a link-local v6 address automatically). **Endpoint exclusion:** add `<endpoint>/32` on the physical interface via its current default gateway, found with `winipcfg.GetIPForwardTable2(windows.AF_INET)` (`[]MibIPforwardRow2`) — pick the lowest-metric `0.0.0.0/0` row whose interface is not our LUID. Re-evaluate on route change (`winipcfg.RegisterRouteChangeCallback(func(MibNotificationType, *MibIPforwardRow2))`) and update the `/32`.
* DNS: `luid.SetDNS(windows.AF_INET, []netip.Addr{dns}, nil)`; then **block DNS leaks** with `golang.zx2c4.com/wireguard/windows/tunnel/firewall.EnableFirewall(luid uint64, doNotRestrict bool, restrictToDNSServers []netip.Addr) error` called as `EnableFirewall(uint64(luid), true, []netip.Addr{dns})`, which installs WFP rules permitting DNS only to the tunnel resolver; `firewall.DisableFirewall()` on down. The full kill-switch variant (`doNotRestrict=false`) is a v1.1 setting.
* Cleanup: closing the Wintun handle deletes the adapter and every address/route on it; the helper process exit (even a crash) closes the handle. WFP rules installed by `EnableFirewall` are tied to the process's WFP session and vanish when the process exits (that is why it must be the helper that calls it, not the tray process).
* Elevation: `windows.ShellExecute(0, "runas", exePath, "tunnel-helper --pipe <name> --sid <user SID>", "", SW_HIDE)`. Build the exe with `-ldflags "-H windowsgui"` and the `asInvoker` manifest (§15).

### 9.3 macOS (helper running as root)

* TUN: `tun.CreateTUN("utun", 1280)` → kernel assigns `utunN`; `dev.Name()`.
* Configure by executing (absolute paths, args as a slice, never a shell): `/sbin/ifconfig utunN inet 10.77.H.2 10.77.H.1 netmask 255.255.255.0 mtu 1280 up`; `/sbin/route -q -n add -inet 0.0.0.0/1 -interface utunN`; same for `128.0.0.0/1`; `/sbin/route -q -n add -inet6 ::/1 -interface utunN`, `8000::/1`; endpoint exclusion `/sbin/route -q -n add -inet <endpoint> <physical gw>` where the physical gateway comes from a `golang.org/x/net/route` RIB lookup (`route.FetchRIB(unix.AF_INET, route.RIBTypeRoute, 0)` → `route.ParseRIB` → `*route.RouteMessage` with `RTF_GATEWAY`, skipping `utun*` interfaces); fallback: parse `route -n get default`.
* DNS: for every active network service (`/usr/sbin/networksetup -listallnetworkservices`), record current `-getdnsservers` and set `-setdnsservers <svc> 10.77.H.1`. On down, restore recorded values (or `Empty`). The helper writes the recorded values to `<data dir>/run/dns-backup.json` **before** changing anything and restores from it on the next start if it exists (crash recovery).
* Elevation: `/usr/bin/osascript -e 'do shell script "<quoted exe> tunnel-helper --socket <path> --uid <n>" with administrator privileges'`. The quoted string must be built with a strict quoting function (only `[A-Za-z0-9/_.\- ]`, single-quoted, plus the two numbers are allowed; refuse otherwise). Later (when signed): `SMAppService` + XPC.
* `fyne.io/systray` uses cgo on macOS; the helper subcommand is the same binary.

### 9.4 Linux (helper via `pkexec`, or in-process when `CapEff` has `CAP_NET_ADMIN`)

* TUN: `tun.CreateTUN("pvp0", 1280)`.
* `ip` commands (`/usr/sbin/ip` or `/sbin/ip`, exec without shell): `ip addr add 10.77.H.2/24 dev pvp0`; `ip link set up dev pvp0 mtu 1280`; policy routing exactly as wg-quick: `ip route add default dev pvp0 table 20566`; `ip rule add not fwmark 20566 table 20566 priority 20566`; `ip rule add table main suppress_prefixlength 0 priority 20565`; IPv6: `ip -6 route add default dev pvp0 table 20566` + the same two `-6` rules. WireGuard device gets `fwmark=20566`. No endpoint route is needed (marked WG packets use the main table).
* DNS: if `/run/systemd/resolve/` exists → `resolvectl dns pvp0 10.77.H.1` + `resolvectl domain pvp0 '~.'` (reverts automatically when the interface disappears). Else write `/etc/resolv.conf` with a backup at `/etc/resolv.conf.private-vpn-pro-backup` and restore on down/next start.
* Elevation: `pkexec <exe> tunnel-helper --socket <path> --uid <n>` (ship `build/linux/app.privatevpnpro.policy` for a friendly prompt). If `pkexec` is missing, show: `sudo setcap cap_net_admin+ep /path/to/private-vpn-pro` then the app runs the tunnel in-process.
* Cleanup: `ip link del pvp0` removes routes; rules are deleted explicitly; on start, remove stale rules with our priority numbers.

### 9.5 Android (in-process, `PvpVpnService`)

Kotlin implements `Callbacks.establishTun(configJSON)`:

```kotlin
Builder().setSession("Private VPN Pro")
  .addAddress(addr, 24).addRoute("0.0.0.0", 0).addRoute("::", 0)   // v6 sink
  .addDnsServer(dns).setMtu(mtu).setBlocking(true).setMetered(false)
  .addDisallowedApplication(packageName)                            // our sockets bypass the VPN (§7.4)
  .establish()!!.detachFd()                                         // → returned to Go
```

Go: `tun.CreateUnmonitoredTUNFromFD(fd)` → `device.NewDevice(tun, conn.NewDefaultBind(), logger)`; `IpcSet`. Because the whole package is disallowed from the VPN, no `protect()` call is needed; keep `conn.PeekLookAtSocketFd4/6` + `VpnService.protect(fd)` as the documented fallback if a device ever ignores `addDisallowedApplication`.

Kill-switch: while the service holds the TUN and WireGuard has no session, packets are dropped (degraded state keeps the TUN). The user may also enable Android's "Block connections without VPN". Disconnect closes the TUN. If the system revokes the VPN (`onRevoke`), Kotlin calls `Call("client.disconnect")`.

Foreground: `startForeground(id, notification, FOREGROUND_SERVICE_TYPE_SYSTEM_EXEMPTED)`; manifest `android:foregroundServiceType="systemExempted"`, permission `FOREGROUND_SERVICE_SYSTEM_EXEMPTED` (the VPN exemption case **[verify on API 34 device]**), plus `FOREGROUND_SERVICE`, `POST_NOTIFICATIONS` (runtime on 33+), `BIND_VPN_SERVICE` on the service.

### 9.6 Connectivity self-test (client, after handshake)

DNS query `A example.com` to `10.77.H.1`, then TCP connect to `1.1.1.1:443` through the tunnel with 5 s timeout. Result shown as "Internet via gateway: OK / DNS failed / no route". No request bodies, nothing logged.

---

## 10. Gateway details ("ⓘ" panel)

### 10.1 What is shown

| Field | Source | Notes |
|---|---|---|
| Name, OS, OS version, app version | beacon + INFO | |
| Uptime (device), gateway uptime | INFO | seconds; UI renders `3d 4h` |
| Connected clients | INFO (`client_count`) | **count only** |
| LAN access policy, subnet, MTU | INFO | |
| LAN IP(s) | INFO | IPv4 addresses of physical interfaces, ≤ 8 |
| Public IP (v4, v6 if any) + last checked | INFO | refreshed per §10.3; `stale` flag if > 30 min old |
| Country, region, city | INFO.geo | labelled **"approximate (city-level, from IP)"** when `source=geoip` |
| Latitude / longitude (+ accuracy) | INFO.geo | same label; `accuracy_km` 25 for geoip, 0 for manual |
| ISP / ASN | INFO.geo | optional |
| Time zone (IANA + UTC offset) and **live local time** | INFO.tz + INFO.now | client renders live (§10.6) |
| Reachability | derived client-side | "LAN" if an endpoint is on-link; "Internet (manual)" for manual entries; plus the CGNAT hint (§10.4) |
| Key fingerprint, first seen | client-side | TOFU hint (T3) |
| Exit path | INFO.dual_role | "Clients exit via this device's own connection" |

### 10.2 How the gateway learns its public IP and location (`core/geo`)

Providers, tried in order until one succeeds (plain `GET`, no API key, `User-Agent: Private VPN Pro/<version>` and nothing else):

| Provider | URL | Mapping |
|---|---|---|
| ipwho.is | `https://ipwho.is/` | `ip, country, country_code, region, city, latitude, longitude, timezone.id, timezone.utc, connection.isp, connection.asn` |
| ipinfo.io | `https://ipinfo.io/json` | `ip, country(cc), region, city, loc "lat,lon", org ("AS1234 Name"), timezone` |
| ipapi.co | `https://ipapi.co/json/` | `ip, country_name, country_code, region, city, latitude, longitude, timezone, org, asn` |

Client: `http.Client{Timeout: 6 s}` with a transport that has `Proxy: nil`, `DisableKeepAlives: true`, `TLSClientConfig{MinVersion: tls.VersionTLS12}`, system roots, `CheckRedirect` allowing ≤ 2 redirects to `https` only, dialer bound per §7.4. Body read through `io.LimitReader(…, 16384)`; status must be 200; decode into a provider-specific struct with `encoding/json` (unknown fields ignored); then **validate**: IP parses with `netip`, `lat ∈ [-90, 90]`, `lon ∈ [-180, 180]`, every string trimmed, control/bidi characters removed, truncated to the caps in §10.5, country code `^[A-Z]{2}$`. Failure of validation = provider failure. The lookup never includes anything about clients (the gateway holds nothing about them that could be sent, and the request is a bare GET).

IPv6 public address: a second request to the same provider over IPv6 only (`net.Dialer` forced to `tcp6`) is attempted once per refresh; absence is normal.

Settings (`gateway.geo`): `enabled` (default **true**; off → no network requests, `source=none`, public IP unknown) and `manual` `{country, region, city, lat, lon, tz_name}` (overrides geo fields; public IP is still looked up unless disabled). There is no GPS source (gateways are desktops).

### 10.3 Refresh schedule and network-change detection

* On gateway enable; then every **10 min ± 1 min**; and **5 s after a network change** (debounced; never more often than every 60 s). All failures → keep the last value and mark `stale` when older than 30 min.
* Network change (`core/sysinfo.Watcher`): desktop polls `net.Interfaces()` + addresses every 10 s and diffs (portable; Windows may additionally use `winipcfg.RegisterInterfaceChangeCallback`). Android: `ConnectivityManager.NetworkCallback` → `Call("sys.network_changed", "{}")`. The same event re-joins multicast groups, recomputes the physical default interface (§7.4) and the host-address deny list (§8.5).

### 10.4 Reachability hint

If the public IP equals none of the host's interface addresses, the gateway is behind NAT; if the physical default interface's address is in `100.64.0.0/10`, it is behind CGNAT. INFO carries `nat: "none" | "nat" | "cgnat" | "unknown"`. Client UI text: *nat* → "Reachable on this LAN. For access from the Internet, forward UDP 51820 and 51821 on your router to this device." *cgnat* → "Reachable on this LAN only (mobile network uses carrier NAT; port forwarding is not possible)." The gateway's own settings page shows the same text.

### 10.5 INFO JSON schema (gateway → client, ≤ 1100 bytes)

```json
{
  "v": 1,
  "pubkey": "<base64url 43>",
  "name": "Office PC",                 // ≤ 32 chars
  "os": "windows",                      // windows|macos|linux|android
  "os_version": "10.0.22631",           // ≤ 32
  "app_version": "1.0.0",               // ≤ 16
  "uptime_sec": 123456, "gateway_uptime_sec": 3456,
  "client_count": 2,
  "lan_access": false, "dual_role": false,
  "subnet": "10.77.42.0/24", "mtu": 1280,
  "wg_port": 51820, "ctrl_port": 51821,
  "lan_ips": ["192.168.1.10"],          // ≤ 8, valid IPv4 strings
  "public_ip": "203.0.113.7", "public_ip6": "",
  "public_ip_checked_at": 1761900000, "stale": false,
  "nat": "nat",
  "geo": {
    "source": "geoip",                  // geoip|manual|none
    "provider": "ipwho.is",             // ≤ 32
    "country": "Germany", "country_code": "DE", "region": "Bavaria", "city": "Munich",  // ≤ 64 each
    "lat": 48.14, "lon": 11.58, "accuracy_km": 25,
    "isp": "Deutsche Telekom", "asn": "AS3320",  // ≤ 64 / ≤ 16
    "checked_at": 1761900000
  },
  "tz": {"name": "Europe/Berlin", "utc_offset_sec": 3600, "abbrev": "CET"},   // ≤ 64 / int / ≤ 8
  "now": 1761900123
}
```

Encoding on the gateway: marshal; if > 1100 bytes drop, in order, `geo.isp`, `geo.asn`, `os_version`, `lan_ips` beyond the first two, `geo.provider`; re-marshal. `tz.name`: Linux/macOS from `$TZ` or the `/etc/localtime` symlink target (`…/zoneinfo/<Name>`); Android from Kotlin (`TimeZone.getDefault().id`); Windows: Go cannot give an IANA name → use the GeoIP provider's `timezone` if present, else `""`. `utc_offset_sec` and `abbrev` always come from `time.Now().Zone()` on the gateway.

### 10.6 Client-side handling (untrusted input)

Another member could send garbage; the client must:
* Parse with hard caps (reject the whole message if `json_len > 1100`, if `v != 1`, or if JSON is invalid; ignore unknown fields).
* For every string: remove C0/C1 control characters and the bidi controls U+202A–U+202E, U+2066–U+2069, U+200E/U+200F; truncate to the field cap (append `…`); render only via `textContent` (web) / `Text()` (Compose). Never `innerHTML`, never string-built HTML.
* Numbers: range-check; display lat/lon only when `source != none` and in range; `client_count ≤ 253`; `utc_offset_sec ∈ [-16h, +16h]`.
* IP strings must parse with `netip` before display.
* **Live local time**: on fetch record `skew = now_gateway_ms − fetch_ms`; while the panel is open compute every second `wall = Date.now() + skew + utc_offset_sec*1000` and format as a UTC clock (`toISOString`-style → `HH:MM:ss`, `YYYY-MM-DD`), with the zone name and `UTC±HH:MM`. If `|skew| > 60 s` show "device clock differs by N s". Compose: `LaunchedEffect` ticking every second over the same formula.
* Fingerprint + "first seen" are computed locally (not from INFO).
* **Locked gateway** (no matching key): the panel shows only the beacon fields (name, OS, app version, ports, client count, flags, fingerprint, "LAN" endpoint, last seen) plus the line "Enter this gateway's key to see location details and connect", a key field with "Scan" (Android) / "Paste", and the word **unverified** (T13). No INFO request is made.

### 10.7 Privacy

INFO describes the **gateway** only (an opted-in role). It is sent only to holders of that network's key (AEAD under `K_ctrl`), only on request, never broadcast, and the gateway never logs who asked. Non-holders see exactly the public beacon fields and nothing more (D25). Clients still transmit nothing about themselves. Gateways do not persist INFO data except the manual override and the settings; the last lookup result is cached in memory only.

---

## 11. Android application (client-only)

Android never acts as a gateway (D26). It discovers gateways, keeps a keyring, connects through `VpnService`, and shows the same list and ⓘ panel as the desktop UI.

### 11.1 Project

`android/` Gradle project (Kotlin DSL), AGP 8.x, JDK 21, `compileSdk 36`, `minSdk 26`, `targetSdk 35`, package `app.privatevpnpro`. Dependencies: Compose BOM + Material 3, `activity-compose`, `lifecycle-runtime-compose`, `com.journeyapps:zxing-android-embedded:4.3.0` (scan), `implementation(files("libs/core.aar"))`. No networking library, no crypto library, no QR *encoder* (Android never shows a key as QR — keys are created on desktops; "Show key" on Android displays text only, for typing into another device).

```
android/app/src/main/java/app/privatevpnpro/
  PvpApplication.kt          // mobile.Mobile.start(filesDir/"pvp", BuildConfig.VERSION_NAME, CoreCallbacks)
  core/CoreBridge.kt         // call(method, json): String; events → StateFlow<UiState>
  core/CoreCallbacks.kt      // implements mobile.Callbacks (below)
  vpn/PvpVpnService.kt       // VpnService (client mode), foreground type systemExempted
  net/NetworkWatcher.kt      // ConnectivityManager callback → core.call("sys.network_changed")
  net/MulticastLockHolder.kt // held while the app process runs the beacon receiver
  ui/MainActivity.kt, ui/Nav.kt
  ui/screens/GatewaysScreen.kt      // the start screen: list with lock badges, Connect, "Add by address"
  ui/screens/GatewayDetailsSheet.kt // ⓘ panel (members: full; locked: public fields + key entry)
  ui/screens/KeyEntrySheet.kt       // scan (ScanContract) / paste; used from Connect and from Keyring
  ui/screens/KeyringScreen.kt, SettingsScreen.kt, LogScreen.kt
  ui/theme/
```

Manifest permissions: `INTERNET`, `ACCESS_NETWORK_STATE`, `CHANGE_WIFI_MULTICAST_STATE` (MulticastLock), `FOREGROUND_SERVICE`, `FOREGROUND_SERVICE_SYSTEM_EXEMPTED`, `POST_NOTIFICATIONS`, `CAMERA` (scan). Nothing else — no wake locks, no battery-optimisation request, no location. `android:allowBackup="false"`, `android:dataExtractionRules` and `fullBackupContent` excluding everything.

### 11.2 gomobile facade (`mobile/` package, exported API — this is the entire surface)

gomobile supports only `int/int64/float64/string/bool/[]byte/error`, structs and interfaces from the bound package. We expose a tiny RPC-style surface; everything else is JSON.

```go
package mobile

// Implemented in Kotlin. Called from Go threads; Kotlin must hop to Main where needed.
type Callbacks interface {
    OnEvent(eventJSON string)                       // see §14.3 event schema
    EstablishTun(configJSON string) (int, error)    // §9.5; returns detached fd
    CloseTun()                                      // Go has closed the device; Kotlin stops the service
    SystemInfo() string                             // {"os_version":"14","model":"Pixel 7","tz":"Europe/Berlin","dns":["192.168.1.1"]}
}

func Start(dataDir, appVersion string, cb Callbacks) error   // idempotent per process
func Stop()
func Call(method, argsJSON string) (string, error)          // §14.4 method table; errors are {"code","message"} JSON
```

Generated Java package: `app.privatevpnpro.mobile` (`gomobile bind -javapkg app.privatevpnpro`). `int` maps to Java `long`.

Go-side DNS on Android: Go's resolver cannot read `/etc/resolv.conf`; `core/engine` installs `net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: <dial the servers from SystemInfo().dns>}` and refreshes on `sys.network_changed`. Only manual-gateway hostnames need it. The mobile build excludes `core/gateway`, `core/gwstack` and `core/geo` (`//go:build !android`), so `gateway.*` methods return `{"code":"unsupported"}` on Android.

### 11.3 Flows

* **First launch:** the Gateways screen is the start screen; it already lists every gateway on the LAN (locked ones with a lock badge). An empty-state card explains: "Gateways on your network appear here. To connect, enter the gateway's key once — shown on the gateway's Private VPN Pro page." There is no "Create network" on Android.
* **Connect (locked gateway):** tap Connect → `KeyEntrySheet` (scan via `ScanContract`, or paste) → `Call("gateways.unlock", {"gateway_id", "key_text"})` → Go verifies the key locally against the gateway's last beacon tag (§5.6) → on success the key is stored in the keyring (asked **once** per network; §13.3 replace-or-add rule) and the entry becomes verified; on failure "This key does not match <name>". Then the verified-gateway flow continues immediately.
* **Connect (verified gateway):** `VpnService.prepare(ctx)` consent (if needed) → `startForegroundService(PvpVpnService, gateway_id)` → service `onStartCommand` → `Call("client.connect", {"gateway_id":…})` → Go JOINs under the bound key → `EstablishTun` → events drive the UI. Notification shows state and a "Disconnect" action.
* **Add by address (secondary):** overflow menu → "Add gateway by address" (`host[:port]`, label) → `Call("gateways.manual_add", …)`; the entry is listed and tries each keyring key via INFO (§6.6); if none verifies it is listed locked and Connect prompts for the key (verified via INFO trial instead of a beacon tag).
* **Details ⓘ:** bottom sheet; verified: `Call("gateways.info", …)` every 30 s while open, live clock per §10.6; locked: public fields + key entry (§10.6).
* **Keyring screen:** list of networks (label, first used, gateways seen), rename, remove (removing makes that network's gateways locked again), "Show key" (text only, after a confirmation).

### 11.4 MulticastLock, Doze and lifecycle

* **MulticastLock** (`WifiManager.createMulticastLock("pvp-discovery")`, `setReferenceCounted(false)`) is needed for beacon *reception* (Wi-Fi drivers filter multicast otherwise) and is held whenever the Go beacon receiver is open: while any Activity is started, and while `PvpVpnService` runs (so the list stays fresh during a session). Subnet broadcasts are delivered without the lock on most devices, which is why D8 sends both. Released, together with `mobile.Stop()`, when no Activity is visible and no VPN session is active.
* **Doze**: only the VPN session must survive the screen being off, and a `VpnService` foreground service does (WireGuard's 25 s keepalive is the only periodic traffic). No wake lock, no battery-optimisation request.
* **Notification**: the `VpnService` foreground notification ("Connected to <gateway>", action "Disconnect"); `POST_NOTIFICATIONS` is requested at first connect; if denied the service still runs.
* **Reachability note** shown in the ⓘ panel of a gateway uses the gateway's own `nat` field (§10.4) — nothing Android-specific.

| State | MulticastLock | Foreground service |
|---|---|---|
| App in foreground, idle | held | – |
| Client connected (background) | held | `PvpVpnService` (systemExempted) |
| App closed, nothing active | released; `Stop()` core | – |

---

## 12. No-logs and persistence

### 12.1 Rules (every role, every OS)

1. The gateway stores client state (public key, tunnel IP, endpoint, lease token, flow tables, counters per client) **in process memory only**. No file, no database, no system log, no crash dump with our data (Go's default crash output goes to stderr → on desktop stderr is `/dev/null` / no console; on Android, a Go panic would print goroutine dumps to logcat — `debug.SetTraceback("none")` is set at start and all key material lives in `[]byte` referenced only from the lease table).
2. Application logging = `core/eventlog` ring buffer (1000 lines, memory) exposed read-only in the UI/log screen. Allowed content: state transitions, counts, error classes, gateway names (gateways opted in), port numbers, our own addresses. **Forbidden content**: any client address, endpoint, key, lease token, DNS name queried, destination of a forwarded flow. Code review checks every log call site; a `vet`-style test greps log format strings for `%v` of lease/flow types (make those types implement `String()` returning `"<redacted>"`).
3. wireguard-go logger: gateway `LogLevelSilent`; client `LogLevelError` into the ring buffer with the peer-key prefix stripped by a filtering writer.
4. Android: never `Log.*` anything coming from Go events except the allowed set; `StrictMode` is not used in release.
5. Metrics shown in the UI are aggregate (bytes, client count, flow counts).

### 12.2 What is persisted, where, with which permissions

One file `state.json` (plus `run/` for runtime files on desktop):

| OS | Directory | Perms |
|---|---|---|
| Windows | `%LOCALAPPDATA%\Private VPN Pro\` | directory ACL inherited (user-only by default); file written with `CreateFile` default DACL |
| macOS | `~/Library/Application Support/Private VPN Pro/` | `0700` / `0600` |
| Linux | `$XDG_CONFIG_HOME/private-vpn-pro/` (default `~/.config/private-vpn-pro/`); runtime sockets in `$XDG_RUNTIME_DIR/private-vpn-pro/` | `0700` / `0600` |
| Android | `<filesDir>/pvp/` (app-private, excluded from backup) | app sandbox |

```json
{
  "schema": 2,
  "keyring": [                                   // ≤ 16 entries; order = most recently used first
    {"id": "<uuid>", "key": "<base64 32 bytes>", "label": "Home",
     "created_here": true,                       // true only on the desktop that generated it
     "created_at": 1761900000, "last_used": 1761903600}
  ],
  "device_name": "PC-1A2B",                      // desktop only; ≤ 32 chars; default per D27; broadcast in beacons
  "gateway": {                                   // desktop only (absent on Android)
    "enabled": false,
    "network_id": "<keyring id>",                // the one network this gateway serves; null until first enable
    "private_key": "<base64>",                   // static WG key, created on first enable
    "wg_port": 51820, "ctrl_port": 51821, "subnet": null,   // null = derived (§7.2)
    "lan_access": false, "dns_upstream": [],
    "geo": {"enabled": true, "manual": null}
  },
  "manual_gateways": [{"id": "<uuid>", "label": "Home", "host": "home.example.org", "ctrl_port": 51821,
                       "network_id": "<keyring id or null>", "pubkey": "<b64url or null>"}],
  "known_gateways": [{"pubkey": "<b64url>", "name": "PC-1A2B", "network_id": "<keyring id or null>",
                      "first_seen": 1761900000, "last_seen": 1761903600}],
  "ui": {"port": 47771, "autostart": false, "theme": "system"}
}
```

Keyring rules: `id` is local and never transmitted; `label` defaults to "My network" for keys created here, otherwise to "<gateway name>'s network" at first use; entries are deduplicated by key bytes; removing an entry that a gateway serves is refused while gateway mode is on. `known_gateways[].network_id` records which keyring entry last verified that gateway (drives the `key_changed` state and the replace-or-add rule, §13.3). Android has no `device_name` and no `gateway` object.

Never persisted: client session keys, leases, peers, endpoints, event log, INFO results, raw beacons. `known_gateways` holds only gateway (opted-in) identities and is capped at 64 entries.

Writes are atomic (write temp file in the same dir, fsync, rename). A `.lock` file (`flock` / Windows exclusive open) in the data dir enforces a single desktop instance; a second instance shows a notification "Private VPN Pro is already running (use the tray icon)" and exits.

---

## 13. Desktop application (`cmd/private-vpn-pro`, `desktop/…`)

### 13.1 Process and tray

* One binary; subcommands: `private-vpn-pro` (default: tray + UI + core), `private-vpn-pro tunnel-helper …` (§13.5), `private-vpn-pro firewall add|remove` (Windows, elevated, §13.6), `private-vpn-pro version`, `private-vpn-pro --no-tray` (Linux sessions without a StatusNotifier host: prints the one-time URL to stdout and keeps running).
* Tray via `fyne.io/systray` (`systray.Run(onReady, onExit)`): menu = **Open Private VPN Pro**, status line (disabled item), **Gateway mode** (checkbox), **Connect to ▸** submenu (live gateway list, verified+online first; locked entries show a 🔒 prefix and selecting one opens the web UI on that gateway's key prompt), **Disconnect**, separator, **Copy my gateway key** (present only when `gateway.network_id` is set; copies that key's text), **Quit**. Icon states: idle, gateway on, connected, both. macOS: `systray.SetTemplateIcon`; `Info.plist` has `LSUIElement = true` so there is no Dock icon. Windows: `-ldflags "-H windowsgui"` so there is no console window. There is **no application window** on any OS.
* "Open Private VPN Pro" mints a token (§13.4) and launches the browser: Windows `windows.ShellExecute(0,"open",url,…)` (from the unprivileged process, so the browser is unprivileged); macOS `/usr/bin/open <url>`; Linux `xdg-open <url>`.

### 13.2 Web UI

Static files under `desktop/web/ui/` embedded with `//go:embed ui/*`: `index.html`, `app.js`, `app.css`, `icons.svg`, `login.html`. Vanilla ES2020, no framework, no build step, no inline scripts/styles (CSP). Views: **Gateways** (start view; list with online badge, 🔒 lock badge for locked entries, "key changed" badge, OS icon, client count, LAN/manual, network label, ⓘ details panel per §10, Connect button — which opens an inline key prompt (paste) for locked entries —, "Add gateway by address"), **Networks** (the keyring: per entry label, "Show key" (text + QR), "Copy", rename, remove; "Create network" button; the entry served by this gateway is marked), **Gateway mode** (switch, which network it serves, gateway name with the "visible to everyone on the LAN" note, settings, firewall status, reachability text, "Reset key"), **Status** (client state, assigned IP, handshake age, bytes; gateway counters), **Log** (ring buffer), **Settings** (autostart, port, theme). QR is a PNG from Go (`github.com/skip2/go-qrcode`).

### 13.3 Gateway list model (shared by web UI and Android)

```json
{"id":"<pubkey b64url>", "name":"PC-1A2B", "os":"windows", "app_version":"1.0.0",
 "online":true, "last_seen_ms":1200, "client_count":2, "flags":{"accepting":true,"lan_access":false,"dual_role":false},
 "access":"member",                                   // member | locked | key_changed
 "network":{"id":"<keyring id>","label":"Home"},      // null when locked
 "endpoints":[{"ip":"192.168.1.10","ctrl_port":51821,"wg_port":51820,"source":"lan","verified":true}],
 "manual":{"id":"<uuid>","label":"Home","host":"home.example.org","ctrl_port":51821},
 "fingerprint":"a1b2c3d4e5", "first_seen":1761900000, "is_new":true, "is_self":false}
```
* `access`: `member` = the latest beacon (or, for manual entries, the last INFO) verified under a keyring entry; `locked` = no keyring entry verifies; `key_changed` = locked **and** `known_gateways[pubkey].network_id` is set (this gateway used to verify under a key we still hold → its key was reset).
* Ordering: `member` entries first (online before offline), then `key_changed`, then `locked`; within a group by name. Locked entries are labelled **unverified** in the ⓘ panel (T13); the UI never auto-connects to them and the "Connect" button on them always opens the key prompt.
* `is_new` = pubkey not in `known_gateways` (shown as a "new" badge; cleared after the first successful connection). Manual entries without a known pubkey are listed by label until an INFO succeeds. Our own gateway appears greyed with `is_self`.
* **Key entry and local verification** (`gateways.unlock`): parse the key (§5.1) → if the entry has a `last_beacon` younger than 30 s, compute the tag under the candidate `K_beacon` and compare (`hmac.Equal`); mismatch → error `key_mismatch`, nothing stored. If there is no fresh beacon (manual entry, or beacon-less at that moment) → INFO trial under the candidate key (3 attempts over 5 s); no authenticated answer → `key_mismatch` if an ERROR/garbage arrived, `unreachable` if nothing arrived. On success apply the **replace-or-add rule**: if `known_gateways[pubkey].network_id = E` exists and E's current key does *not* verify this gateway → replace E's key bytes in place (same `id`, same label — this is the "gateway reset its key" path); else deduplicate by key bytes or append a new entry labelled "<gateway name>'s network". Set `last_used`, set `known_gateways[pubkey].network_id`, re-evaluate the entry's `access`. The key is asked **once** per network; from then on every gateway of that network verifies automatically.
* Raw beacons: the table keeps the latest 116-byte datagram per endpoint (≤ 3 per entry) in memory only, for the local verification above.

### 13.4 Local HTTP server security (`desktop/web/server.go`)

* Listen `127.0.0.1:47771` (configured port; try 47772…47780 if busy; the tray always knows the real one). Never `0.0.0.0`, never `localhost` (name), no IPv6 listener.
* **Host check**: `r.Host` must be exactly `127.0.0.1:<port>`; otherwise `421 Misdirected Request`, no body. Also reject requests whose `Host` is `localhost` (DNS rebinding commonly targets names).
* **Login**: tray mints `tok` (32 random bytes, base64url), stores `{tok → expiry now+60 s}` (max 8 outstanding), opens `http://127.0.0.1:<port>/#t=<tok>`. `index.html` JS reads `location.hash`, calls `history.replaceState` to clear it, then `POST /api/v1/session {"token":tok}`. Server: single-use (delete on first sight), expiry check, then `Set-Cookie: pvp_s=<32 random bytes b64url>; HttpOnly; SameSite=Strict; Path=/` and body `{"csrf":"<32 random bytes b64url>"}` (kept in JS memory only). Sessions: idle expiry 12 h, max 4 concurrent, all dropped on restart. `/api/v1/session` limited to 5 req/s. Without a session, `/` serves `login.html` ("Open Private VPN Pro from the tray icon") and `/api/*` returns 401.
* **Every `/api/*` request**: valid session cookie; for non-GET additionally `Origin == http://127.0.0.1:<port>` **and** header `X-PVP-CSRF` equal to the session's csrf; `Sec-Fetch-Site`, if present, must be `same-origin` or `none`. `Content-Type: application/json` required on bodies; bodies capped at 64 KiB.
* **Response headers** (all responses): `Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'; object-src 'none'`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `Cross-Origin-Opener-Policy: same-origin`, `Cross-Origin-Resource-Policy: same-origin`, `Cache-Control: no-store` on `/api/*`. **No** `Access-Control-*` headers ever.
* **SSE** `GET /api/v1/events`: cookie + Host check (EventSource cannot send headers; `SameSite=Strict` prevents cross-site use). One stream per session.
* Other local processes of **other users** cannot obtain a token; same-user processes are trusted (T6).
* Server timeouts: `ReadHeaderTimeout 5 s`, `IdleTimeout 60 s`, `MaxHeaderBytes 16 KiB`.

### 13.5 Privileged tunnel helper (`desktop/helper`)

Spawned by the main process when client mode is requested on Windows/macOS/Linux (unless Linux in-process capability path). It owns: TUN, the client WireGuard device, routes, DNS, DNS-leak firewall (Windows), and the dual-role `/32` client routes. It knows nothing about the network key, discovery or the control protocol — the main process does JOIN/RENEW/INFO and sends the helper a `TunnelConfig` (which contains the **ephemeral** session private key and `K_psk` for that one tunnel).

**Transport:** newline-delimited JSON, one object per line, ≤ 64 KiB per line.
* Windows: named pipe `\\.\pipe\private-vpn-pro-helper-<16 hex random>` created by the helper via `github.com/Microsoft/go-winio.ListenPipe` with security descriptor `D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;<launching user SID>)`; the pipe name and SID come from the command line (neither is secret).
* macOS/Linux: Unix socket `<runtime dir>/helper-<16 hex>.sock`; helper creates it as root, `chown <uid>`, `chmod 0600`, and verifies the peer with `SO_PEERCRED` (Linux) / `LOCAL_PEERCRED`/`getpeereid` (macOS) == `uid`.

**Messages** (`"id"` echoes for request/response matching):
```
→ {"id":1,"op":"hello","version":"1.0.0"}          ← {"id":1,"ok":true,"version":"1.0.0","elevated":true}
→ {"id":2,"op":"up","config":<TunnelConfig>}       ← {"id":2,"ok":true,"ifname":"utun4"}
→ {"id":3,"op":"status"}                           ← {"id":3,"ok":true,"handshake_age_sec":12,"rx":123,"tx":456,"endpoint_ok":true}
→ {"id":4,"op":"set_endpoint","endpoint":"..."}    (roaming / re-JOIN to the same gateway)
→ {"id":5,"op":"route_add","dst":"203.0.113.9/32"} / {"op":"route_del",...}   (dual role, §7.4; dst must be a single host, never private/loopback)
→ {"id":6,"op":"down"}                             ← {"id":6,"ok":true}
→ {"id":7,"op":"exit"}
← {"ev":"tunnel","state":"up|down|error","message":"…"}   (unsolicited)
```
Helper rules: refuses to start if not elevated or if its version differs from the caller's; **tears everything down and exits when the connection closes** (this is the crash cleanup for the main process); on start, cleans leftovers from a previous crash (Linux rules by priority number, macOS DNS backup file, Windows nothing needed). The main process restarts a helper (new UAC/password prompt) only on explicit user action.

### 13.6 Windows specifics

* Manifest (embedded with `github.com/tc-hib/go-winres`): `requestedExecutionLevel level="asInvoker"`, `dpiAware`, `longPathAware`, supportedOS up to Windows 11; icon.
* **Firewall**: Windows Defender Firewall blocks unsolicited inbound UDP. When the user enables gateway mode (and on first start for beacon reception, optionally) the app runs `private-vpn-pro firewall add` elevated (`ShellExecute runas`) which executes `netsh advfirewall firewall add rule name="Private VPN Pro" dir=in action=allow program="<exe path>" protocol=UDP profile=private,domain enable=yes` (program-scoped, UDP only, **not** the Public profile). `firewall remove` deletes it. The Gateway page shows "Firewall rule: present / missing — Add" (checked with `netsh … show rule name="Private VPN Pro"`). Windows may additionally show its own prompt; both are fine.
* **Autostart**: `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Private VPN Pro = "<exe>" --autostart` (unprivileged; works because the app is `asInvoker`). macOS: `~/Library/LaunchAgents/app.privatevpnpro.plist` (`RunAtLoad`). Linux: `~/.config/autostart/private-vpn-pro.desktop`. Autostart restores gateway mode if it was on; it never auto-connects a client tunnel (that would prompt for elevation at logon).
* Running as a standard (non-admin) user: gateway mode works without any prompt if the firewall rule exists (an admin can add it once); client mode prompts for admin credentials.

### 13.7 macOS and Linux specifics

* macOS: unsigned/ad-hoc-signed builds trigger Gatekeeper ("open anyway") and the application firewall's "allow incoming connections" prompt when gateway mode first listens; `build/macos/Info.plist` with `LSUIElement`, `CFBundleIdentifier app.privatevpnpro`, `NSHighResolutionCapable`. Universal binary (`lipo`).
* Linux: `fyne.io/systray` needs a StatusNotifierItem host (KDE, GNOME with AppIndicator extension); otherwise `--no-tray`. Gateway mode may need `ufw allow 51820:51822/udp` — the Gateway page shows the exact command when the ports are not reachable from the LAN (self-check by having the beacon receiver observe our own beacon from the LAN broadcast).

---

## 14. Local API (desktop HTTP) and method table (shared with Android)

All handlers live in `core/api` as `func(ctx, argsJSON) (resultJSON, *APIError)` and are exposed twice: HTTP (`desktop/web`) and `mobile.Call`. Errors: `{"code":"string","message":"human text"}` with HTTP 400/401/409/500.

### 14.1 Endpoints (prefix `/api/v1`)

| Method & path | Core method | Body → Response |
|---|---|---|
| `POST /session` | — (web only) | `{token}` → `{csrf}` |
| `GET /status` | `status.get` | → `{version, device_name, keyring:{count}, gateway:{enabled, network:{id,label}|null, clients, uptime_sec, wg_port, ctrl_port, subnet, lan_access, firewall_rule, nat, public_ip}, client:{state, gateway_id, gateway_name, network_label, assigned_ip, since, rx, tx, handshake_age_sec, degraded_since}, dual_role}` |
| `GET /keyring` | `keyring.list` | → `{entries:[{id, label, created_here, created_at, last_used, gateways_seen}]}` (never includes key bytes) |
| `POST /keyring` | `keyring.add` | `{key_text, label?}` → `{id, existing}` — generic add with no gateway binding (dedup by key bytes) |
| `POST /keyring/create` | `keyring.create` | `{label?}` → `{id, key_text}` — **desktop only** (`unsupported` on Android) |
| `PATCH /keyring/{id}` | `keyring.rename` | `{label}` → `{}` |
| `DELETE /keyring/{id}` | `keyring.remove` | → `{}` (409 `in_use` while the gateway serves it and is enabled; disconnects a client session using it) |
| `POST /keyring/{id}/reveal` | `keyring.reveal` | → `{key_text}` |
| `GET /keyring/{id}/qr.png` | — (web only) | PNG |
| `POST /gateway/network` | `gateway.set_network` | `{keyring_id}` → `{}` (restarts the gateway if enabled; with an empty keyring, `gateway.enable` calls `keyring.create` implicitly and binds it) |
| `POST /gateway/reset-key` | `gateway.reset_key` | → `{key_text}` (new key bytes for the served entry, same id/label; all peers dropped; beacons switch immediately) |
| `GET /gateways` | `gateways.list` | → `{gateways:[§13.3 …]}` |
| `POST /gateways/{id}/unlock` | `gateways.unlock` | `{key_text}` → `{keyring_id, method:"beacon"|"info", replaced:bool}`; 400 `key_mismatch`, 504 `unreachable` (§13.3) |
| `POST /gateways/manual` | `gateways.manual_add` | `{label, host, ctrl_port?, keyring_id?}` → `{id}`; without `keyring_id` an INFO trial over the keyring runs in the background (§6.6) |
| `DELETE /gateways/manual/{id}` | `gateways.manual_remove` | → `{}` |
| `GET /gateways/{id}/info` | `gateways.info` | → `{info:<§10.5>, fetched_at_ms, endpoint_used}` (performs INFO_REQ under the bound key; 409 `locked` if none; 504 on timeout) |
| `POST /client/connect` | `client.connect` | `{gateway_id}` → `{}` (state via events); 409 `locked` when `access != member` — the UI then shows the key prompt and retries after `gateways.unlock` |
| `POST /client/disconnect` | `client.disconnect` | → `{}` |
| `POST /client/selftest` | `client.selftest` | → `{dns_ok, tcp_ok, ms}` |
| `POST /gateway/enable` / `disable` | `gateway.enable` / `gateway.disable` | → `{}` |
| `GET /settings` / `PUT /settings` | `settings.get` / `settings.set` | §12.2 subset (`device_name`, `gateway.*`, `ui.*`) |
| `POST /firewall/add` (Windows) | `firewall.add` | → `{}` (triggers UAC) |
| `GET /log` | `log.get` | → `{lines:[…]}` |
| `GET /events` (SSE) | — | events as `data: <event JSON>` |
| `POST /quit` | `app.quit` | → `{}` |
| Android-only | `sys.network_changed` | `{}` → `{}` |

Removed in Revision 2: `network.create/join/leave/reveal/reset`, `/network/qr.png`, `gateway.set_gps`. On Android every `gateway.*` method and `keyring.create` return `{"code":"unsupported"}`.

### 14.2 Validation

All inputs are validated in `core/api`, not in the UI: device name ≤ 32 chars after control-char stripping; keyring labels ≤ 32 chars likewise; hostnames `^[A-Za-z0-9.-]{1,253}$` or IP literals; ports 1024–65535; subnet must be a `/24` in private space; key text per §5.1 (checksum failure → `key_format`, distinct from `key_mismatch`); keyring size ≤ 16 (`keyring_full`).

### 14.3 Event schema (SSE and `Callbacks.OnEvent`)

```json
{"type":"status", "status":<status.get result>}
{"type":"gateways", "gateways":[…]}             // on every table change (incl. access changes), coalesced to ≤ 2/s
{"type":"keyring", "entries":[…]}               // on every keyring change (same shape as keyring.list)
{"type":"log", "line":"2026-11-01T10:00:00Z gateway: enabled (wg 51820, ctrl 51821)"}
{"type":"error", "code":"clock_skew", "message":"…"}
{"type":"elevation_needed", "reason":"client"}   // desktop: helper launch failed/cancelled
```

### 14.4 `mobile.Call` method names

Exactly the "Core method" column above. Arguments and results are the same JSON documents.

---

## 15. Repository layout, dependencies, build and release

### 15.1 Layout

```
private-vpn-pro/
├── go.mod                      module github.com/OWNER/private-vpn-pro ; go 1.27
├── cmd/private-vpn-pro/             main.go (subcommand dispatch), main_windows.go (manifest/console), …
├── core/
│   ├── netkey/                 NK generation, text/QR format, HKDF subkeys, beacon tag (HMAC)
│   ├── keyring/                keyring entries, dedup, replace-or-add rule, trial-verify helpers
│   ├── wire/                   control envelope + beacon layout, encode/decode, AEAD/HMAC, size tables, fuzz tests
│   ├── beacon/                 sender (per-interface multicast+broadcast), receiver (tag trial, spam caps), gateway table with access state
│   ├── control/                UDP control server (gateway side) + client (JOIN/RENEW/LEAVE/INFO), replay cache, limiters
│   ├── gwstack/                gVisor stack as tun.Device, TCP/UDP forwarders, DNS forwarder, policy
│   ├── gateway/                gateway engine: WG device, leases, address pool, limits, lifecycle
│   ├── client/                 session state machine, endpoint selection, self-test
│   ├── tunnel/                 Tunnel interface; tunnel_windows.go, tunnel_darwin.go, tunnel_linux.go, tunnel_android.go
│   ├── netbind/                per-OS socket binding (fwmark / IP_UNICAST_IF / IP_BOUND_IF), physical-interface tracker
│   ├── geo/                    providers, validation, refresh scheduler, cache
│   ├── sysinfo/                OS/version, LAN IPs, tz, uptime, resolvers, network-change watcher
│   ├── state/                  state.json load/save (atomic), per-OS paths, lock file
│   ├── eventlog/               ring buffer, redaction helpers
│   ├── api/                    transport-agnostic methods + event bus
│   └── engine/                 orchestrator: wires everything, owns role state, dual-role rules
├── desktop/
│   ├── tray/                   systray wiring, icons (embedded PNG/ICO)
│   ├── web/                    HTTP server, auth, headers; ui/ (index.html, app.js, app.css, login.html, icons.svg)
│   ├── helper/                 tunnel-helper process: pipe/socket server, ops, per-OS elevation launchers
│   ├── firewall/               Windows netsh rule add/remove/check
│   └── autostart/              per-OS autostart registration
├── mobile/                     gomobile facade (package mobile)
├── android/                    Gradle project (§11.1); app/libs/core.aar is build output, git-ignored
├── build/
│   ├── windows/ (winres.json, manifest.xml, icon.ico, fetch-wintun.sh)
│   ├── macos/   (Info.plist, make-app.sh, icon.icns)
│   ├── linux/   (app.privatevpnpro.policy, private-vpn-pro.desktop, icon.png)
│   └── android/ (signing.gradle snippet)
├── .github/workflows/ci.yml, release.yml
└── docs/ARCHITECTURE.md, docs/DECISIONS.md, docs/TESTING.md
```

### 15.2 Build tags

`core/tunnel` and `core/netbind` use `//go:build windows|darwin|linux|android` files; note `android` builds also satisfy `linux`, so Linux-only files must use `//go:build linux && !android`. `desktop/*` is excluded from the mobile build with `//go:build !android`.

### 15.3 Dependencies (verified versions; pin these in `go.mod`)

| Module | Version | Use |
|---|---|---|
| `golang.zx2c4.com/wireguard` | `v0.0.0-20261024220952-b3bc704ef0ee` | device, conn, tun, tun/netstack (template) |
| `golang.zx2c4.com/wireguard/windows` | `v1.1.1` | `tunnel/winipcfg`, `tunnel/firewall`, reference `tunnel/addressconfig.go` |
| `golang.zx2c4.com/wintun` | `v0.0.0-20230126152724-0fa3db229ce2` | pulled by wireguard tun on Windows |
| `gvisor.dev/gvisor` | `v0.0.0-20261031110703-16342efb9a78` (branch `go`) | `pkg/tcpip/...` |
| `golang.org/x/crypto` | `v0.58.0` | `chacha20poly1305` |
| `golang.org/x/sys` | `v0.49.0` | socket options, ShellExecute, DPAPI (v1.1) |
| `golang.org/x/net` | `v0.60.0` | `ipv4` (multicast), `dns/dnsmessage`, `route` (macOS) |
| `golang.org/x/mobile` | `v0.0.0-20261011034528-197770444867` | `gomobile bind` |
| `fyne.io/systray` | `v1.12.2` | tray |
| `github.com/Microsoft/go-winio` | `v0.6.4` | named pipes with DACL: `winio.ListenPipe(path, &winio.PipeConfig{SecurityDescriptor: "<SDDL>", MessageMode: true})` |
| `github.com/skip2/go-qrcode` | latest | QR PNG |
| `github.com/tc-hib/go-winres` | latest (build tool only) | manifest + icon `.syso` |
| Go stdlib | 1.27 | `crypto/hkdf`, `crypto/ecdh`, `net/netip`, `net/http`, `embed` |

Binary size: gVisor adds ≈ 12 MB; build with `-trimpath -ldflags "-s -w -X main.version=…"`.

### 15.4 GitHub Actions

Pin every action by commit SHA. Secrets: `ANDROID_KEYSTORE_B64`, `ANDROID_KEYSTORE_PASSWORD`, `ANDROID_KEY_ALIAS`, `ANDROID_KEY_PASSWORD`.

**`ci.yml`** (push, PR): ubuntu-latest → `go vet ./...`, `go test -race ./...` (incl. wire fuzz corpus), `staticcheck`, cross-build `GOOS=windows/linux` amd64+arm64 with `CGO_ENABLED=0`; macos-14 → `go build` (cgo for systray); android → see release job but `assembleDebug`, unsigned.

**`release.yml`** (tag `v*`):

| Job | Runner | Steps | Artifact |
|---|---|---|---|
| windows | ubuntu-latest | `go-winres make` (manifest+icon) → `CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "-s -w -H windowsgui -X main.version=$TAG" -o private-vpn-pro.exe ./cmd/private-vpn-pro` (and arm64) → `build/windows/fetch-wintun.sh`: download `https://www.wintun.net/builds/wintun-0.14.1.zip`, **verify `sha256 = 07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51`** (verified 2026-11-01), extract `wintun/bin/amd64/wintun.dll` / `arm64` → zip | `private-vpn-pro-windows-amd64.zip`, `…-arm64.zip` (exe + wintun.dll + README + LICENSES) |
| macos | macos-14 | build arm64 and amd64 (`CGO_ENABLED=1`), `lipo -create`, `build/macos/make-app.sh` → `Private VPN Pro.app` (Info.plist, icon), `codesign -s - --deep` (ad-hoc), `build/macos/make-dmg.sh` (`hdiutil`) | `private-vpn-pro-macos-universal.dmg` |
| linux | ubuntu-latest | `CGO_ENABLED=0` amd64 + arm64; tar with `.desktop`, policy file, icon | `private-vpn-pro-linux-amd64.tar.gz`, `…-arm64…` |
| android | ubuntu-latest | `actions/setup-java` (21), `android-actions/setup-android`, `sdkmanager "platforms;android-36" "build-tools;36.0.0" "ndk;27.2.12479018"`; `go install golang.org/x/mobile/cmd/gomobile@<pinned>`; `gomobile init`; `gomobile bind -target android/arm64,android/arm,android/amd64 -androidapi 26 -javapkg app.privatevpnpro -trimpath -ldflags "-s -w -X …" -o android/app/libs/core.aar ./mobile`; decode keystore from secret to `$RUNNER_TEMP/release.jks`; `./gradlew assembleRelease` with `signingConfigs.release` reading the four env vars | `private-vpn-pro-android.apk` |
| publish | ubuntu-latest (needs all) | `sha256sum * > SHA256SUMS`; `gh release create $TAG --notes-file …` | GitHub Release |

Versioning: tags `vMAJOR.MINOR.PATCH`; Go `main.version` from the tag; Android `versionName = tag`, `versionCode = MAJOR*10000 + MINOR*100 + PATCH`. The **wire protocol version** (`0x01`) changes only on incompatible changes; the app refuses nothing by app version, only by wire version.

Local developer loop (macOS dev machine): `make core-aar` (gomobile with `ANDROID_NDK_HOME` pointing at NDK 27), `make desktop` (`go run ./cmd/private-vpn-pro`), `make windows` (cross-compile + copy `wintun.dll` from the verified zip into `dist/windows/`).

---

## 16. Scope and milestones

### 16.1 v1.0 — must ship (3 gateway OSes × 4 client OSes, every pairing)

Core: netkey (+ beacon tag), keyring, wire (+fuzz), beacon (public + tag trial + spam caps), control, gwstack, gateway, client, tunnel (4 OSes), netbind, geo, sysinfo, state (schema 2), eventlog, api, engine.
Desktop: tray, web UI (Gateways with lock/unlock flow, Networks/keyring, Gateway mode, Status, Log, Settings; ⓘ panel), local API security, helper (Windows/macOS/Linux) with elevation, Windows firewall rule, Windows DNS-leak WFP rules, autostart, single instance, manual gateways, dual role.
Android (client-only): gateway list with lock badges + ⓘ, key entry by QR scan / paste (asked once per network), keyring screen, client mode (VpnService), manual "add by address", network-change callback, notification.
CI/release: all jobs in §15.4.

**Suggested build order** (so the first field test happens early): M1 core protocol + keyring + gwstack + gateway engine (desktop, unprivileged) with a CLI test client on Linux/macOS (in-process TUN as root) → M2 desktop tray/web UI + Windows firewall → M3 Android client incl. unlock flow → **first field test: Windows gateway ← Android client** → M4 desktop helper (Windows → macOS → Linux) → M5 desktop dual role + manual-gateway INFO trial + key-reset/`key_changed` UX → M6 release pipeline hardening and the pairing matrix (§17).

### 16.2 v1.1 — next

DPAPI/Keychain/Android-Keystore wrapping of `state.json` secrets; full kill-switch on Windows (`doNotRestrict=false`) and a `pf`/`nftables` equivalent; directory/rendezvous server (§6.8) and NAT traversal hints; signed/notarised macOS build with `SMAppService` helper; Windows service hosting the helper (zero prompts); Linux `.deb`/`.rpm`; iOS client (NetworkExtension) if ever.

### 16.3 Explicitly out of scope

Android gateway mode (product decision, Revision 2); chaining through an upstream gateway; IPv6 forwarding; per-app routing; traffic accounting per client (would be identifying); any server-side component in v1.

---

## 17. Testing requirements (summary; details in `docs/TESTING.md`)

* **Unit/fuzz**: `core/wire` round-trips and `go test -fuzz` on every decoder incl. the beacon (must never panic, never allocate > 2 KB per datagram); beacon tag trial against a 16-entry keyring; spam caps and verified-beats-unverified rule; replace-or-add keyring rule; replay cache; address pool; policy table; DNS forwarder (AAAA, TC, malformed); geo validation with hostile fixtures (bidi, 10 KB strings, NaN).
* **Integration (single host, no privileges)**: two engines in one process — gateway on `127.0.0.1` with netstack, client using `tun/netstack` (`CreateNetTUN`) instead of a real TUN → HTTP through the tunnel against a local test server, DNS through the forwarder, lease expiry, dual-role subnet conflict; locked → unlock (beacon tag) → connect; manual entry → INFO trial → connect; gateway `reset_key` → client shows `key_changed` → unlock replaces the keyring entry in place.
* **Pairing matrix** (manual, before each release): gateway ∈ {Windows, macOS, Linux} × client ∈ {Windows, macOS, Linux, Android} = 12 pairs; each: discovery ≤ 5 s (listed locked on a fresh device, verified after key entry), connect ≤ 10 s, public IP as seen by the client equals the gateway's INFO `public_ip`, DNS works, AAAA empty, ⓘ panel live clock, disconnect leaves no routes/DNS changes (`route print`/`netstat -rn`/`ip rule`), and `state.json` on the gateway contains no client data (byte-compare before/after a session).
* **Security checks**: `curl -H 'Host: evil.example' http://127.0.0.1:47771/api/v1/status` → 421; cross-site CSRF page fixture → 403; unauthenticated UDP junk to 51820/51821 → zero responses (tcpdump); flood test → gateway stays responsive to a valid member; client cannot reach `127.0.0.1:47771` or the gateway's LAN IP through the tunnel; a forged beacon (wrong tag, real gateway's pubkey, other source IP) never displaces the verified entry and a forged beacon with a fresh pubkey appears only as locked/unverified; 1000 forged beacons/s from one source → list shows ≤ 4 entries from it and the UI stays responsive; a wrong key entered for a locked gateway is rejected locally with no datagram sent (tcpdump).
* **Android**: VPN revoke → clean disconnect; process death → no stale foreground service; app backgrounded with an active session → list keeps updating (MulticastLock held).

---

## 18. Implementation risks (ranked)

1. **Desktop helper elevation UX** (UAC / `osascript` / `pkexec`) and crash-cleanup on three OSes — the most OS-specific code in the project; mitigated by the "helper exits on pipe close" rule and the macOS DNS backup file.
2. **Windows networking details**: WFP DNS-leak rules (`tunnel/firewall.EnableFirewall`, verified), endpoint `/32` maintenance across route changes, interface metric handling (`MibIPInterfaceRow{UseAutomaticMetric:false, Metric:0, NLMTU:1280}.Set()`). Mirror wireguard-windows's `tunnel/` package line by line.
3. **gVisor as a router**: promiscuous/spoofing forwarder behaviour under load, buffer growth, goroutine counts; mitigated by hard caps (§8.7) and a soak test (1000 concurrent flows, 1 h).
4. **Public-beacon UX under hostile LANs**: forged entries are harmless by construction but can confuse users; the spam caps, ordering and "unverified" labelling must be implemented exactly as §6.2/§13.3 say, and the first-run empty-state copy must make "locked = enter the key once" obvious.
5. **gomobile toolchain** with Go 1.27 and NDK 27 (pseudo-versioned module, occasional breakage); mitigated by pinning the x/mobile commit and testing `gomobile bind` in CI on every push.
6. **Beacon delivery** on exotic APs (client isolation, multicast filtering): mitigated by broadcast + multicast and the manual `host:port` path; the Gateway page's self-check surfaces "your LAN is filtering broadcasts".
7. **Clock skew** on devices without NTP (rare) breaks every control message; surfaced as an explicit error.
