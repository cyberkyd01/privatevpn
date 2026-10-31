// Package tunnel defines the client-mode tunnel contract (ARCHITECTURE §9).
//
// Implementations: native per-OS tunnels (tunnel_windows.go, tunnel_darwin.go,
// tunnel_linux.go — run inside the privileged helper), the Android tunnel
// (tunnel_android.go, TUN fd supplied by VpnService), and desktop/helper.Client
// (the unprivileged main process's proxy to the helper).
//
// # Kill switch (fail-closed)
//
// With Config.KillSwitch the native tunnels install an OS-level block of all
// traffic that does not go through the tunnel (persistent WFP filters on
// Windows, a pf anchor on macOS, a blackhole default route in the
// policy-routing table on Linux). The block is installed before the tunnel
// routes, replaced atomically on a re-Up or SetEndpoint, and — deliberately —
// survives the helper or main process crashing and a reboot (BFE persistence,
// a LaunchDaemon, a systemd unit): only an explicit Down removes it.
// `privatevpn unblock` (elevated) is the manual recovery.
package tunnel

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
)

// Peer is the single WireGuard peer (the gateway) of a client tunnel.
type Peer struct {
	PublicKey    [32]byte
	PresharedKey [32]byte
	Endpoint     netip.AddrPort
	Keepalive    int // seconds
}

// Config fully describes one client tunnel. It contains the ephemeral session
// private key: never log it, never persist it.
type Config struct {
	PrivateKey [32]byte
	Address    netip.Prefix // e.g. 10.77.42.2/24
	DNS        []netip.Addr // exactly the gateway tunnel IP in v1
	MTU        int
	Peer       Peer
	SinkIPv6   bool   // route ::/0 into the tunnel and drop it
	FwMark     uint32 // Linux only (20566); 0 elsewhere
	// KillSwitch blocks every packet that does not go through the tunnel
	// (except loopback, the gateway endpoint, DHCP/NDP and, with AllowLAN,
	// local networks) and keeps blocking after a crash until Down.
	KillSwitch bool
	// AllowLAN keeps RFC1918, link-local, multicast and broadcast
	// destinations reachable while the kill switch is on. Only Windows can
	// enforce AllowLAN=false; macOS and Linux report WarnLANNotBlocked.
	AllowLAN bool
}

// String deliberately hides everything.
func (Config) String() string { return "<redacted tunnel config>" }

// Status is reported by Tunnel.Status.
type Status struct {
	IfName          string `json:"ifname"`
	HandshakeAgeSec int64  `json:"handshake_age_sec"` // -1 = no handshake yet
	RxBytes         uint64 `json:"rx"`
	TxBytes         uint64 `json:"tx"`
	// Warnings lists what could not be protected (Warn* codes). Empty means
	// everything the config asked for is in place.
	Warnings []string `json:"warnings,omitempty"`
	// KillSwitchActive reports whether the OS-level block is installed.
	KillSwitchActive bool `json:"kill_switch_active,omitempty"`
}

// Warning codes (Status.Warnings). They are stable identifiers for the UI.
const (
	// WarnIPv6NotBlocked: the IPv6 sink/block could not be installed; sites
	// reachable over IPv6 may see the real address.
	WarnIPv6NotBlocked = "ipv6_not_blocked"
	// WarnDNSNotSet: the system resolver could not be pointed at the gateway.
	WarnDNSNotSet = "dns_not_set"
	// WarnKillSwitchFailed: Config.KillSwitch was requested but the block
	// could not be installed; a dropped tunnel would fall back to the
	// physical network.
	WarnKillSwitchFailed = "kill_switch_failed"
	// WarnLANNotBlocked: Config.AllowLAN was false but this OS cannot keep
	// local networks out (routing-based block; on-link destinations stay
	// reachable).
	WarnLANNotBlocked = "lan_not_blocked"
	// WarnDNSNotBlocked: other resolvers remain reachable while the kill
	// switch is on (Linux: the kernel lacks fib-rule port matching), so a
	// crash may let queries reach a LAN resolver.
	WarnDNSNotBlocked = "dns_not_blocked"
	// WarnKillSwitchNotPersistent: the block is in place for this boot but
	// the piece that re-installs it at the next boot (LaunchDaemon, systemd
	// unit, persistent WFP objects) could not be installed.
	WarnKillSwitchNotPersistent = "kill_switch_not_persistent"
)

// Tunnel is a client-mode tunnel. Methods are safe for concurrent use.
type Tunnel interface {
	// Up creates the TUN, WireGuard device, addresses, routes and DNS, and
	// (Config.KillSwitch) the fail-closed block, replacing any leftover one.
	// Calling Up while up replaces the previous tunnel without a window in
	// which traffic could leave through the physical network.
	Up(cfg Config) (ifname string, err error)
	// SetEndpoint changes the peer endpoint (roaming / re-JOIN) and updates
	// the endpoint exclusion route/permit (new permits before old ones go).
	SetEndpoint(ep netip.AddrPort) error
	// Status returns handshake age, byte counters and warnings.
	Status() (Status, error)
	// RouteAdd/RouteDel manage a /32 host route for dst via the physical
	// default gateway (dual role, §7.4). No-op where not needed (Linux,
	// Android). dst must be a public unicast IPv4 address.
	RouteAdd(dst netip.Addr) error
	RouteDel(dst netip.Addr) error
	// Down removes everything Up created, including the kill-switch block,
	// and also a block left behind by an earlier crashed session. Safe to
	// call when nothing is up; idempotent.
	Down() error
	// Close releases the implementation (helper exit). It removes the tunnel
	// but leaves a kill-switch block in place: a session that ends without
	// an explicit Down (crash, pipe closed, failure) must stay blocked.
	Close() error
}

// ErrNotElevated is returned by native tunnels / the helper client when
// administrator rights are missing or the elevation prompt was cancelled.
var ErrNotElevated = errors.New("administrator rights are required for client mode")

// configJSON is the on-the-wire form (helper pipe and Android EstablishTun),
// ARCHITECTURE §9.1.
type configJSON struct {
	PrivateKey string   `json:"private_key"`
	Address    string   `json:"address"`
	DNS        []string `json:"dns"`
	MTU        int      `json:"mtu"`
	Peer       struct {
		PublicKey    string   `json:"public_key"`
		PresharedKey string   `json:"preshared_key"`
		Endpoint     string   `json:"endpoint"`
		AllowedIPs   []string `json:"allowed_ips"`
		Keepalive    int      `json:"keepalive"`
	} `json:"peer"`
	SinkIPv6   bool   `json:"sink_ipv6"`
	FwMark     uint32 `json:"fwmark"`
	KillSwitch bool   `json:"kill_switch"`
	AllowLAN   bool   `json:"allow_lan"`
}

// MarshalJSON encodes Config in the §9.1 format.
func (c Config) MarshalJSON() ([]byte, error) {
	var j configJSON
	j.PrivateKey = base64.StdEncoding.EncodeToString(c.PrivateKey[:])
	j.Address = c.Address.String()
	j.DNS = []string{}
	for _, d := range c.DNS {
		j.DNS = append(j.DNS, d.String())
	}
	j.MTU = c.MTU
	j.Peer.PublicKey = base64.StdEncoding.EncodeToString(c.Peer.PublicKey[:])
	j.Peer.PresharedKey = base64.StdEncoding.EncodeToString(c.Peer.PresharedKey[:])
	j.Peer.Endpoint = c.Peer.Endpoint.String()
	j.Peer.AllowedIPs = []string{"0.0.0.0/0"}
	j.Peer.Keepalive = c.Peer.Keepalive
	j.SinkIPv6 = c.SinkIPv6
	j.FwMark = c.FwMark
	j.KillSwitch = c.KillSwitch
	j.AllowLAN = c.AllowLAN
	return json.Marshal(j)
}

// UnmarshalJSON decodes and validates the §9.1 format.
func (c *Config) UnmarshalJSON(b []byte) error {
	var j configJSON
	if err := json.Unmarshal(b, &j); err != nil {
		return err
	}
	var out Config
	if err := decodeKey(j.PrivateKey, &out.PrivateKey); err != nil {
		return fmt.Errorf("private_key: %w", err)
	}
	if err := decodeKey(j.Peer.PublicKey, &out.Peer.PublicKey); err != nil {
		return fmt.Errorf("peer.public_key: %w", err)
	}
	if err := decodeKey(j.Peer.PresharedKey, &out.Peer.PresharedKey); err != nil {
		return fmt.Errorf("peer.preshared_key: %w", err)
	}
	p, err := netip.ParsePrefix(j.Address)
	if err != nil || !p.Addr().Is4() {
		return fmt.Errorf("address: invalid")
	}
	out.Address = p
	if len(j.DNS) > 4 {
		return fmt.Errorf("dns: too many")
	}
	for _, d := range j.DNS {
		a, err := netip.ParseAddr(d)
		if err != nil {
			return fmt.Errorf("dns: invalid")
		}
		out.DNS = append(out.DNS, a)
	}
	if j.MTU < 576 || j.MTU > 1420 {
		return fmt.Errorf("mtu: out of range")
	}
	out.MTU = j.MTU
	ep, err := netip.ParseAddrPort(j.Peer.Endpoint)
	if err != nil {
		return fmt.Errorf("peer.endpoint: invalid")
	}
	out.Peer.Endpoint = ep
	if j.Peer.Keepalive < 0 || j.Peer.Keepalive > 600 {
		return fmt.Errorf("peer.keepalive: out of range")
	}
	out.Peer.Keepalive = j.Peer.Keepalive
	out.SinkIPv6 = j.SinkIPv6
	out.FwMark = j.FwMark
	out.KillSwitch = j.KillSwitch
	out.AllowLAN = j.AllowLAN
	*c = out
	return nil
}

func decodeKey(s string, dst *[32]byte) error {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(b) != 32 {
		return errors.New("must be 32 bytes base64")
	}
	copy(dst[:], b)
	return nil
}

// addWarning appends code to ws once.
func addWarning(ws []string, code string) []string {
	for _, w := range ws {
		if w == code {
			return ws
		}
	}
	return append(ws, code)
}
