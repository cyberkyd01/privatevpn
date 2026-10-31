package tunnel

import (
	"errors"
	"net/netip"
)

// MaxHostRoutes caps the dual-role /32 routes one tunnel manages (§7.4).
const MaxHostRoutes = 1024

var (
	errClosed      = errors.New("tunnel: closed")
	errNotUp       = errors.New("tunnel: not up")
	errTooManyHost = errors.New("tunnel: too many host routes")
)

// Validate checks a Config before any system state is touched. Error
// messages never echo keys or addresses.
func (c Config) Validate() error {
	if isZeroKey(c.PrivateKey) {
		return errors.New("tunnel config: private key missing")
	}
	if isZeroKey(c.Peer.PublicKey) {
		return errors.New("tunnel config: peer public key missing")
	}
	a := c.Address
	if !a.IsValid() || !a.Addr().Is4() || a.Bits() < 8 || a.Bits() > 30 {
		return errors.New("tunnel config: address must be an IPv4 prefix /8–/30")
	}
	if a.Addr() == a.Masked().Addr() || a.Addr() == lastAddr(a) {
		return errors.New("tunnel config: address is the network or broadcast address")
	}
	if len(c.DNS) > 4 {
		return errors.New("tunnel config: too many DNS servers")
	}
	for _, d := range c.DNS {
		if !d.Is4() || d.IsUnspecified() || d.IsMulticast() || d.IsLoopback() {
			return errors.New("tunnel config: DNS servers must be IPv4 unicast")
		}
	}
	if c.MTU < 576 || c.MTU > 1420 {
		return errors.New("tunnel config: mtu out of range")
	}
	if err := CheckEndpoint(c.Peer.Endpoint); err != nil {
		return err
	}
	if c.Peer.Keepalive < 0 || c.Peer.Keepalive > 600 {
		return errors.New("tunnel config: keepalive out of range")
	}
	return nil
}

// CheckEndpoint validates a WireGuard peer endpoint. v1 requires IPv4: the
// IPv6 sink routes (§7.6) would capture an IPv6 endpoint. Private (LAN)
// addresses are allowed.
func CheckEndpoint(ep netip.AddrPort) error {
	a := ep.Addr()
	if !ep.IsValid() || ep.Port() == 0 || !a.Is4() {
		return errors.New("tunnel: endpoint must be IPv4 address:port")
	}
	if a.IsUnspecified() || a.IsLoopback() || a.IsMulticast() || a == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
		return errors.New("tunnel: endpoint is not a unicast address")
	}
	return nil
}

var (
	pfxThisNet  = netip.MustParsePrefix("0.0.0.0/8")
	pfxReserved = netip.MustParsePrefix("240.0.0.0/4")
)

// CheckPublicIPv4 reports whether a is acceptable as a dual-role host route
// destination (route_add, §13.5): a single public unicast IPv4 address —
// never private, loopback, link-local, multicast, broadcast, 0/8 or 240/4.
// Shared address space (100.64/10) is accepted: a peer in the same carrier
// NAT is reached via the default gateway too.
func CheckPublicIPv4(a netip.Addr) error {
	if !a.Is4() || !a.IsGlobalUnicast() || a.IsPrivate() || pfxThisNet.Contains(a) || pfxReserved.Contains(a) {
		return errors.New("tunnel: host route destination must be a public unicast IPv4 address")
	}
	return nil
}

func isZeroKey(k [32]byte) bool {
	var z [32]byte
	return k == z
}

// lastAddr returns the broadcast address of an IPv4 prefix.
func lastAddr(p netip.Prefix) netip.Addr {
	b := p.Masked().Addr().As4()
	host := 32 - p.Bits()
	v := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	v |= (1 << host) - 1
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}

// peerTunnelAddr is the gateway's tunnel address (.1 of the subnet, §7.2),
// used as the point-to-point destination on macOS.
func peerTunnelAddr(p netip.Prefix) netip.Addr {
	a := p.Masked().Addr().Next()
	if a == p.Addr() {
		a = a.Next()
	}
	return a
}

// netmask4 renders the prefix length as a dotted IPv4 netmask.
func netmask4(bits int) string {
	v := ^uint32(0) << (32 - bits)
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}).String()
}
