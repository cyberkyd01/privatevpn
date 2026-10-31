// Package netbind binds the gateway's outbound OS sockets to the physical
// network while this device's own client tunnel is up (dual role,
// ARCHITECTURE §7.4), so traffic forwarded for this device's clients never
// enters the upstream tunnel.
//
// Linux marks every socket with SO_MARK FwMark (policy routing sends marked
// traffic via the main table). Windows (IP_UNICAST_IF) and macOS (IP_BOUND_IF)
// bind sockets to the physical default interface, but only for destinations
// outside private, link-local and on-link ranges. Elsewhere it is a no-op.
package netbind

import (
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// FwMark is the Linux socket mark that the client tunnel's policy routing
// exempts from the tunnel (§7.4, §9.4).
const FwMark = 0x5056

// errNoPhysical is returned by Control when a socket must be bound but no
// physical default interface is known. Failing closed keeps forwarded traffic
// out of the tunnel (D12: never chain).
var errNoPhysical = errors.New("netbind: no physical default interface")

// physical is a snapshot of the physical network, replaced atomically.
type physical struct {
	index4, index6 uint32         // default interface index per family; 0 = none
	onLink         []netip.Prefix // subnets of non-tunnel interfaces
}

var (
	bypass      atomic.Bool
	phys        atomic.Pointer[physical]
	refreshMu   sync.Mutex
	lastExclude string // guarded by refreshMu
)

// SetBypass turns binding on or off. The engine sets it while this device's
// own client tunnel is up.
func SetBypass(active bool) {
	bypass.Store(active)
	if active && phys.Load() == nil {
		refreshMu.Lock()
		ex := lastExclude
		refreshMu.Unlock()
		_ = RefreshPhysical(ex)
	}
}

// RefreshPhysical recomputes the physical default interface: the interface
// carrying the lowest-metric default route, ignoring the interface named
// excludeIfName (our tunnel). Call it on every network change.
func RefreshPhysical(excludeIfName string) error {
	refreshMu.Lock()
	defer refreshMu.Unlock()
	lastExclude = excludeIfName
	i4, i6, err := defaultInterfaces(excludeIfName)
	p := &physical{index4: i4, index6: i6, onLink: onLinkPrefixes(excludeIfName)}
	phys.Store(p)
	return err
}

// CanMark reports whether this process can apply Control's socket option.
// On Linux SO_MARK needs CAP_NET_ADMIN; without it dual role cannot keep
// forwarded traffic out of the tunnel (it fails closed), so the engine
// refuses the role combination. Always true elsewhere.
func CanMark() bool { return canMark() }

// Control is a net.Dialer / net.ListenConfig Control function. It does
// nothing unless bypass is active.
func Control(network, address string, c syscall.RawConn) error {
	if !bypass.Load() {
		return nil
	}
	return control(network, address, c)
}

// Dialer returns a dialer whose sockets are bound per Control.
func Dialer(timeout time.Duration) *net.Dialer {
	return &net.Dialer{Timeout: timeout, Control: Control}
}

// ListenConfig returns a listen config whose sockets are bound per Control.
// Wildcard local addresses count as "needs binding".
func ListenConfig() *net.ListenConfig {
	return &net.ListenConfig{Control: Control}
}

// target is what a socket option implementation needs to know.
type target struct {
	v6   bool // AF_INET6 socket
	dual bool // AF_INET6 socket that may carry IPv4 (wildcard or v4-mapped)
}

// classify decides whether a socket for address must be bound. Loopback,
// private (RFC 1918, ULA), link-local and on-link destinations are left to
// the routing table; everything else, including wildcard listen addresses,
// is bound.
func classify(network, address string) (target, bool) {
	t := target{v6: strings.HasSuffix(network, "6")}
	ap, err := netip.ParseAddrPort(address)
	if err != nil {
		host, _, serr := net.SplitHostPort(address)
		if serr != nil {
			host = address
		}
		a, perr := netip.ParseAddr(host)
		if perr != nil {
			return t, true // unresolvable here: bind (fail toward the physical path)
		}
		ap = netip.AddrPortFrom(a, 0)
	}
	raw := ap.Addr().WithZone("")
	a := raw.Unmap()
	if !t.v6 && a.Is6() {
		t.v6 = true
	}
	if t.v6 && (raw.Is4In6() || a.IsUnspecified()) {
		t.dual = true
	}
	if a.IsUnspecified() {
		return t, true
	}
	if a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() {
		return t, false
	}
	if p := phys.Load(); p != nil {
		for _, pfx := range p.onLink {
			if pfx.Contains(a) {
				return t, false
			}
		}
	}
	return t, true
}

// onLinkPrefixes lists the subnets of all up, non-loopback interfaces except
// the excluded one.
func onLinkPrefixes(exclude string) []netip.Prefix {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []netip.Prefix
	for _, ifc := range ifs {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 || (exclude != "" && ifc.Name == exclude) {
			continue
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip, ok := netip.AddrFromSlice(ipn.IP)
			if !ok {
				continue
			}
			ones, _ := ipn.Mask.Size()
			ip = ip.Unmap()
			if ip.Is4() && ones > 32 {
				ones -= 96
			}
			if pfx, err := ip.Prefix(ones); err == nil {
				out = append(out, pfx)
			}
		}
	}
	return out
}
