package gwstack

import (
	"net/netip"
	"sync/atomic"
)

// Verdict is the outcome of a destination policy check.
type Verdict int

const (
	Deny     Verdict = iota // TCP: RST; UDP: silent drop
	Forward                 // dial the destination with an OS socket
	LocalDNS                // this gateway's DNS forwarder (.1:53)
)

func (v Verdict) String() string {
	switch v {
	case Deny:
		return "deny"
	case Forward:
		return "forward"
	case LocalDNS:
		return "local-dns"
	}
	return "invalid"
}

var (
	// alwaysDeny holds the fixed host/special ranges of §8.5.
	alwaysDeny = []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/8"),
		netip.MustParsePrefix("127.0.0.0/8"),
		netip.MustParsePrefix("169.254.0.0/16"),
		netip.MustParsePrefix("224.0.0.0/4"),
		netip.MustParsePrefix("240.0.0.0/4"),
	}
	// lanRanges are denied unless LAN access is on.
	lanRanges = []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("172.16.0.0/12"),
		netip.MustParsePrefix("192.168.0.0/16"),
		netip.MustParsePrefix("100.64.0.0/10"),
	}
)

// Policy is the per-new-flow destination policy (§8.5). Safe for concurrent
// use.
type Policy struct {
	gw     netip.Addr
	subnet netip.Prefix
	lan    atomic.Bool
	extra  atomic.Pointer[[]netip.Prefix]
}

// NewPolicy returns a policy for the gateway at gw serving subnet, with LAN
// access off.
func NewPolicy(gw netip.Addr, subnet netip.Prefix) *Policy {
	return &Policy{gw: gw, subnet: subnet.Masked()}
}

// SetLANAccess switches access to the private ranges.
func (p *Policy) SetLANAccess(on bool) { p.lan.Store(on) }

// LANAccess reports whether the private ranges are reachable.
func (p *Policy) LANAccess() bool { return p.lan.Load() }

// SetExtraDeny replaces the host-specific deny list (the host's own
// addresses, a dual-role client-tunnel subnet). The slice is copied.
func (p *Policy) SetExtraDeny(pfx []netip.Prefix) {
	cp := make([]netip.Prefix, 0, len(pfx))
	for _, x := range pfx {
		if x.IsValid() {
			cp = append(cp, netip.PrefixFrom(x.Addr().Unmap(), x.Bits()).Masked())
		}
	}
	p.extra.Store(&cp)
}

// Check classifies a new TCP or UDP flow to dst.
func (p *Policy) Check(dst netip.AddrPort) Verdict {
	a := dst.Addr().Unmap()
	if !a.Is4() {
		return Deny
	}
	if p.subnet.Contains(a) {
		if a == p.gw && dst.Port() == 53 {
			return LocalDNS
		}
		return Deny
	}
	if dst.Port() == 0 {
		return Deny
	}
	for _, x := range alwaysDeny {
		if x.Contains(a) {
			return Deny
		}
	}
	if ex := p.extra.Load(); ex != nil {
		for _, x := range *ex {
			if x.Contains(a) {
				return Deny
			}
		}
	}
	if !p.lan.Load() {
		for _, x := range lanRanges {
			if x.Contains(a) {
				return Deny
			}
		}
	}
	return Forward
}

// AllowICMP reports whether an ICMP packet to dst may enter the stack: only
// echo to the gateway address is answered (§8.8).
func (p *Policy) AllowICMP(dst netip.Addr) bool { return dst == p.gw }
