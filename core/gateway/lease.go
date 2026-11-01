package gateway

import (
	"net/netip"
	"time"

	"github.com/cyberkyd01/private-vpn-pro/core/eventlog"
	"github.com/cyberkyd01/private-vpn-pro/core/gwstack"
)

// lease is one client's state (§8.2). Memory only, never serialised;
// String() is redacted.
type lease struct {
	eventlog.Redacted

	pub      [32]byte
	ip       netip.Addr
	token    [16]byte
	expires  time.Time
	mtu      int
	client   *gwstack.Client
	endpoint netip.Addr // learned WireGuard endpoint (only tracked with an EndpointHook)
	routed   bool       // EndpointHook(endpoint, true) is in effect
}

// pool hands out .2–.254, least recently released first: never-used
// addresses come first, released ones queue at the back.
type pool struct {
	free []netip.Addr
}

func newPool(subnet netip.Prefix) *pool {
	base := subnet.Masked().Addr().As4()
	p := &pool{free: make([]netip.Addr, 0, poolSize)}
	for i := 2; i <= 254; i++ {
		base[3] = byte(i)
		p.free = append(p.free, netip.AddrFrom4(base))
	}
	return p
}

func (p *pool) get() (netip.Addr, bool) {
	if len(p.free) == 0 {
		return netip.Addr{}, false
	}
	a := p.free[0]
	p.free = p.free[1:]
	return a, true
}

func (p *pool) put(a netip.Addr) { p.free = append(p.free, a) }

// leaseTable maps keys and addresses to leases. Not synchronised.
type leaseTable struct {
	pool  *pool
	byKey map[[32]byte]*lease
}

func newLeaseTable(subnet netip.Prefix) *leaseTable {
	return &leaseTable{pool: newPool(subnet), byKey: map[[32]byte]*lease{}}
}

// add allocates an address for pub, which must not have a lease.
func (t *leaseTable) add(pub [32]byte) (*lease, error) {
	ip, ok := t.pool.get()
	if !ok {
		return nil, ErrPoolFull
	}
	l := &lease{pub: pub, ip: ip}
	t.byKey[pub] = l
	return l, nil
}

// remove drops l and returns its address to the pool.
func (t *leaseTable) remove(l *lease) {
	if t.byKey[l.pub] != l {
		return
	}
	delete(t.byKey, l.pub)
	t.pool.put(l.ip)
}

// expired returns the leases whose lifetime ended before now.
func (t *leaseTable) expired(now time.Time) []*lease {
	var out []*lease
	for _, l := range t.byKey {
		if now.After(l.expires) {
			out = append(out, l)
		}
	}
	return out
}
