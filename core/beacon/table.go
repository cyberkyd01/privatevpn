// Package beacon implements LAN discovery (ARCHITECTURE §6.2): the gateway's
// beacon sender, every device's receiver, and the in-memory gateway table
// with tag verification, replay checks and anti-spam limits.
package beacon

import (
	"net/netip"
	"slices"
	"sort"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/cyberkyd01/private-vpn-pro/core/wire"
)

// Table limits (§6.2).
const (
	MaxEntries         = 64
	MaxUnverified      = 16
	MaxUnverifiedPerIP = 4
	MaxEndpoints       = 3
	OnlineWindow       = 10 * time.Second
	ExpireAfter        = 5 * time.Minute
	TSWindow           = 120 * time.Second
	FreshBeacon        = 30 * time.Second // usable for local key verification
)

// KeyRef is one keyring entry's beacon key.
type KeyRef struct {
	ID      string
	KBeacon [32]byte
}

// Endpoint is one address a gateway was heard from.
type Endpoint struct {
	IP       netip.Addr
	WGPort   uint16
	CtrlPort uint16
	Verified bool
	LastSeen time.Time
	Raw      []byte // latest datagram from this endpoint (memory only)
}

// Entry is one gateway in the live table.
type Entry struct {
	Pub       [32]byte
	Beacon    wire.Beacon // latest accepted body
	Verified  bool
	NetworkID string // keyring id when Verified
	Endpoints []Endpoint
	FirstSeen time.Time
	LastSeen  time.Time
}

// Online reports whether the gateway was heard recently.
func (e Entry) Online(now time.Time) bool { return now.Sub(e.LastSeen) <= OnlineWindow }

type counterKey struct {
	pub [32]byte
	src netip.Addr
}

type counter struct {
	instance uint64
	value    uint32
}

// Table is safe for concurrent use.
type Table struct {
	mu       sync.Mutex
	entries  map[[32]byte]*Entry
	verCtr   map[[32]byte]counter
	unverCtr map[counterKey]counter
	perIP    map[netip.Addr]*rate.Limiter
	self     [32]byte
	now      func() time.Time
}

// NewTable returns an empty table.
func NewTable() *Table {
	return &Table{
		entries:  map[[32]byte]*Entry{},
		verCtr:   map[[32]byte]counter{},
		unverCtr: map[counterKey]counter{},
		perIP:    map[netip.Addr]*rate.Limiter{},
		now:      time.Now,
	}
}

// SetSelf sets our own gateway public key (its beacons are ignored).
func (t *Table) SetSelf(pub [32]byte) {
	t.mu.Lock()
	t.self = pub
	t.mu.Unlock()
}

func newer(c counter, inst uint64, v uint32, have bool) bool {
	if !have || c.instance != inst {
		return true // new engine instance resets the counter
	}
	return v > c.value
}

// Handle processes one received datagram. keys are tried in order (most
// recently used first). It reports whether the table changed.
func (t *Table) Handle(raw []byte, from netip.Addr, keys []KeyRef) bool {
	b, ok := wire.ParseBeacon(raw)
	if !ok {
		return false
	}
	now := t.now()
	d := now.Sub(time.Unix(int64(b.TS), 0))
	if d > TSWindow || d < -TSWindow {
		return false
	}
	from = from.Unmap()
	if !from.Is4() {
		return false
	}
	netID := ""
	for _, k := range keys {
		if wire.VerifyBeacon(raw, k.KBeacon) {
			netID = k.ID
			break
		}
	}

	t.mu.Lock()
	defer t.mu.Unlock()
	if b.GatewayPub == t.self {
		return false
	}
	e := t.entries[b.GatewayPub]

	if netID != "" {
		c, have := t.verCtr[b.GatewayPub]
		if !newer(c, b.InstanceID, b.Counter, have) {
			return false
		}
		t.verCtr[b.GatewayPub] = counter{b.InstanceID, b.Counter}
		if e == nil {
			if !t.makeRoom(true) {
				return false
			}
			e = &Entry{Pub: b.GatewayPub, FirstSeen: now}
			t.entries[b.GatewayPub] = e
		}
		if !e.Verified {
			e.Endpoints = nil // drop endpoints learned from unverified beacons
		}
		e.Verified, e.NetworkID = true, netID
		t.update(e, b, raw, from, true, now)
		return true
	}

	// Unverified path: spam limits apply.
	if e != nil && e.Verified && (now.Sub(e.LastSeen) <= OnlineWindow || !e.hasEndpoint(from)) {
		// While verified beacons keep arriving, unverified ones for the same
		// key are ignored (spoofing cannot downgrade a member gateway). Once
		// they have stopped (e.g. the gateway reset its key), the next
		// unverified beacon from an address the gateway was verified at
		// turns the entry locked; a forgery from elsewhere cannot take over
		// an offline member's entry and endpoints (it waits for expiry).
		return false
	}
	lim := t.perIP[from]
	if lim == nil {
		if len(t.perIP) > 1024 {
			t.perIP = map[netip.Addr]*rate.Limiter{}
		}
		lim = rate.NewLimiter(2, 2)
		t.perIP[from] = lim
	}
	if !lim.AllowN(now, 1) {
		return false
	}
	ck := counterKey{b.GatewayPub, from}
	c, have := t.unverCtr[ck]
	if !newer(c, b.InstanceID, b.Counter, have) {
		return false
	}
	if e == nil {
		if t.unverifiedFrom(from) >= MaxUnverifiedPerIP || !t.makeRoom(false) {
			return false
		}
		e = &Entry{Pub: b.GatewayPub, FirstSeen: now}
		t.entries[b.GatewayPub] = e
	}
	if len(t.unverCtr) > 4*MaxEntries {
		t.unverCtr = map[counterKey]counter{}
	}
	t.unverCtr[ck] = counter{b.InstanceID, b.Counter}
	if e.Verified {
		e.Endpoints = nil
	}
	e.Verified, e.NetworkID = false, ""
	t.update(e, b, raw, from, false, now)
	return true
}

func (e *Entry) hasEndpoint(ip netip.Addr) bool {
	for _, ep := range e.Endpoints {
		if ep.IP == ip {
			return true
		}
	}
	return false
}

func (t *Table) update(e *Entry, b wire.Beacon, raw []byte, from netip.Addr, verified bool, now time.Time) {
	e.Beacon = b
	e.LastSeen = now
	ep := Endpoint{IP: from, WGPort: b.WGPort, CtrlPort: b.CtrlPort, Verified: verified, LastSeen: now,
		Raw: append([]byte(nil), raw...)}
	eps := []Endpoint{ep}
	for _, old := range e.Endpoints {
		if old.IP != from && len(eps) < MaxEndpoints {
			eps = append(eps, old)
		}
	}
	e.Endpoints = eps
}

func (t *Table) unverifiedFrom(ip netip.Addr) int {
	n := 0
	for _, e := range t.entries {
		if !e.Verified && e.hasEndpoint(ip) {
			n++
		}
	}
	return n
}

// makeRoom ensures space for one more entry. Unverified entries may only
// evict unverified entries (LRU); verified entries are never evicted.
func (t *Table) makeRoom(verified bool) bool {
	unver := 0
	for _, e := range t.entries {
		if !e.Verified {
			unver++
		}
	}
	needEvict := len(t.entries) >= MaxEntries || (!verified && unver >= MaxUnverified)
	if !needEvict {
		return true
	}
	var oldest *Entry
	for _, e := range t.entries {
		if !e.Verified && (oldest == nil || e.LastSeen.Before(oldest.LastSeen)) {
			oldest = e
		}
	}
	if oldest == nil {
		return false
	}
	delete(t.entries, oldest.Pub)
	return true
}

// Reverify re-checks every endpoint's latest raw beacon against keys, e.g.
// after a key was added or removed. An entry that becomes verified keeps
// only the endpoints whose beacon verifies (the others may be forgeries
// collected while it was locked). It reports whether anything changed.
func (t *Table) Reverify(keys []KeyRef) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	changed := false
	for _, e := range t.entries {
		netID := ""
		var eps []Endpoint
		for _, ep := range e.Endpoints {
			ep.Verified = false
			for _, k := range keys {
				if wire.VerifyBeacon(ep.Raw, k.KBeacon) {
					if netID == "" {
						netID = k.ID
					}
					ep.Verified = k.ID == netID
					break
				}
			}
			eps = append(eps, ep)
		}
		if netID != "" {
			eps = slices.DeleteFunc(eps, func(ep Endpoint) bool { return !ep.Verified })
		}
		if (netID != "") != e.Verified || netID != e.NetworkID || len(eps) != len(e.Endpoints) {
			e.Verified, e.NetworkID, e.Endpoints = netID != "", netID, eps
			changed = true
		}
	}
	return changed
}

// Expire drops entries not heard from for ExpireAfter.
func (t *Table) Expire() bool {
	now := t.now()
	t.mu.Lock()
	defer t.mu.Unlock()
	changed := false
	for k, e := range t.entries {
		if now.Sub(e.LastSeen) > ExpireAfter {
			delete(t.entries, k)
			delete(t.verCtr, k)
			changed = true
		}
	}
	return changed
}

// Get returns a copy of one entry.
func (t *Table) Get(pub [32]byte) (Entry, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	e, ok := t.entries[pub]
	if !ok {
		return Entry{}, false
	}
	return e.clone(), true
}

// Snapshot returns copies of all entries, most recently seen first.
func (t *Table) Snapshot() []Entry {
	t.mu.Lock()
	out := make([]Entry, 0, len(t.entries))
	for _, e := range t.entries {
		out = append(out, e.clone())
	}
	t.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].LastSeen.After(out[j].LastSeen) })
	return out
}

func (e *Entry) clone() Entry {
	c := *e
	c.Endpoints = make([]Endpoint, len(e.Endpoints))
	for i, ep := range e.Endpoints {
		ep.Raw = append([]byte(nil), ep.Raw...)
		c.Endpoints[i] = ep
	}
	return c
}
