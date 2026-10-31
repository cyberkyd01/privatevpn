package gateway

import (
	"crypto/rand"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/cyberkyd01/privatevpn/core/eventlog"
)

func randKey() [32]byte {
	var k [32]byte
	rand.Read(k[:])
	return k
}

func TestStartValidation(t *testing.T) {
	priv, _ := newKey(t)
	for name, cfg := range map[string]Config{
		"no key":        {},
		"public subnet": {PrivateKey: priv, Subnet: netip.MustParsePrefix("8.8.8.0/24")},
		"wide subnet":   {PrivateKey: priv, Subnet: netip.MustParsePrefix("10.77.0.0/16")},
		"ipv6 subnet":   {PrivateKey: priv, Subnet: netip.MustParsePrefix("fd00::/120")},
		"tiny MTU":      {PrivateKey: priv, MTU: 500},
		"bad port":      {PrivateKey: priv, ListenPort: 70000},
	} {
		cfg.Log = eventlog.New(10)
		if g, err := Start(cfg); err == nil {
			g.Close()
			t.Errorf("%s: Start succeeded", name)
		}
	}
}

func TestDefaults(t *testing.T) {
	g := startGateway(t, nil)
	if g.Subnet() != DeriveSubnet(g.PublicKey()) || g.mtu != 1280 {
		t.Fatalf("subnet %v mtu %d", g.Subnet(), g.mtu)
	}
	g2 := startGateway(t, func(c *Config) { c.Subnet = netip.MustParsePrefix("192.168.250.77/24") })
	if g2.Subnet() != netip.MustParsePrefix("192.168.250.0/24") {
		t.Fatalf("override subnet %v", g2.Subnet())
	}
	l, err := g2.Join(randKey(), 0)
	if err != nil || l.GatewayIP != netip.MustParseAddr("192.168.250.1") || l.IP != netip.MustParseAddr("192.168.250.2") {
		t.Fatalf("lease %v %v: %v", l.IP, l.GatewayIP, err)
	}
}

func TestJoinValidationAndMTU(t *testing.T) {
	g := startGateway(t, nil)
	if _, err := g.Join([32]byte{}, 0); err != ErrInvalidKey {
		t.Fatalf("zero key: %v", err)
	}
	if _, err := g.Join(g.PublicKey(), 0); err != ErrInvalidKey {
		t.Fatalf("own key: %v", err)
	}
	k := randKey()
	for _, c := range []struct{ hint, want int }{{0, 1280}, {1400, 1280}, {1200, 1200}, {100, 576}} {
		l, err := g.Join(k, c.hint)
		if err != nil || l.MTU != c.want {
			t.Fatalf("hint %d: MTU %d, %v", c.hint, l.MTU, err)
		}
	}
	g.SetLANAccess(true)
	if l, _ := g.Join(k, 0); !l.LANAccess || !g.LANAccess() {
		t.Fatal("LAN access not reported")
	}
}

func TestPoolFull(t *testing.T) {
	g := startGateway(t, nil)
	seen := map[netip.Addr]bool{}
	for i := range poolSize {
		l, err := g.Join(randKey(), 0)
		if err != nil {
			t.Fatalf("join %d: %v", i, err)
		}
		if want := g.Subnet().Addr().As4(); l.IP.As4()[3] != byte(i+2) || seen[l.IP] || l.IP.As4()[2] != want[2] {
			t.Fatalf("join %d got %v", i, l.IP)
		}
		seen[l.IP] = true
	}
	if _, err := g.Join(randKey(), 0); err != ErrPoolFull {
		t.Fatalf("join 254: %v", err)
	}
	if g.ClientCount() != poolSize || len(g.peerKeys()) != poolSize {
		t.Fatalf("count %d peers %d", g.ClientCount(), len(g.peerKeys()))
	}
}

func TestLeaseExpiry(t *testing.T) {
	clk := setFakeClock(t)
	g := startGateway(t, nil)
	a, b := randKey(), randKey()
	la, err := g.Join(a, 0)
	if err != nil {
		t.Fatal(err)
	}
	lb, err := g.Join(b, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := g.Renew(a, [16]byte{}); err != ErrUnknownLease {
		t.Fatalf("Renew with wrong token: %v", err)
	}

	clk.advance(100 * time.Second)
	if _, err := g.Renew(a, la.Token); err != nil {
		t.Fatal(err)
	}
	clk.advance(21 * time.Second) // b: 121 s old; a: renewed 21 s ago
	g.sweep()
	if g.ClientCount() != 1 {
		t.Fatalf("after first sweep: %d clients", g.ClientCount())
	}
	peers := g.peerKeys()
	if !peers[a] || peers[b] {
		t.Fatal("wrong peer removed")
	}
	if _, err := g.Renew(b, lb.Token); err != ErrUnknownLease {
		t.Fatalf("Renew of expired lease: %v", err)
	}
	if err := g.Leave(b, lb.Token); err != ErrUnknownLease {
		t.Fatalf("Leave of expired lease: %v", err)
	}

	// The released address goes to the back of the pool.
	lc, _ := g.Join(randKey(), 0)
	if lc.IP == lb.IP || lc.IP.As4()[3] != 4 {
		t.Fatalf("reused %v too early (b had %v)", lc.IP, lb.IP)
	}

	// Expired but not yet swept: no longer renewable.
	clk.advance(121 * time.Second)
	if _, err := g.Renew(a, la.Token); err != ErrUnknownLease {
		t.Fatalf("Renew of expired, unswept lease: %v", err)
	}
	g.sweep()
	if g.ClientCount() != 0 || len(g.peerKeys()) != 0 {
		t.Fatalf("after second sweep: %d clients, %d peers", g.ClientCount(), len(g.peerKeys()))
	}
}

func TestClose(t *testing.T) {
	g := startGateway(t, nil)
	k := randKey()
	l, err := g.Join(k, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := g.Close(); err != nil {
		t.Fatal(err)
	}
	if err := g.Close(); err != nil {
		t.Fatal("second Close:", err)
	}
	if _, err := g.Join(randKey(), 0); err != ErrClosed {
		t.Fatalf("Join after Close: %v", err)
	}
	if _, err := g.Renew(k, l.Token); err != ErrClosed {
		t.Fatalf("Renew after Close: %v", err)
	}
	if g.ClientCount() != 0 {
		t.Fatal("leases survive Close")
	}
}

type hookRecorder struct {
	mu  sync.Mutex
	ops []string
}

func (h *hookRecorder) fn(ep netip.Addr, add bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	op := "-"
	if add {
		op = "+"
	}
	h.ops = append(h.ops, op+ep.String())
}

func (h *hookRecorder) take() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := h.ops
	h.ops = nil
	return out
}

func TestEndpointHook(t *testing.T) {
	rec := &hookRecorder{}
	g := startGateway(t, func(c *Config) { c.EndpointHook = rec.fn })
	onLink := []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")}
	g.onLink.Store(&onLink)

	a, b, c := randKey(), randKey(), randKey()
	for _, k := range [][32]byte{a, b, c} {
		if _, err := g.Join(k, 0); err != nil {
			t.Fatal(err)
		}
	}
	nat := netip.MustParseAddr("203.0.113.9")
	wait := func(want ...string) {
		t.Helper()
		var got []string
		for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); time.Sleep(5 * time.Millisecond) {
			got = append(got, rec.take()...)
			if len(got) >= len(want) {
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
		got = append(got, rec.take()...)
		if !slices.Equal(got, want) {
			t.Fatalf("hook calls %v, want %v", got, want)
		}
	}

	// Two clients behind one public NAT address share one route; a LAN, an
	// on-link public and a CGNAT endpoint need none.
	g.reconcileEndpoints(map[[32]byte]netip.Addr{a: nat, b: nat, c: netip.MustParseAddr("192.168.1.50")})
	wait("+" + nat.String())
	g.reconcileEndpoints(map[[32]byte]netip.Addr{a: nat, b: nat, c: netip.MustParseAddr("198.51.100.20")})
	g.reconcileEndpoints(map[[32]byte]netip.Addr{a: nat, b: nat, c: netip.MustParseAddr("100.64.1.1")})
	wait()

	// Roaming: a moves; the shared route stays until b leaves too.
	moved := netip.MustParseAddr("192.0.2.200")
	g.reconcileEndpoints(map[[32]byte]netip.Addr{a: moved, b: nat})
	wait("+" + moved.String())
	g.mu.Lock()
	g.removeLocked(g.table.byKey[b]) // as on expiry / Leave
	g.mu.Unlock()
	wait("-" + nat.String())

	// Close removes what is left.
	g.Close()
	wait("-" + moved.String())
}
