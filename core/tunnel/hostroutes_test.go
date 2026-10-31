package tunnel

import (
	"errors"
	"net/netip"
	"reflect"
	"testing"
)

func pfx(s string) netip.Prefix  { return netip.MustParsePrefix(s) }
func addr(s string) netip.Addr   { return netip.MustParseAddr(s) }
func gwOf(s string) netip.Addr   { return netip.MustParseAddr(s) }
func noGW() netip.Addr           { return netip.Addr{} }
func onLink(s string) netip.Addr { return netip.MustParseAddr(s) } // "0.0.0.0" next hop (Windows on-link)

// A typical Windows-like table: Wi-Fi (luid 7, metric 25+35) and Ethernet
// (luid 3, metric 0+25) both have defaults; Ethernet wins.
func fakeTable() []rtEntry {
	return []rtEntry{
		{Dst: pfx("0.0.0.0/0"), Gateway: gwOf("192.168.1.1"), IfIndex: 7, Metric: 60},
		{Dst: pfx("0.0.0.0/0"), Gateway: gwOf("10.0.0.1"), IfIndex: 3, Metric: 25},
		{Dst: pfx("192.168.1.0/24"), Gateway: onLink("0.0.0.0"), IfIndex: 7, Metric: 281},
		{Dst: pfx("10.0.0.0/24"), Gateway: onLink("0.0.0.0"), IfIndex: 3, Metric: 281},
		{Dst: pfx("172.20.0.0/16"), Gateway: gwOf("10.0.0.254"), IfIndex: 3, Metric: 30},
	}
}

func TestBestRoute(t *testing.T) {
	tab := fakeTable()
	cases := map[string]struct {
		ifIndex uint64
		bits    int
	}{
		"203.0.113.9":  {3, 0},  // public → lowest-metric default
		"192.168.1.10": {7, 24}, // LAN on Wi-Fi
		"10.0.0.5":     {3, 24},
		"172.20.9.9":   {3, 16}, // corporate route
	}
	for dst, want := range cases {
		r, ok := bestRoute(tab, addr(dst))
		if !ok || r.IfIndex != want.ifIndex || r.Dst.Bits() != want.bits {
			t.Errorf("%s: got %+v ok=%v", dst, r, ok)
		}
	}
	if _, ok := bestRoute(nil, addr("1.1.1.1")); ok {
		t.Error("empty table matched")
	}
}

func TestExclusionFor(t *testing.T) {
	tab := fakeTable()
	r, need, err := exclusionFor(tab, addr("203.0.113.9"))
	if err != nil || !need || r != (hostRoute{Dst: addr("203.0.113.9"), Gateway: gwOf("10.0.0.1"), IfIndex: 3}) {
		t.Errorf("public endpoint: %+v need=%v err=%v", r, need, err)
	}
	if _, need, err := exclusionFor(tab, addr("192.168.1.10")); err != nil || need {
		t.Errorf("LAN endpoint must not need a /32 (need=%v err=%v)", need, err)
	}
	if _, need, _ := exclusionFor(tab, addr("172.20.1.1")); need {
		t.Error("corporate /16 covers it: no /32 needed")
	}
	// On-link default (PPP, Windows next hop 0.0.0.0): interface route.
	ppp := []rtEntry{{Dst: pfx("0.0.0.0/0"), Gateway: onLink("0.0.0.0"), IfIndex: 9, IfName: "ppp0"}}
	r, need, err = exclusionFor(ppp, addr("8.8.8.8"))
	if err != nil || !need || r.Gateway.IsValid() || r.IfIndex != 9 || r.IfName != "ppp0" {
		t.Errorf("interface default: %+v need=%v err=%v", r, need, err)
	}
	// Another /1 (e.g. another VPN) does not shadow our /1 routes.
	other := append(fakeTable(), rtEntry{Dst: pfx("0.0.0.0/1"), Gateway: gwOf("10.0.0.1"), IfIndex: 3})
	if _, need, _ := exclusionFor(other, addr("8.8.8.8")); !need {
		t.Error("a /1 route must still get an exclusion")
	}
	if _, _, err := exclusionFor([]rtEntry{{Dst: pfx("192.168.1.0/24"), IfIndex: 7}}, addr("8.8.8.8")); !errors.Is(err, errNoPhysicalRoute) {
		t.Errorf("offline: err=%v", err)
	}
}

func TestPlanHostRoutes(t *testing.T) {
	tab := fakeTable()
	ep := addr("203.0.113.9")
	lanEP := addr("192.168.1.10")
	viaEth := func(a string) hostRoute { return hostRoute{Dst: addr(a), Gateway: gwOf("10.0.0.1"), IfIndex: 3} }
	viaWiFi := func(a string) hostRoute { return hostRoute{Dst: addr(a), Gateway: gwOf("192.168.1.1"), IfIndex: 7} }

	add, del, unr := planHostRoutes(tab, []netip.Addr{ep, addr("198.51.100.7"), ep}, map[netip.Addr]hostRoute{})
	if !reflect.DeepEqual(add, []hostRoute{viaEth("198.51.100.7"), viaEth("203.0.113.9")}) || len(del) != 0 || len(unr) != 0 {
		t.Errorf("fresh: add=%v del=%v unr=%v", add, del, unr)
	}

	// Steady state: nothing to do.
	inst := map[netip.Addr]hostRoute{ep: viaEth("203.0.113.9")}
	if add, del, _ := planHostRoutes(tab, []netip.Addr{ep}, inst); len(add)+len(del) != 0 {
		t.Errorf("steady: add=%v del=%v", add, del)
	}

	// Ethernet unplugged: the default moves to Wi-Fi → re-point.
	wifiOnly := []rtEntry{tab[0], tab[2]}
	add, del, _ = planHostRoutes(wifiOnly, []netip.Addr{ep}, inst)
	if !reflect.DeepEqual(add, []hostRoute{viaWiFi("203.0.113.9")}) || !reflect.DeepEqual(del, []hostRoute{viaEth("203.0.113.9")}) {
		t.Errorf("gateway change: add=%v del=%v", add, del)
	}

	// Endpoint roamed onto the LAN: old /32 removed, none added.
	add, del, _ = planHostRoutes(tab, []netip.Addr{lanEP}, inst)
	if len(add) != 0 || !reflect.DeepEqual(del, []hostRoute{viaEth("203.0.113.9")}) {
		t.Errorf("roam to LAN: add=%v del=%v", add, del)
	}

	// Offline: keep what is installed, report unreachable.
	add, del, unr = planHostRoutes(nil, []netip.Addr{ep}, inst)
	if len(add)+len(del) != 0 || !reflect.DeepEqual(unr, []netip.Addr{ep}) {
		t.Errorf("offline: add=%v del=%v unr=%v", add, del, unr)
	}

	// Tunnel down: everything goes.
	add, del, _ = planHostRoutes(nil, nil, inst)
	if len(add) != 0 || len(del) != 1 {
		t.Errorf("down: add=%v del=%v", add, del)
	}
}

type fakeOps struct {
	tab     []rtEntry
	tabErr  error
	live    map[netip.Addr]hostRoute
	failAdd map[netip.Addr]bool
	adds    int
	dels    int
}

func (f *fakeOps) table() ([]rtEntry, error) { return f.tab, f.tabErr }
func (f *fakeOps) add(r hostRoute) error {
	if f.failAdd[r.Dst] {
		return errors.New("add failed")
	}
	f.adds++
	f.live[r.Dst] = r
	return nil
}
func (f *fakeOps) del(r hostRoute) error {
	f.dels++
	delete(f.live, r.Dst)
	return nil
}

func TestHostRoutesLifecycle(t *testing.T) {
	ops := &fakeOps{tab: fakeTable(), live: map[netip.Addr]hostRoute{}, failAdd: map[netip.Addr]bool{}}
	h := newHostRoutes(ops)
	client := addr("198.51.100.7")

	// Dual-role host added while down: remembered, nothing installed.
	if err := h.addHost(client); err != nil || len(ops.live) != 0 || h.endpointOK() {
		t.Fatalf("addHost while down: err=%v live=%v", err, ops.live)
	}
	if err := h.start(addr("203.0.113.9")); err != nil || len(ops.live) != 2 || !h.endpointOK() {
		t.Fatalf("start: err=%v live=%v ok=%v", err, ops.live, h.endpointOK())
	}
	// Roam to a LAN endpoint: its /32 disappears, the client's stays.
	if err := h.setEndpoint(addr("192.168.1.10")); err != nil || len(ops.live) != 1 || !h.endpointOK() {
		t.Fatalf("roam: err=%v live=%v", err, ops.live)
	}
	if err := h.delHost(client); err != nil || len(ops.live) != 0 {
		t.Fatalf("delHost: err=%v live=%v", err, ops.live)
	}
	// Failed add: endpoint not OK, error reported without addresses.
	ops.failAdd[addr("203.0.113.9")] = true
	err := h.setEndpoint(addr("203.0.113.9"))
	if err == nil || h.endpointOK() {
		t.Fatalf("failed add: err=%v ok=%v", err, h.endpointOK())
	}
	delete(ops.failAdd, addr("203.0.113.9"))
	if err := h.reconcile(); err != nil || !h.endpointOK() {
		t.Fatalf("retry: err=%v ok=%v", err, h.endpointOK())
	}
	// Route table unreadable.
	ops.tabErr = errors.New("table")
	if err := h.reconcile(); err == nil || h.endpointOK() {
		t.Fatal("table error not reported")
	}
	ops.tabErr = nil
	// Offline: endpoint not OK.
	ops.tab = []rtEntry{{Dst: pfx("192.168.1.0/24"), IfIndex: 7}}
	if err := h.reconcile(); !errors.Is(err, errNoPhysicalRoute) || h.endpointOK() {
		t.Fatalf("offline: err=%v", err)
	}
	ops.tab = fakeTable()
	if err := h.stop(); err != nil || len(ops.live) != 0 || h.endpointOK() {
		t.Fatalf("stop: err=%v live=%v", err, ops.live)
	}
	// Hosts survive a stop for the next start.
	_ = h.addHost(client)
	_ = h.start(addr("203.0.113.9"))
	if len(ops.live) != 2 {
		t.Fatalf("restart: live=%v", ops.live)
	}
	_ = h.stop()
}

func TestHostRoutesCap(t *testing.T) {
	h := newHostRoutes(&fakeOps{live: map[netip.Addr]hostRoute{}})
	for i := 0; i < MaxHostRoutes; i++ {
		a := netip.AddrFrom4([4]byte{8, byte(i >> 16), byte(i >> 8), byte(i)})
		if err := h.addHost(a); err != nil {
			t.Fatal(err)
		}
	}
	if err := h.addHost(addr("9.9.9.9")); !errors.Is(err, errTooManyHost) {
		t.Fatalf("cap not enforced: %v", err)
	}
	if err := h.addHost(addr("8.0.0.0")); err != nil {
		t.Fatalf("re-adding a known host must succeed: %v", err)
	}
}
