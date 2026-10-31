package tunnel

import (
	"net/netip"
	"testing"
)

func countBy(fs []wfpFilter, pred func(wfpFilter) bool) int {
	n := 0
	for _, f := range fs {
		if pred(f) {
			n++
		}
	}
	return n
}

func hasCond(f wfpFilter, field wfpField, kind wfpKind) bool {
	for _, c := range f.Conds {
		if c.Field == field && c.Kind == kind {
			return true
		}
	}
	return false
}

func TestWFPFilterKeys(t *testing.T) {
	seen := map[wfpGUID]bool{wfpProviderKey: true, wfpSublayerKey: true}
	for i := 0; i < wfpMaxFilters; i++ {
		k := wfpFilterKey(i)
		if seen[k] {
			t.Fatalf("key %d collides", i)
		}
		seen[k] = true
	}
	if wfpFilterKey(3) != wfpFilterKey(3) {
		t.Error("keys are not deterministic")
	}
}

func TestWFPKillSwitchPlan(t *testing.T) {
	spec := wfpSpec{KillSwitch: true, TunnelLUID: 0x1234, Endpoint: netip.MustParseAddr("192.168.1.10"),
		DNS: []netip.Addr{netip.MustParseAddr("10.77.42.1")}, AllowLAN: true}
	fs := buildWFPFilters(spec)
	if len(fs) > wfpMaxFilters {
		t.Fatalf("%d filters exceed the key range", len(fs))
	}
	// Blocks: 4 catch-all at the lowest weight, 4 DNS blocks above every
	// permit except the app and the tunnel-resolver permits.
	blocks := countBy(fs, func(f wfpFilter) bool { return !f.Permit && len(f.Conds) == 0 })
	if blocks != 4 {
		t.Errorf("catch-all blocks = %d", blocks)
	}
	for _, f := range fs {
		switch {
		case !f.Permit && len(f.Conds) == 0 && f.Weight != wfpWeightBlock:
			t.Errorf("catch-all block at weight %d", f.Weight)
		case !f.Permit && len(f.Conds) > 0 && f.Weight != wfpWeightDNSBlock:
			t.Errorf("DNS block at weight %d", f.Weight)
		case f.Permit && f.Weight <= wfpWeightBlock:
			t.Errorf("permit %q not above the block", f.Name)
		case f.Permit && f.Weight > wfpWeightDNSBlock && !(hasCond(f, wfpFieldAppID, wfpAppID) || hasCond(f, wfpFieldRemotePort, wfpU16) && hasCond(f, wfpFieldRemoteAddr, wfpU32)):
			t.Errorf("permit %q outranks the DNS block", f.Name)
		}
	}
	// The LAN permit must not outrank the DNS block (a LAN router must not
	// resolve names), and must be below the specific permits.
	lan := countBy(fs, func(f wfpFilter) bool { return f.Weight == wfpWeightLAN })
	if lan != 4 {
		t.Errorf("LAN filters = %d", lan)
	}
	// Exactly the expected special cases.
	if n := countBy(fs, func(f wfpFilter) bool { return hasCond(f, wfpFieldLocalInterface, wfpU64) }); n != 4 {
		t.Errorf("tunnel permits = %d", n)
	}
	if n := countBy(fs, func(f wfpFilter) bool { return hasCond(f, wfpFieldAppID, wfpAppID) && len(f.Conds) == 1 }); n != 4 {
		t.Errorf("app permits = %d", n)
	}
	ep := countBy(fs, func(f wfpFilter) bool {
		return f.Permit && len(f.Conds) == 1 && f.Conds[0].Field == wfpFieldRemoteAddr && f.Conds[0].Kind == wfpU32 && f.Conds[0].Num == 0xC0A8010A
	})
	if ep != 2 {
		t.Errorf("endpoint permits = %d", ep)
	}
	if n := countBy(fs, func(f wfpFilter) bool { return hasCond(f, wfpFieldFlags, wfpFlagsAllSet) }); n != 4 {
		t.Errorf("loopback permits = %d", n)
	}
	if n := countBy(fs, func(f wfpFilter) bool { return hasCond(f, wfpFieldICMPType, wfpU16) }); n != 7 {
		t.Errorf("NDP permits = %d", n)
	}
	// Deterministic.
	again := buildWFPFilters(spec)
	if len(again) != len(fs) {
		t.Fatal("plan size changed")
	}
	for i := range fs {
		if fs[i].Name != again[i].Name || fs[i].Layer != again[i].Layer || len(fs[i].Conds) != len(again[i].Conds) {
			t.Fatalf("plan differs at %d", i)
		}
	}
	// Without LAN, no RFC1918 permit; boot block (no LUID) has no interface
	// permit but still the endpoint.
	noLAN := buildWFPFilters(wfpSpec{KillSwitch: true, TunnelLUID: 1, Endpoint: spec.Endpoint, AllowLAN: false})
	if countBy(noLAN, func(f wfpFilter) bool { return f.Weight == wfpWeightLAN }) != 0 {
		t.Error("LAN permitted without AllowLAN")
	}
	boot := buildWFPFilters(wfpSpec{KillSwitch: true, Endpoint: spec.Endpoint, AllowLAN: true})
	if countBy(boot, func(f wfpFilter) bool { return hasCond(f, wfpFieldLocalInterface, wfpU64) }) != 0 {
		t.Error("boot plan permits a tunnel interface")
	}
	for _, f := range boot {
		if f.Permit && len(f.Conds) == 1 && f.Conds[0].Kind == wfpU32 && f.Conds[0].Num == 0xC0A8010A {
			return
		}
	}
	t.Error("boot plan does not permit the endpoint")
}

func TestWFPDNSOnlyPlan(t *testing.T) {
	fs := buildWFPFilters(wfpSpec{DNS: []netip.Addr{netip.MustParseAddr("10.77.42.1"), netip.MustParseAddr("fd00::1")}})
	if len(fs) != 10 {
		t.Fatalf("DNS-only plan has %d filters, want 10", len(fs))
	}
	for _, f := range fs {
		if !hasCond(f, wfpFieldRemotePort, wfpU16) || !hasCond(f, wfpFieldProtocol, wfpU8) {
			t.Errorf("%q is not scoped to DNS", f.Name)
		}
		if !f.Permit && f.Weight >= wfpWeightDNSPermit {
			t.Errorf("block %q outranks the permits", f.Name)
		}
	}
	// No resolver: nothing permitted except our own process.
	none := buildWFPFilters(wfpSpec{})
	if len(none) != 8 {
		t.Errorf("no-resolver plan has %d filters", len(none))
	}
}

func TestWFPCondHelpers(t *testing.T) {
	if c := condV4(wfpFieldRemoteAddr, netip.MustParsePrefix("10.1.2.3/8")); c.Kind != wfpV4Net || c.Prefix.String() != "10.0.0.0/8" {
		t.Errorf("v4 net: %+v", c)
	}
	if c := condV4(wfpFieldRemoteAddr, netip.MustParsePrefix("1.2.3.4/32")); c.Kind != wfpU32 || c.Num != 0x01020304 {
		t.Errorf("v4 host: %+v", c)
	}
	if c := condV6(wfpFieldRemoteAddr, netip.MustParsePrefix("fe80::1/10")); c.Kind != wfpV6Net || c.Prefix.String() != "fe80::/10" {
		t.Errorf("v6 net: %+v", c)
	}
	if c := condV6(wfpFieldRemoteAddr, netip.MustParsePrefix("ff02::1:2/128")); c.Kind != wfpV6Addr {
		t.Errorf("v6 host: %+v", c)
	}
}
