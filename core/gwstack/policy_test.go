package gwstack

import (
	"net/netip"
	"testing"
)

func TestPolicy(t *testing.T) {
	gw := netip.MustParseAddr("10.77.42.1")
	p := NewPolicy(gw, netip.MustParsePrefix("10.77.42.1/24"))
	p.SetExtraDeny([]netip.Prefix{
		netip.MustParsePrefix("192.168.1.20/32"), // host LAN address
		netip.MustParsePrefix("203.0.113.7/32"),  // host public address
		netip.MustParsePrefix("10.77.9.0/24"),    // dual-role client-tunnel subnet
	})
	ap := netip.MustParseAddrPort
	cases := []struct {
		dst      string
		lanOff   Verdict
		lanOn    Verdict
		comments string
	}{
		{"10.77.42.1:53", LocalDNS, LocalDNS, "DNS forwarder"},
		{"10.77.42.1:80", Deny, Deny, "gateway, other port"},
		{"10.77.42.1:0", Deny, Deny, "gateway port 0"},
		{"10.77.42.7:22", Deny, Deny, "another client"},
		{"10.77.42.255:53", Deny, Deny, "subnet broadcast"},
		{"10.77.9.1:53", Deny, Deny, "upstream gateway (dual role)"},
		{"10.77.9.2:443", Deny, Deny, "own client tunnel (dual role)"},
		{"0.0.0.0:80", Deny, Deny, "this network"},
		{"0.1.2.3:80", Deny, Deny, "this network"},
		{"127.0.0.1:47771", Deny, Deny, "loopback web UI"},
		{"127.1.2.3:80", Deny, Deny, "loopback"},
		{"169.254.169.254:80", Deny, Deny, "cloud metadata"},
		{"169.254.10.10:80", Deny, Deny, "link-local"},
		{"224.0.0.251:5353", Deny, Deny, "mDNS multicast"},
		{"239.255.77.77:51822", Deny, Deny, "beacon multicast"},
		{"240.0.0.1:80", Deny, Deny, "reserved"},
		{"255.255.255.255:67", Deny, Deny, "limited broadcast"},
		{"192.168.1.20:80", Deny, Deny, "host LAN address"},
		{"203.0.113.7:443", Deny, Deny, "host public address"},
		{"93.184.216.34:0", Deny, Deny, "port 0"},
		{"192.168.1.1:80", Deny, Forward, "LAN router"},
		{"10.0.0.5:445", Deny, Forward, "10/8"},
		{"172.16.0.1:80", Deny, Forward, "172.16/12 low"},
		{"172.31.255.254:80", Deny, Forward, "172.16/12 high"},
		{"100.64.0.1:80", Deny, Forward, "CGNAT"},
		{"172.32.0.1:80", Forward, Forward, "just outside 172.16/12"},
		{"93.184.216.34:443", Forward, Forward, "Internet"},
		{"1.1.1.1:53", Forward, Forward, "public resolver"},
		{"8.8.8.8:853", Forward, Forward, "DoT"},
	}
	for _, c := range cases {
		p.SetLANAccess(false)
		if got := p.Check(ap(c.dst)); got != c.lanOff {
			t.Errorf("%s (%s) lan=off: got %v want %v", c.dst, c.comments, got, c.lanOff)
		}
		p.SetLANAccess(true)
		if got := p.Check(ap(c.dst)); got != c.lanOn {
			t.Errorf("%s (%s) lan=on: got %v want %v", c.dst, c.comments, got, c.lanOn)
		}
	}
	if p.Check(netip.AddrPortFrom(netip.MustParseAddr("2606:4700::1111"), 443)) != Deny {
		t.Error("IPv6 destination not denied")
	}

	// ICMP: echo to the gateway only.
	if !p.AllowICMP(gw) {
		t.Error("ICMP to gateway denied")
	}
	for _, a := range []string{"10.77.42.7", "8.8.8.8", "192.168.1.1", "127.0.0.1"} {
		if p.AllowICMP(netip.MustParseAddr(a)) {
			t.Errorf("ICMP to %s allowed", a)
		}
	}

	// ExtraDeny is replaced, not appended (RefreshPolicy).
	p.SetLANAccess(false)
	p.SetExtraDeny(nil)
	if p.Check(ap("203.0.113.7:443")) != Forward {
		t.Error("stale extra deny entry")
	}
}

func TestRedirectOnlyInTests(t *testing.T) {
	// testing.Testing() is true here, so the redirect is installed; the same
	// guard keeps production binaries from ever using it.
	to := netip.MustParseAddrPort("127.0.0.1:8080")
	d, err := New(Config{Prefix: netip.MustParsePrefix("10.77.1.1/24"), MTU: 1280, Limits: testLimits(),
		RedirectForTesting: func(netip.AddrPort) netip.AddrPort { return to }})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if got := d.target(netip.MustParseAddrPort("192.0.2.1:80")); got != to.String() {
		t.Fatalf("target = %s", got)
	}
	d2, err := New(Config{Prefix: netip.MustParsePrefix("10.77.1.1/24"), MTU: 1280, Limits: testLimits()})
	if err != nil {
		t.Fatal(err)
	}
	defer d2.Close()
	if got := d2.target(netip.MustParseAddrPort("192.0.2.1:80")); got != "192.0.2.1:80" {
		t.Fatalf("target without redirect = %s", got)
	}
}
