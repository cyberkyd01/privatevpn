package tunnel

import (
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func testConfig() Config {
	var c Config
	for i := range c.PrivateKey {
		c.PrivateKey[i] = byte(i + 1)
		c.Peer.PublicKey[i] = byte(0x40 + i)
		c.Peer.PresharedKey[i] = byte(0x80 + i)
	}
	c.PrivateKey[0] &= 248 // a clamped Curve25519 key reads back unchanged
	c.PrivateKey[31] = c.PrivateKey[31]&127 | 64
	c.Address = netip.MustParsePrefix("10.77.42.2/24")
	c.DNS = []netip.Addr{netip.MustParseAddr("10.77.42.1")}
	c.MTU = 1280
	c.Peer.Endpoint = netip.MustParseAddrPort("192.168.1.10:51820")
	c.Peer.Keepalive = 25
	c.SinkIPv6 = true
	c.FwMark = 20566
	return c
}

func TestValidate(t *testing.T) {
	if err := testConfig().Validate(); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	bad := map[string]func(*Config){
		"no private key":   func(c *Config) { c.PrivateKey = [32]byte{} },
		"no peer key":      func(c *Config) { c.Peer.PublicKey = [32]byte{} },
		"v6 address":       func(c *Config) { c.Address = netip.MustParsePrefix("fd00::2/64") },
		"/31":              func(c *Config) { c.Address = netip.MustParsePrefix("10.77.42.2/31") },
		"network addr":     func(c *Config) { c.Address = netip.MustParsePrefix("10.77.42.0/24") },
		"broadcast addr":   func(c *Config) { c.Address = netip.MustParsePrefix("10.77.42.255/24") },
		"v6 dns":           func(c *Config) { c.DNS = []netip.Addr{netip.MustParseAddr("fd00::1")} },
		"5 dns":            func(c *Config) { c.DNS = make([]netip.Addr, 5) },
		"mtu low":          func(c *Config) { c.MTU = 500 },
		"mtu high":         func(c *Config) { c.MTU = 1500 },
		"v6 endpoint":      func(c *Config) { c.Peer.Endpoint = netip.MustParseAddrPort("[2001:db8::1]:51820") },
		"4in6 endpoint":    func(c *Config) { c.Peer.Endpoint = netip.MustParseAddrPort("[::ffff:192.168.1.10]:51820") },
		"port 0":           func(c *Config) { c.Peer.Endpoint = netip.MustParseAddrPort("192.168.1.10:0") },
		"loopback ep":      func(c *Config) { c.Peer.Endpoint = netip.MustParseAddrPort("127.0.0.1:51820") },
		"broadcast ep":     func(c *Config) { c.Peer.Endpoint = netip.MustParseAddrPort("255.255.255.255:51820") },
		"keepalive range":  func(c *Config) { c.Peer.Keepalive = 601 },
		"negative keepal.": func(c *Config) { c.Peer.Keepalive = -1 },
	}
	for name, mut := range bad {
		c := testConfig()
		mut(&c)
		err := c.Validate()
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		// Errors must never echo addresses.
		for _, v := range []string{"192.168", "10.77", "fd00", "2001:", "127.0", "255.255", ":51820"} {
			if strings.Contains(err.Error(), v) {
				t.Errorf("%s: error leaks a value: %q", name, err)
			}
		}
	}
}

func TestCheckPublicIPv4(t *testing.T) {
	ok := []string{"203.0.113.9", "8.8.8.8", "1.1.1.1", "100.64.0.1", "198.51.100.200"}
	bad := []string{"10.0.0.1", "172.16.5.4", "192.168.1.1", "127.0.0.1", "169.254.1.1", "224.0.0.1",
		"255.255.255.255", "0.0.0.0", "0.1.2.3", "240.0.0.1", "::1", "2001:db8::1", "::ffff:8.8.8.8"}
	for _, s := range ok {
		if err := CheckPublicIPv4(netip.MustParseAddr(s)); err != nil {
			t.Errorf("%s rejected", s)
		}
	}
	for _, s := range bad {
		if err := CheckPublicIPv4(netip.MustParseAddr(s)); err == nil {
			t.Errorf("%s accepted", s)
		}
	}
	if CheckPublicIPv4(netip.Addr{}) == nil {
		t.Error("zero addr accepted")
	}
}

func TestAddrHelpers(t *testing.T) {
	p := netip.MustParsePrefix("10.77.42.2/24")
	if got := peerTunnelAddr(p); got.String() != "10.77.42.1" {
		t.Errorf("peerTunnelAddr = %s", got)
	}
	if got := peerTunnelAddr(netip.MustParsePrefix("10.77.42.1/24")); got.String() != "10.77.42.2" {
		t.Errorf("peerTunnelAddr(.1) = %s", got)
	}
	if got := lastAddr(p); got.String() != "10.77.42.255" {
		t.Errorf("lastAddr = %s", got)
	}
	for bits, want := range map[int]string{0: "0.0.0.0", 1: "128.0.0.0", 24: "255.255.255.0", 30: "255.255.255.252", 32: "255.255.255.255"} {
		if got := netmask4(bits); got != want {
			t.Errorf("netmask4(%d) = %s, want %s", bits, got, want)
		}
	}
}

func TestUAPIConfig(t *testing.T) {
	c := testConfig()
	k := func(b [32]byte) string { return hex.EncodeToString(b[:]) }
	want := "private_key=" + k(c.PrivateKey) + "\n" +
		"listen_port=0\n" +
		"fwmark=20566\n" +
		"replace_peers=true\n" +
		"public_key=" + k(c.Peer.PublicKey) + "\n" +
		"preshared_key=" + k(c.Peer.PresharedKey) + "\n" +
		"endpoint=192.168.1.10:51820\n" +
		"persistent_keepalive_interval=25\n" +
		"replace_allowed_ips=true\n" +
		"allowed_ip=0.0.0.0/0\n"
	if got := uapiConfig(c, 20566); got != want {
		t.Errorf("uapiConfig:\n%s\nwant:\n%s", got, want)
	}
	if got := uapiConfig(c, 0); strings.Contains(got, "fwmark") {
		t.Errorf("fwmark emitted without a mark:\n%s", got)
	}
	ep := uapiEndpoint(c.Peer.PublicKey, netip.MustParseAddrPort("203.0.113.9:4000"))
	if ep != "public_key="+k(c.Peer.PublicKey)+"\nupdate_only=true\nendpoint=203.0.113.9:4000\n" {
		t.Errorf("uapiEndpoint = %q", ep)
	}
}

func TestParseUAPIStatus(t *testing.T) {
	var peer, other [32]byte
	peer[0], other[0] = 1, 2
	now := time.Unix(1_761_900_100, 0)
	get := "private_key=" + strings.Repeat("ab", 32) + "\nlisten_port=40000\n" +
		"public_key=" + hex.EncodeToString(other[:]) + "\nlast_handshake_time_sec=1761900000\nrx_bytes=999\ntx_bytes=999\n" +
		"public_key=" + hex.EncodeToString(peer[:]) + "\nprotocol_version=1\nendpoint=192.168.1.10:51820\n" +
		"last_handshake_time_sec=1761900088\nlast_handshake_time_nsec=5\ntx_bytes=456\nrx_bytes=123\n" +
		"persistent_keepalive_interval=25\nallowed_ip=0.0.0.0/0\n"
	st := parseUAPIStatus(get, peer, now)
	if st.HandshakeAgeSec != 12 || st.RxBytes != 123 || st.TxBytes != 456 {
		t.Errorf("status = %+v", st)
	}
	fresh := parseUAPIStatus("public_key="+hex.EncodeToString(peer[:])+"\nlast_handshake_time_sec=0\nrx_bytes=0\n", peer, now)
	if fresh.HandshakeAgeSec != -1 {
		t.Errorf("no handshake: age = %d, want -1", fresh.HandshakeAgeSec)
	}
	if st := parseUAPIStatus("", peer, now); st.HandshakeAgeSec != -1 {
		t.Errorf("empty: %+v", st)
	}
}

func TestConfigJSONRoundTrip(t *testing.T) {
	c := testConfig()
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	var back Config
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if uapiConfig(back, 20566) != uapiConfig(c, 20566) || back.Validate() != nil {
		t.Error("config changed across the JSON codec")
	}
	if s := (Config{}).String(); strings.Contains(s, "10.77") {
		t.Errorf("String leaks: %s", s)
	}
}

func TestRedact(t *testing.T) {
	cases := map[string]string{
		"peer(AbCd…xyz0) - Handshake did not complete after 5 seconds, retrying (try 2)":            "peer - Handshake did not complete after 5 seconds, retrying (try 2)",
		"write udp4 0.0.0.0:41000->192.168.1.10:51820: sendto: network is unreachable":              "write udp4 <addr>-><addr>: sendto: network is unreachable",
		"dial [2001:db8::1]:51820 failed":                                                           "dial <addr> failed",
		"route to fe80::1%en0 gone":                                                                 "route to <addr> gone",
		"key " + strings.Repeat("A", 43) + "= leaked":                                               "key <key> leaked",
		"hex " + strings.Repeat("0f", 32) + " leaked":                                               "hex <key> leaked",
		"Failed to send handshake initiation: no known endpoint for peer":                           "Failed to send handshake initiation: no known endpoint for peer",
		"Interface state was Down, requested Up, now Up":                                            "Interface state was Down, requested Up, now Up",
		"UDP bind has been updated":                                                                 "UDP bind has been updated",
		"route: writing to routing socket: File exists (add host 203.0.113.9: gateway 192.168.1.1)": "route: writing to routing socket: File exists (add host <addr>: gateway <addr>)",
	}
	for in, want := range cases {
		if got := Redact(in); got != want {
			t.Errorf("Redact(%q)\n got %q\nwant %q", in, got, want)
		}
	}
}

func TestDebouncer(t *testing.T) {
	var n atomic.Int32
	d := newDebouncer(30*time.Millisecond, func() { n.Add(1) })
	for i := 0; i < 10; i++ {
		d.kick()
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(100 * time.Millisecond)
	if got := n.Load(); got != 1 {
		t.Fatalf("burst ran %d times, want 1", got)
	}
	d.kick()
	d.stop()
	d.kick()
	time.Sleep(80 * time.Millisecond)
	if got := n.Load(); got != 1 {
		t.Fatalf("ran after stop: %d", got)
	}
}
