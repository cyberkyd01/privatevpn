package tunnel

import (
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

func TestHasCapNetAdmin(t *testing.T) {
	status := "Name:\tprivatevpn\nCapInh:\t0000000000000000\nCapPrm:\t0000000000001000\nCapEff:\t%s\nCapBnd:\t000001ffffffffff\n"
	for eff, want := range map[string]bool{
		"0000000000001000": true,  // CAP_NET_ADMIN only (setcap)
		"000001ffffffffff": true,  // root
		"0000000000000000": false, // unprivileged
		"0000000000000800": false, // CAP_NET_BIND_SERVICE only... (bit 11) not 12
		"zz":               false,
	} {
		if got := hasCapNetAdmin([]byte(strings.Replace(status, "%s", eff, 1))); got != want {
			t.Errorf("CapEff %s: got %v", eff, got)
		}
	}
	if hasCapNetAdmin([]byte("Name:\tx\n")) {
		t.Error("missing CapEff reported as elevated")
	}
}

// The Linux endpoint-exclusion rule must look the endpoint up in the main
// table ahead of the suppress_prefixlength rule (priority 20565), so that
// unmarked control-plane datagrams to an off-LAN gateway leave through the
// physical default route instead of the tunnel.
func TestLinuxEndpointRuleArgs(t *testing.T) {
	ep := netip.MustParseAddr("203.0.113.9")
	got := strings.Join(linuxEndpointRuleArgs("add", ep, "20564"), " ")
	want := "-4 rule add to 203.0.113.9/32 table main priority 20564"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	mapped := netip.MustParseAddr("::ffff:203.0.113.9")
	if d := linuxEndpointRuleArgs("del", mapped, "20564"); d[2] != "del" || d[4] != "203.0.113.9/32" {
		t.Fatalf("mapped address not unmapped: %v", d)
	}
}

func TestResolvConfUsesResolved(t *testing.T) {
	if !resolvConfUsesResolved("../run/systemd/resolve/stub-resolv.conf", nil) {
		t.Error("stub symlink")
	}
	if !resolvConfUsesResolved("", []byte("# managed\nnameserver 127.0.0.53\noptions edns0 trust-ad\n")) {
		t.Error("stub content")
	}
	if resolvConfUsesResolved("/run/NetworkManager/resolv.conf", []byte("nameserver 192.168.1.1\n")) {
		t.Error("NetworkManager file treated as resolved")
	}
	got := string(resolvConfContent([]netip.Addr{netip.MustParseAddr("10.77.42.1")}))
	if !strings.HasPrefix(got, "#") || !strings.HasSuffix(got, "\nnameserver 10.77.42.1\n") {
		t.Errorf("resolv.conf content = %q", got)
	}
}

func TestParseNetworkServices(t *testing.T) {
	out := "An asterisk (*) denotes that a network service is disabled.\nWi-Fi\n*Bluetooth PAN\nUSB 10/100/1000 LAN\nThunderbolt Bridge\n-evil\n\n"
	want := []string{"Wi-Fi", "USB 10/100/1000 LAN", "Thunderbolt Bridge"}
	if got := parseNetworkServices([]byte(out)); !reflect.DeepEqual(got, want) {
		t.Errorf("got %q", got)
	}
}

func TestParseDNSServers(t *testing.T) {
	if s, ok := parseDNSServers([]byte("There aren't any DNS Servers set on Wi-Fi.\n")); !ok || s != nil {
		t.Errorf("empty: %v %v", s, ok)
	}
	if s, ok := parseDNSServers([]byte("192.168.1.1\n2001:db8::53\n")); !ok || !reflect.DeepEqual(s, []string{"192.168.1.1", "2001:db8::53"}) {
		t.Errorf("list: %v %v", s, ok)
	}
	if _, ok := parseDNSServers([]byte("** Error: The parameters were not valid.\n")); ok {
		t.Error("error output accepted")
	}
	if _, ok := parseDNSServers(nil); ok {
		t.Error("no output accepted")
	}
}

func TestParseRouteGetDefault(t *testing.T) {
	out := "   route to: default\ndestination: default\n       mask: default\n    gateway: 192.168.1.1\n  interface: en0\n      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>\n"
	gw, ifn, ok := parseRouteGetDefault([]byte(out))
	if !ok || gw.String() != "192.168.1.1" || ifn != "en0" {
		t.Errorf("got %v %q %v", gw, ifn, ok)
	}
	if _, _, ok := parseRouteGetDefault([]byte("route: writing to routing socket: not in table\n")); ok {
		t.Error("no route accepted")
	}
}

func TestDNSBackup(t *testing.T) {
	b := dnsBackup{Services: []dnsBackupEntry{{Name: "Wi-Fi", Servers: []string{"192.168.1.1"}}, {Name: "USB LAN"}}}
	data, err := encodeDNSBackup(b)
	if err != nil {
		t.Fatal(err)
	}
	back, err := decodeDNSBackup(data)
	if err != nil || back.Version != 1 || len(back.Services) != 2 || back.Services[0].Servers[0] != "192.168.1.1" {
		t.Fatalf("round trip: %+v %v", back, err)
	}
	for _, bad := range []string{
		`{"version":2,"services":[]}`,
		`{"version":1,"services":[{"name":"-x","servers":[]}]}`,
		`{"version":1,"services":[{"name":"Wi-Fi","servers":["; rm -rf /"]}]}`,
		`{"version":1,"services":[{"name":"Wi\nFi","servers":[]}]}`,
		`{"version":1,"services":[],"extra":1}`,
		`not json`,
	} {
		if _, err := decodeDNSBackup([]byte(bad)); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
	if got := setDNSArgs("Wi-Fi", nil); !reflect.DeepEqual(got, []string{"-setdnsservers", "Wi-Fi", "Empty"}) {
		t.Errorf("restore empty: %q", got)
	}
	if got := setDNSArgs("Wi-Fi", []string{"10.77.42.1"}); !reflect.DeepEqual(got, []string{"-setdnsservers", "Wi-Fi", "10.77.42.1"}) {
		t.Errorf("set: %q", got)
	}
}
