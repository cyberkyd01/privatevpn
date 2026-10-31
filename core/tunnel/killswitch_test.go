package tunnel

import (
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

func TestKSStateCodec(t *testing.T) {
	b, err := encodeKSState(netip.MustParseAddr("192.168.1.10"), true)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != `{"version":1,"endpoint":"192.168.1.10","allow_lan":true}` {
		t.Errorf("encoded: %s", b)
	}
	ep, lan, err := decodeKSState(b)
	if err != nil || ep.String() != "192.168.1.10" || !lan {
		t.Fatalf("decode: %v %v %v", ep, lan, err)
	}
	for name, in := range map[string]string{
		"v6":        `{"version":1,"endpoint":"2001:db8::1","allow_lan":true}`,
		"loopback":  `{"version":1,"endpoint":"127.0.0.1","allow_lan":true}`,
		"empty":     `{"version":1,"endpoint":"","allow_lan":true}`,
		"version":   `{"version":2,"endpoint":"192.168.1.10","allow_lan":true}`,
		"extra":     `{"version":1,"endpoint":"192.168.1.10","allow_lan":true,"key":"x"}`,
		"trailing":  `{"version":1,"endpoint":"192.168.1.10","allow_lan":true}{}`,
		"not json":  `nope`,
		"huge":      `{"version":1,"endpoint":"` + strings.Repeat("1", 5000) + `"}`,
		"broadcast": `{"version":1,"endpoint":"255.255.255.255","allow_lan":false}`,
	} {
		if _, _, err := decodeKSState([]byte(in)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if _, err := encodeKSState(netip.MustParseAddr("::ffff:1.2.3.4"), false); err == nil {
		t.Error("4in6 encoded")
	}
}

func TestPFRules(t *testing.T) {
	ep := netip.MustParseAddr("203.0.113.9")
	live := pfRules("utun4", ep, true)
	lines := strings.Split(strings.TrimSpace(live), "\n")
	// First match wins: loopback and the tunnel first, blocks last.
	if !strings.HasPrefix(lines[1], "pass quick on lo0 all") || !strings.HasPrefix(lines[2], "pass quick on utun4 all") {
		t.Errorf("head: %q", lines[:3])
	}
	if lines[len(lines)-2] != "block drop in quick all" || lines[len(lines)-1] != "block return out quick all" {
		t.Errorf("tail: %q", lines[len(lines)-2:])
	}
	for _, want := range []string{
		"pass out quick inet from any to 203.0.113.9 no state",
		"pass in quick inet from 203.0.113.9 to any no state",
		"block return out quick proto { tcp, udp } from any to any port 53",
		"from any port 68 to any port 67",
		"from any port 546 to any port 547",
		"icmp6-type { routersol, routeradv, neighbrsol, neighbradv, redir }",
		"10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, 224.0.0.0/4, 255.255.255.255/32",
		"fe80::/10, ff00::/8",
		"pass in quick inet proto udp from any to 239.255.77.77 no state",
	} {
		if !strings.Contains(live, want) {
			t.Errorf("missing %q in:\n%s", want, live)
		}
	}
	// The DNS block must precede the LAN pass (a LAN router must not resolve).
	if strings.Index(live, "port 53") > strings.Index(live, "10.0.0.0/8") {
		t.Error("DNS block after LAN pass")
	}
	// Every pass rule is stateless.
	for _, l := range lines {
		if strings.HasPrefix(l, "pass") && !strings.HasSuffix(l, "no state") {
			t.Errorf("stateful pass rule: %s", l)
		}
	}
	boot := pfRules("", ep, false)
	if strings.Contains(boot, "utun") || strings.Contains(boot, "10.0.0.0/8") || strings.Contains(boot, "ff00::/8") {
		t.Errorf("boot rules leak tunnel/LAN:\n%s", boot)
	}
	if !strings.Contains(boot, "to 203.0.113.9") {
		t.Error("boot rules do not permit the endpoint")
	}
	if strings.Contains(boot, "100.64.") {
		t.Error("CGNAT treated as LAN")
	}
}

func TestPFParsers(t *testing.T) {
	main := []byte("scrub-anchor \"com.apple/*\" all\nnat-anchor \"com.apple/*\" all\nanchor \"com.apple/*\" all\n")
	if !pfMainHasAppleAnchor(main) || pfMainHasAppleAnchor([]byte("pass all\n")) || pfMainHasAppleAnchor([]byte("anchor \"other/*\" all\n")) {
		t.Error("pfMainHasAppleAnchor")
	}
	if !pfEnabled([]byte("Status: Enabled for 0 days 00:01:02           Debug: Urgent\n")) || pfEnabled([]byte("Status: Disabled\n")) || pfEnabled(nil) {
		t.Error("pfEnabled")
	}
	if !pfAnchorHasRules([]byte("pass quick on lo0 all no state\nblock drop in quick all\n")) || pfAnchorHasRules([]byte("No ALTQ support in kernel\nALTQ related functions disabled\n")) || pfAnchorHasRules(nil) {
		t.Error("pfAnchorHasRules")
	}
}

func TestLaunchdPlistAndSystemdUnit(t *testing.T) {
	p := launchdPlist("app.privatevpn.killswitch", "/Library/Application Support/PrivateVPN/bin/privatevpn")
	for _, want := range []string{"<string>app.privatevpn.killswitch</string>", "<string>/Library/Application Support/PrivateVPN/bin/privatevpn</string>",
		"<string>killswitch-boot</string>", "<key>RunAtLoad</key>\n\t<true/>", "<key>KeepAlive</key>\n\t<false/>"} {
		if !strings.Contains(p, want) {
			t.Errorf("plist lacks %q", want)
		}
	}
	if !strings.Contains(launchdPlist("l", "/a&b<c>"), "<string>/a&amp;b&lt;c&gt;</string>") {
		t.Error("plist path not escaped")
	}
	u := systemdUnit("/var/lib/privatevpn/bin/privatevpn")
	for _, want := range []string{"Before=network-pre.target", "DefaultDependencies=no", "Type=oneshot", "RemainAfterExit=yes",
		`ExecStart="/var/lib/privatevpn/bin/privatevpn" killswitch-boot`, "WantedBy=sysinit.target"} {
		if !strings.Contains(u, want) {
			t.Errorf("unit lacks %q", want)
		}
	}
	if got := systemdQuote(`/a"b\c`); got != `"/a\"b\\c"` {
		t.Errorf("systemdQuote = %s", got)
	}
}

func TestLinuxBlockArgs(t *testing.T) {
	ep, dns := netip.MustParseAddr("192.168.1.10"), netip.MustParseAddr("10.77.42.1")
	v4 := linuxBlockArgs("-4", "20566", ep, dns)
	joined := func(cs []ipCmdArgs) []string {
		var out []string
		for _, c := range cs {
			out = append(out, strings.Join(c.args, " "))
		}
		return out
	}
	want := []string{
		"-4 route add blackhole default table 20566 metric 20566",
		"-4 rule add not fwmark 20566 table 20566 priority 20566",
		"-4 rule add table main suppress_prefixlength 0 priority 20565",
		"-4 rule add to 192.168.1.10/32 table main priority 20564",
		"-4 rule add fwmark 20566 table main priority 20561",
		"-4 rule add to 10.77.42.1/32 table main suppress_prefixlength 0 priority 20562",
		"-4 rule add ipproto udp dport 53 blackhole priority 20563",
		"-4 rule add ipproto tcp dport 53 blackhole priority 20563",
	}
	if got := joined(v4); !reflect.DeepEqual(got, want) {
		t.Errorf("v4:\n got %q\nwant %q", got, want)
	}
	// Only the DNS confinement is optional; the block itself is mandatory.
	for i, c := range v4 {
		if (i < 4) != (c.warn == "") {
			t.Errorf("cmd %d warn=%q", i, c.warn)
		}
	}
	v6 := joined(linuxBlockArgs("-6", "20566", ep, dns))
	for _, l := range v6 {
		if strings.Contains(l, "192.168") || strings.Contains(l, "10.77") || !strings.HasPrefix(l, "-6 ") {
			t.Errorf("v6 line %q", l)
		}
	}
	if len(v6) != 6 {
		t.Errorf("v6: %d commands", len(v6))
	}
	// Boot block: no DNS rule without a resolver.
	boot := joined(linuxBlockArgs("-4", "20566", ep, netip.Addr{}))
	if len(boot) != 7 || strings.Contains(strings.Join(boot, "\n"), "20562") {
		t.Errorf("boot: %q", boot)
	}
	if got := linuxTunnelDefaultArgs("-6", "pvn0"); strings.Join(got, " ") != "-6 route add default dev pvn0 table 20566" {
		t.Errorf("tunnel default: %q", got)
	}
	if got := linuxEndpointRuleArgs("del", netip.MustParseAddr("::ffff:203.0.113.9"), "20564"); strings.Join(got, " ") != "-4 rule del to 203.0.113.9/32 table main priority 20564" {
		t.Errorf("endpoint rule: %q", got)
	}
}

func TestParseIPRules(t *testing.T) {
	out := []byte("0:\tfrom all lookup local\n20562:\tfrom all to 10.77.42.1 lookup main suppress_prefixlength 0\n" +
		"20564:\tfrom all to 192.168.1.10 lookup main\n20564:\tfrom all to 203.0.113.9 lookup main\n20564:\tfrom all to 192.168.1.10 lookup main\n" +
		"20566:\tfrom all fwmark 0x5056 lookup 20566\nnot a rule\n32766:\tfrom all lookup main\n")
	rules := parseIPRules(out)
	if len(rules) != 7 || rules[1] != (ipRule{Prio: 20562, To: "10.77.42.1"}) || rules[5] != (ipRule{Prio: 20566}) {
		t.Errorf("rules: %+v", rules)
	}
	stale := staleHostRules(rules, 20564, netip.MustParseAddr("203.0.113.9"))
	if len(stale) != 1 || stale[0].String() != "192.168.1.10" {
		t.Errorf("stale: %v", stale)
	}
	if n := len(staleHostRules(rules, 20564, netip.Addr{})); n != 2 {
		t.Errorf("all stale: %d", n)
	}
	if !routeShowHasBlackhole([]byte("default dev pvn0 scope link\nblackhole default metric 20566\n")) || routeShowHasBlackhole([]byte("default dev pvn0 scope link\n")) {
		t.Error("routeShowHasBlackhole")
	}
}

func TestCmdErrorClassifiers(t *testing.T) {
	exists := &cmdError{label: "ip rule", err: errors.New("exit status 2"), detail: "RTNETLINK answers: File exists"}
	missing := &cmdError{label: "ip rule", err: errors.New("exit status 2"), detail: "RTNETLINK answers: No such file or directory"}
	if !isExistsErr(exists) || isExistsErr(missing) || isExistsErr(errors.New("File exists")) {
		t.Error("isExistsErr")
	}
	if !isMissingErr(missing) || isMissingErr(exists) || !isMissingErr(&cmdError{detail: "route: not in table", err: errors.New("x")}) {
		t.Error("isMissingErr")
	}
	ws := addWarning(nil, WarnDNSNotSet)
	ws = addWarning(ws, WarnDNSNotSet)
	ws = addWarning(ws, WarnIPv6NotBlocked)
	if !reflect.DeepEqual(ws, []string{WarnDNSNotSet, WarnIPv6NotBlocked}) {
		t.Errorf("addWarning: %v", ws)
	}
}
