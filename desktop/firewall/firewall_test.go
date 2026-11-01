//go:build !android

package firewall

import (
	"strings"
	"testing"
)

func TestNetshArgs(t *testing.T) {
	exe := `C:\Program Files\Private VPN Pro\private-vpn-pro.exe`
	rules := addArgs(exe)
	if len(rules) != 2 {
		t.Fatalf("want 2 rules, got %d", len(rules))
	}
	got := strings.Join(rules[0], "|")
	want := `advfirewall|firewall|add|rule|name=Private VPN Pro|dir=in|action=allow|program=C:\Program Files\Private VPN Pro\private-vpn-pro.exe|protocol=UDP|profile=private,domain|enable=yes`
	if got != want {
		t.Errorf("add args\n got %s\nwant %s", got, want)
	}
	pub := strings.Join(rules[1], "|")
	if !strings.Contains(pub, "profile=public") || !strings.Contains(pub, "remoteip=localsubnet") ||
		!strings.Contains(pub, "program=") || !strings.Contains(pub, "protocol=UDP") {
		t.Errorf("public rule must be program-scoped UDP limited to the local subnet: %s", pub)
	}
	if got := strings.Join(deleteArgs(RuleName), " "); got != "advfirewall firewall delete rule name=Private VPN Pro" {
		t.Error(got)
	}
	if got := strings.Join(showArgs(RuleName), " "); got != "advfirewall firewall show rule name=Private VPN Pro verbose" {
		t.Error(got)
	}
}

func TestRuleCoversProgram(t *testing.T) {
	out := []byte("Rule Name: Private VPN Pro\r\n----\r\nEnabled: Yes\r\nDirection: In\r\nProfiles: Domain,Private\r\nProgram: C:\\Users\\Al\\Private VPN Pro\\private-vpn-pro.exe\r\nAction: Allow\r\n")
	if !ruleCoversProgram(out, `c:\users\al\private vpn pro\PRIVATE-VPN-PRO.exe`) {
		t.Error("case-insensitive match")
	}
	if ruleCoversProgram(out, `C:\Other\private-vpn-pro.exe`) {
		t.Error("a rule for another path is stale")
	}
	if !ruleCoversProgram(out, `C:\Users\Zoë\private-vpn-pro.exe`) {
		t.Error("non-ASCII paths accept any rule with our name")
	}
}

func TestValidExe(t *testing.T) {
	for _, bad := range []string{"", `C:\a"b.exe`, "C:\\a\nb.exe", "C:\\a\x00.exe"} {
		if validExe(bad) {
			t.Errorf("%q accepted", bad)
		}
	}
	if !validExe(`C:\Program Files\Private VPN Pro\private-vpn-pro.exe`) {
		t.Error("normal path rejected")
	}
}
