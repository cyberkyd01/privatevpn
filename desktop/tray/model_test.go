//go:build !android

package tray

import (
	"strings"
	"testing"
)

func TestSanitize(t *testing.T) {
	cases := map[string]string{
		"Office PC":                          "Office PC",
		"evil‮exe.txt":                       "evilexe.txt",
		"a⁦b⁩c‎‏d":                           "abcd",
		"line\nbreak\ttab\x00nul\x7fdel\x85": "linebreaktabnuldel",
		"  spaced  ":                         "spaced",
		strings.Repeat("x", 40):              strings.Repeat("x", 32) + "…",
		strings.Repeat("é", 33):              strings.Repeat("é", 32) + "…",
		"bad\xffutf8":                        "badutf8",
	}
	for in, want := range cases {
		if got := sanitize(in, 32); got != want {
			t.Errorf("sanitize(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseStatusAndIcon(t *testing.T) {
	st, ok := parseStatus([]byte(`{"version":"1","gateway":{"enabled":true,"network":{"id":"n1","label":"Home"},"clients":2},"client":{"state":"connected","gateway_id":"g1","gateway_name":"Alice‮ PC","protected":true,"kill_switch":"on"},"problems":[]}`))
	if !ok || !st.GatewayEnabled || st.GatewayNetworkID != "n1" || st.GatewayClients != 2 || st.ClientState != "connected" || st.ClientGateway != "Alice PC" || st.Unprotected || st.Problems != 0 {
		t.Fatalf("%+v", st)
	}
	if iconFor(st) != iconBoth {
		t.Error("both")
	}
	if got := statusLine(st); got != "Protected · connected to Alice PC · Gateway on (2 clients)" {
		t.Errorf("status line %q", got)
	}
	if problemLine(st) != "" {
		t.Error("no problems expected")
	}
	st, _ = parseStatus([]byte(`{"version":"dev"}`)) // the engine stub
	if iconFor(st) != iconIdle || statusLine(st) != "Not protected (VPN off)" || st.GatewayNetworkID != "" || st.Unprotected {
		t.Errorf("stub status: %+v %q", st, statusLine(st))
	}
	cases := []struct {
		gw    bool
		state string
		want  iconKind
	}{
		{false, "idle", iconIdle}, {false, "joining", iconIdle}, {true, "joining", iconGateway},
		{false, "tunnel_up", iconConnected}, {false, "degraded", iconWarning}, {true, "connected", iconBoth},
		{true, "", iconGateway}, {false, "blocked", iconWarning}, {true, "blocked", iconWarning}, {true, "degraded", iconWarning},
	}
	for _, c := range cases {
		if got := iconFor(statusModel{GatewayEnabled: c.gw, ClientState: c.state}); got != c.want {
			t.Errorf("gw=%v state=%q: %v, want %v", c.gw, c.state, got, c.want)
		}
	}
	if _, ok := parseStatus([]byte(`nope`)); ok {
		t.Error("invalid JSON accepted")
	}
	if got := statusLine(statusModel{GatewayEnabled: true, GatewayClients: 1, ClientState: "degraded"}); got != "Connection interrupted — traffic held, reconnecting · Gateway on (1 client)" {
		t.Errorf("%q", got)
	}
}

func TestKillSwitchStates(t *testing.T) {
	// A crashed session's leftover block: no gateway, state blocked.
	st, ok := parseStatus([]byte(`{"client":{"state":"blocked","gateway_id":"","kill_switch":"on"},"problems":[
		{"code":"cgnat","severity":"info","message":"carrier NAT"},
		{"code":"kill_switch_engaged","severity":"error","action":"disconnect","message":"Internet access is blocked by the kill switch\u202e."}]}`))
	if !ok || st.ClientState != "blocked" || st.Problems != 1 || st.FirstProblem != "Internet access is blocked by the kill switch." {
		t.Fatalf("%+v", st)
	}
	if iconFor(st) != iconWarning || statusLine(st) != "Internet blocked to protect your IP" || !canDisconnect(st.ClientState) {
		t.Errorf("blocked: icon %v line %q", iconFor(st), statusLine(st))
	}
	if got := problemLine(st); got != "⚠ Internet access is blocked by the kill switch." {
		t.Errorf("problem line %q", got)
	}
	// Blocked session with the kill switch off: do not claim it is blocked.
	st, _ = parseStatus([]byte(`{"client":{"state":"blocked","gateway_id":"g1","gateway_name":"Home","kill_switch":"off"}}`))
	if got := statusLine(st); got != "VPN connection failed — traffic may not be protected" {
		t.Errorf("kill switch off: %q", got)
	}
	// Connected but leaking (e.g. IPv6 not blocked): warning icon, two problems.
	st, _ = parseStatus([]byte(`{"client":{"state":"connected","gateway_name":"Home","protected":false},"problems":[
		{"severity":"warning","message":"Kill switch is off"},{"severity":"error","message":"IPv6 traffic could not be blocked"}]}`))
	if !st.Unprotected || iconFor(st) != iconWarning || statusLine(st) != "Connected to Home — not fully protected" {
		t.Errorf("unprotected: %+v %q", st, statusLine(st))
	}
	if st.FirstProblem != "IPv6 traffic could not be blocked" || problemLine(st) != "⚠ 2 problems — open Private VPN Pro for details" {
		t.Errorf("problems: %+v %q", st, problemLine(st))
	}
	// Resuming after a restart.
	st, _ = parseStatus([]byte(`{"client":{"state":"blocked","resume_pending":true}}`))
	if got := statusLine(st); got != "Reconnecting after restart — Internet blocked" {
		t.Errorf("resume blocked: %q", got)
	}
	st, _ = parseStatus([]byte(`{"client":{"state":"joining","gateway_name":"Home","resume_pending":true}}`))
	if got := statusLine(st); got != "Reconnecting to Home after restart…" {
		t.Errorf("resume joining: %q", got)
	}
	// Long problem texts are capped for the menu.
	st, _ = parseStatus([]byte(`{"problems":[{"severity":"error","message":"` + strings.Repeat("x", 200) + `"}]}`))
	if n := len([]rune(st.FirstProblem)); n != 71 {
		t.Errorf("first problem length %d", n)
	}
	for state, want := range map[string]bool{"": false, "idle": false, "joining": true, "tunnel_up": true, "connected": true, "degraded": true, "blocked": true} {
		if canDisconnect(state) != want {
			t.Errorf("canDisconnect(%q) = %v", state, !want)
		}
	}
}

func TestConnectEntriesOrderAndLabels(t *testing.T) {
	gws, ok := parseGateways([]byte(`[
		{"id":"l1","name":"Zed","access":"locked","online":true},
		{"id":"m2","name":"Bravo","access":"member","online":true},
		{"id":"off","name":"Alpha","access":"member","online":false},
		{"id":"m1","name":"Alpha","access":"member","online":true},
		{"id":"kc","name":"Key","access":"key_changed","online":true},
		{"id":"lo","name":"Gone","access":"locked","online":false},
		{"id":"self","name":"Me","access":"member","online":true,"is_self":true},
		{"id":"weird","name":"","access":"something","online":true,"manual":{"label":"Manual one"}},
		{"id":"","name":"no id"}
	]`))
	if !ok {
		t.Fatal("parse")
	}
	es, more := connectEntries(gws, statusModel{ClientState: "connected", ClientGatewayID: "m2"})
	var got []string
	for _, e := range es {
		got = append(got, e.Title)
	}
	want := []string{"Alpha", "Bravo", "🔒 Key", "🔒 Manual one", "🔒 Zed", "Alpha (offline)"}
	if strings.Join(got, "|") != strings.Join(want, "|") || more != 0 {
		t.Fatalf("entries %q (more %d), want %q", got, more, want)
	}
	if !es[1].Checked || es[0].Checked {
		t.Error("connected gateway should be checked")
	}
	if !es[2].Locked || !es[3].Locked || es[0].Locked {
		t.Error("lock flags")
	}
	if !es[5].Disabled || es[5].Locked {
		t.Error("offline member should be disabled")
	}
	// Overflow beyond the pool.
	var many []gatewayModel
	for i := 0; i < maxEntries+5; i++ {
		many = append(many, gatewayModel{ID: string(rune('a' + i)), Name: "G", Access: "member", Online: true})
	}
	es, more = connectEntries(many, statusModel{})
	if len(es) != maxEntries || more != 5 {
		t.Errorf("len %d more %d", len(es), more)
	}
}

func TestMenuText(t *testing.T) {
	if got := menuText("windows", "R&D_PC"); got != "R&&D_PC" {
		t.Error(got)
	}
	if got := menuText("linux", "R&D_PC"); got != "R&D__PC" {
		t.Error(got)
	}
	if got := menuText("darwin", "R&D_PC"); got != "R&D_PC" {
		t.Error(got)
	}
}

func TestIconsEmbedded(t *testing.T) {
	for _, n := range iconNames {
		for _, suffix := range []string{".png", ".ico", "_template.png"} {
			b := mustIcon(n + suffix)
			if len(b) < 100 {
				t.Errorf("%s%s too small", n, suffix)
			}
			if strings.HasSuffix(suffix, ".png") && string(b[1:4]) != "PNG" {
				t.Errorf("%s%s is not a PNG", n, suffix)
			}
			if suffix == ".ico" && (b[0] != 0 || b[1] != 0 || b[2] != 1 || b[3] != 0) {
				t.Errorf("%s.ico is not an ICO", n)
			}
		}
	}
}

func TestOpenBrowserRefusesRemote(t *testing.T) {
	for _, u := range []string{"https://evil.example/", "http://localhost:47771/", "file:///etc/passwd", "http://127.0.0.1.evil.example/"} {
		if err := OpenBrowser(u); err == nil {
			t.Errorf("OpenBrowser(%q) accepted", u)
		}
	}
}
