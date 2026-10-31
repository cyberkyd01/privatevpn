package engine

import (
	"encoding/json"
	"net/netip"
	"testing"
	"time"

	"github.com/cyberkyd01/privatevpn/core/control"
	"github.com/cyberkyd01/privatevpn/core/eventlog"
	"github.com/cyberkyd01/privatevpn/core/netkey"
	"github.com/cyberkyd01/privatevpn/core/tunnel"
	"github.com/cyberkyd01/privatevpn/core/wire"
)

func newTestEngine(t *testing.T) *Engine {
	t.Helper()
	e, err := New(Options{DataDir: t.TempDir(), AppVersion: "1.0.0", Log: eventlog.New(100)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.Close)
	return e
}

func call(t *testing.T, e *Engine, method string, args any) (map[string]any, string) {
	t.Helper()
	b, _ := json.Marshal(args)
	res, aerr := e.Call(method, b)
	if aerr != nil {
		return nil, aerr.Code
	}
	var m map[string]any
	if err := json.Unmarshal(res, &m); err != nil {
		t.Fatalf("%s: bad JSON %s", method, res)
	}
	return m, ""
}

// fakeBeacon injects a beacon from a gateway with pub=[1…] signed under k.
func fakeBeacon(e *Engine, k netkey.Key, ctr uint32) {
	b := wire.Beacon{TS: uint64(time.Now().Unix()), InstanceID: 7, Counter: ctr, WGPort: 51820, CtrlPort: 51821,
		Flags: wire.BeaconAccepting, OS: wire.OSWindows, ClientCount: 1, AppVersion: [3]byte{1, 0, 0}, Name: "Office‮PC"}
	b.GatewayPub[0] = 1
	e.core.onBeacon(b.Seal(k.Derive().Beacon), netip.MustParseAddr("192.168.1.10"))
}

func listOne(t *testing.T, e *Engine) map[string]any {
	t.Helper()
	m, code := call(t, e, "gateways.list", nil)
	if code != "" {
		t.Fatal(code)
	}
	// Real gateways on the LAN may also be listed; pick the injected one.
	want := pubID([32]byte{1})
	for _, g := range m["gateways"].([]any) {
		if gm := g.(map[string]any); gm["id"] == want {
			return gm
		}
	}
	t.Fatal("injected gateway not listed")
	return nil
}

func TestLockedThenUnlock(t *testing.T) {
	e := newTestEngine(t)
	gwKey, _ := netkey.Generate()
	fakeBeacon(e, gwKey, 1)

	g := listOne(t, e)
	if g["access"] != "locked" || g["network"] != nil {
		t.Fatalf("expected locked entry, got %v", g["access"])
	}
	if g["name"] != "OfficePC" {
		t.Fatalf("bidi control not stripped from beacon name: %q", g["name"])
	}
	id := g["id"].(string)

	if _, code := call(t, e, "gateways.unlock", map[string]any{"gateway_id": id, "key_text": "PVN1-nope"}); code != "key_format" {
		t.Fatalf("bad key text: %s", code)
	}
	other, _ := netkey.Generate()
	if _, code := call(t, e, "gateways.unlock", map[string]any{"gateway_id": id, "key_text": other.Text()}); code != "key_mismatch" {
		t.Fatalf("wrong key: %s", code)
	}
	if _, code := call(t, e, "gateways.info", map[string]any{"gateway_id": id}); code != "locked" {
		t.Fatalf("info on locked gateway: %s", code)
	}
	if _, code := call(t, e, "client.connect", map[string]any{"gateway_id": id}); code != "locked" {
		t.Fatalf("connect to locked gateway: %s", code)
	}

	res, code := call(t, e, "gateways.unlock", map[string]any{"gateway_id": id, "key_text": gwKey.Text()})
	if code != "" || res["method"] != "beacon" || res["replaced"] != false {
		t.Fatalf("unlock: %v %s", res, code)
	}
	g = listOne(t, e)
	if g["access"] != "member" || g["network"] == nil {
		t.Fatalf("after unlock: %v", g["access"])
	}
	kr, _ := call(t, e, "keyring.list", nil)
	entries := kr["entries"].([]any)
	if len(entries) != 1 {
		t.Fatalf("keyring entries %d", len(entries))
	}
	if _, ok := entries[0].(map[string]any)["key"]; ok {
		t.Fatal("keyring.list leaked key bytes")
	}

	// Gateway resets its key: entry turns key_changed after its verified
	// beacons stop, and the new key replaces the old entry in place.
	e.core.table.Expire()
	newKey, _ := netkey.Generate()
	old := entries[0].(map[string]any)["id"].(string)
	waitUntil(t, func() bool {
		fakeBeacon(e, newKey, uint32(time.Now().UnixNano()))
		return listOne(t, e)["access"] == "key_changed"
	})
	res, code = call(t, e, "gateways.unlock", map[string]any{"gateway_id": id, "key_text": newKey.Text()})
	if code != "" || res["replaced"] != true || res["keyring_id"] != old {
		t.Fatalf("replace path: %v %s", res, code)
	}
	if listOne(t, e)["access"] != "member" {
		t.Fatal("not member after replacing key")
	}
}

// blockingTunnel blocks in Up until release is closed and reports Down.
type blockingTunnel struct {
	upStarted chan struct{}
	release   chan struct{}
	downed    chan struct{}
}

func newBlockingTunnel() *blockingTunnel {
	return &blockingTunnel{upStarted: make(chan struct{}, 1), release: make(chan struct{}), downed: make(chan struct{}, 4)}
}

func (b *blockingTunnel) Up(tunnel.Config) (string, error) {
	select {
	case b.upStarted <- struct{}{}:
	default:
	}
	<-b.release
	return "fake0", nil
}

func (b *blockingTunnel) Down() error {
	select {
	case b.downed <- struct{}{}:
	default:
	}
	return nil
}

func (b *blockingTunnel) Status() (tunnel.Status, error) {
	return tunnel.Status{IfName: "fake0", HandshakeAgeSec: -1}, nil
}
func (b *blockingTunnel) SetEndpoint(netip.AddrPort) error { return nil }
func (b *blockingTunnel) RouteAdd(netip.Addr) error        { return nil }
func (b *blockingTunnel) RouteDel(netip.Addr) error        { return nil }
func (b *blockingTunnel) Close() error                     { return b.Down() }

// leaseHandler is a control.Handler that grants every JOIN.
type leaseHandler struct{}

func (leaseHandler) Join([32]byte, int) (control.JoinResult, wire.ErrCode) {
	gw := netip.MustParseAddr("10.77.201.1")
	return control.JoinResult{Assigned: netip.MustParseAddr("10.77.201.2"), GatewayIP: gw, DNS: gw,
		WGPort: 51820, MTU: 1280, Keepalive: 25, LeaseSec: 120, Token: [16]byte{1}}, wire.ErrNone
}
func (leaseHandler) Renew([32]byte, [16]byte) (uint32, bool, wire.ErrCode) {
	return 120, false, wire.ErrNone
}
func (leaseHandler) Leave([32]byte, [16]byte) {}
func (leaseHandler) Info() []byte             { return []byte(`{"v":1}`) }

// A disconnect that lands while the tunnel is still coming up (the
// elevation prompt, typically) must not leave the tunnel up with no session.
func TestDisconnectDuringTunnelUp(t *testing.T) {
	key, _ := netkey.Generate()
	sub := key.Derive()
	var gwPub [32]byte
	gwPub[0] = 1
	srv, err := control.Listen(control.ServerConfig{Port: 0, ControlKey: sub.Control, GatewayPub: gwPub,
		Handler: leaseHandler{}, Log: eventlog.New(10)})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	bt := newBlockingTunnel()
	e, err := New(Options{DataDir: t.TempDir(), AppVersion: "1.0.0", Log: eventlog.New(100),
		Platform: Platform{NewTunnel: func() (tunnel.Tunnel, error) { return bt, nil }}})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if _, code := call(t, e, "keyring.add", map[string]any{"key_text": key.Text()}); code != "" {
		t.Fatal(code)
	}
	b := wire.Beacon{GatewayPub: gwPub, TS: uint64(time.Now().Unix()), InstanceID: 3, Counter: 1,
		WGPort: 51820, CtrlPort: uint16(srv.Port()), Flags: wire.BeaconAccepting, OS: wire.OSLinux, Name: "gw"}
	e.core.onBeacon(b.Seal(sub.Beacon), netip.MustParseAddr("127.0.0.1"))
	g := listOne(t, e)
	if g["access"] != "member" {
		t.Fatalf("access %v", g["access"])
	}
	if _, code := call(t, e, "client.connect", map[string]any{"gateway_id": g["id"]}); code != "" {
		t.Fatal("connect:", code)
	}
	select {
	case <-bt.upStarted:
	case <-time.After(15 * time.Second):
		t.Fatal("tunnel Up not reached")
	}
	call(t, e, "client.disconnect", nil)
	close(bt.release)
	select {
	case <-bt.downed:
	case <-time.After(5 * time.Second):
		t.Fatal("tunnel left up after a disconnect during Up")
	}
	if st := status(t, e)["client"].(map[string]any); st["state"] != "idle" {
		t.Fatalf("client state %v", st["state"])
	}
}

func TestNoGatewayAfterClose(t *testing.T) {
	e := newTestEngine(t)
	e.Close()
	if aerr := e.core.gatewayEnable(); aerr == nil {
		t.Fatal("gateway enabled after Close")
	}
	e.core.mu.Lock()
	defer e.core.mu.Unlock()
	if e.core.gw != nil {
		t.Fatal("gateway running after Close")
	}
}

func waitUntil(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met")
		}
		time.Sleep(250 * time.Millisecond)
	}
}

func TestKeyringValidation(t *testing.T) {
	e := newTestEngine(t)
	res, code := call(t, e, "keyring.create", map[string]any{"label": "Home\x00"})
	if code != "" {
		t.Fatal(code)
	}
	if _, err := netkey.Parse(res["key_text"].(string)); err != nil {
		t.Fatal("created key does not parse")
	}
	r2, _ := call(t, e, "keyring.add", map[string]any{"key_text": res["key_text"]})
	if r2["existing"] != true || r2["id"] != res["id"] {
		t.Fatal("duplicate key not deduplicated")
	}
	kr, _ := call(t, e, "keyring.list", nil)
	if l := kr["entries"].([]any)[0].(map[string]any)["label"]; l != "Home" {
		t.Fatalf("label not cleaned: %q", l)
	}
	if _, code := call(t, e, "settings.set", map[string]any{"gateway": map[string]any{"subnet": "8.8.8.0/24"}}); code != "bad_request" {
		t.Fatalf("public subnet accepted: %s", code)
	}
	if _, code := call(t, e, "gateways.manual_add", map[string]any{"host": "bad host!"}); code != "bad_request" {
		t.Fatalf("bad host accepted: %s", code)
	}
}

func TestSanitizeInfo(t *testing.T) {
	doc := []byte(`{"v":1,"name":"A‮B","os":"evil","client_count":9999,"public_ip":"not-an-ip",
	  "lan_ips":["10.0.0.1","x"],"geo":{"source":"geoip","lat":200,"lon":10,"country_code":"de"},
	  "tz":{"name":"Europe/Berlin; rm","utc_offset_sec":3600}}`)
	m := sanitizeInfo(doc)
	if m["name"] != "AB" || m["os"] != nil || m["client_count"] != nil || m["public_ip"] != nil {
		t.Fatalf("sanitize: %v", m)
	}
	geo := m["geo"].(map[string]any)
	if geo["lat"] != nil || geo["country_code"] != nil {
		t.Fatalf("geo not validated: %v", geo)
	}
	if tz := m["tz"].(map[string]any); tz["name"] != nil || tz["utc_offset_sec"] != float64(3600) {
		t.Fatalf("tz: %v", tz)
	}
	if ips := m["lan_ips"].([]string); len(ips) != 1 {
		t.Fatalf("lan_ips: %v", ips)
	}
}
