package engine

import (
	"bufio"
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"

	"github.com/cyberkyd01/privatevpn/core/eventlog"
	"github.com/cyberkyd01/privatevpn/core/tunnel"
)

// nsTunnel is a userspace client tunnel (no TUN, no privileges) for tests.
type nsTunnel struct {
	mu         sync.Mutex
	dev        *device.Device
	tnet       *netstack.Net
	downs      int  // explicit Down calls
	ups        int  // Up calls (successful or not)
	failStatus bool // simulate the tunnel process dying
	failUp     bool // simulate the OS refusing the tunnel (after the block went in)
	breakPSK   bool // a tunnel that never handshakes (gateway firewall)
}

func (n *nsTunnel) Up(cfg tunnel.Config) (string, error) {
	n.mu.Lock()
	n.ups++
	old := n.dev
	n.dev, n.tnet = nil, nil
	failUp, breakPSK := n.failUp, n.breakPSK
	n.mu.Unlock()
	if old != nil {
		old.Close() // replacing the tunnel is not a Down
	}
	if failUp {
		return "", fmt.Errorf("tunnel: create adapter: driver not installed")
	}
	if breakPSK {
		cfg.Peer.PresharedKey[0] ^= 1
	}
	tdev, tnet, err := netstack.CreateNetTUN([]netip.Addr{cfg.Address.Addr()}, cfg.DNS, cfg.MTU)
	if err != nil {
		return "", err
	}
	dev := device.NewDevice(tdev, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	uapi := fmt.Sprintf("private_key=%s\npublic_key=%s\npreshared_key=%s\nendpoint=%s\nallowed_ip=0.0.0.0/0\npersistent_keepalive_interval=%d\n",
		hex.EncodeToString(cfg.PrivateKey[:]), hex.EncodeToString(cfg.Peer.PublicKey[:]),
		hex.EncodeToString(cfg.Peer.PresharedKey[:]), cfg.Peer.Endpoint, cfg.Peer.Keepalive)
	if err := dev.IpcSet(uapi); err != nil {
		dev.Close()
		return "", err
	}
	dev.Up()
	n.mu.Lock()
	n.dev, n.tnet = dev, tnet
	n.mu.Unlock()
	return "netstack", nil
}

func (n *nsTunnel) Status() (tunnel.Status, error) {
	n.mu.Lock()
	dev, fail := n.dev, n.failStatus
	n.mu.Unlock()
	if fail {
		return tunnel.Status{}, fmt.Errorf("helper gone")
	}
	st := tunnel.Status{IfName: "netstack", HandshakeAgeSec: -1}
	if dev == nil {
		return st, nil
	}
	s, err := dev.IpcGet()
	if err != nil {
		return st, err
	}
	sc := bufio.NewScanner(strings.NewReader(s))
	for sc.Scan() {
		k, v, _ := strings.Cut(sc.Text(), "=")
		n, _ := strconv.ParseInt(v, 10, 64)
		switch k {
		case "last_handshake_time_sec":
			if n > 0 {
				st.HandshakeAgeSec = time.Now().Unix() - n
			}
		case "rx_bytes":
			st.RxBytes = uint64(n)
		case "tx_bytes":
			st.TxBytes = uint64(n)
		}
	}
	return st, nil
}

func (n *nsTunnel) SetEndpoint(netip.AddrPort) error { return nil }
func (n *nsTunnel) RouteAdd(netip.Addr) error        { return nil }
func (n *nsTunnel) RouteDel(netip.Addr) error        { return nil }
func (n *nsTunnel) Close() error                     { return n.Down() }
func (n *nsTunnel) Down() error {
	n.mu.Lock()
	dev := n.dev
	n.dev, n.tnet = nil, nil
	n.downs++
	n.failStatus = false
	n.mu.Unlock()
	if dev != nil {
		dev.Close()
	}
	return nil
}

// freeUDPPorts returns two distinct free UDP ports (both sockets are held
// open while choosing, so the OS cannot hand out the same port twice).
func freeUDPPorts(t *testing.T) (int, int) {
	t.Helper()
	var ports [2]int
	for i := range ports {
		c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		ports[i] = c.LocalAddr().(*net.UDPAddr).Port
	}
	return ports[0], ports[1]
}

func status(t *testing.T, e *Engine) map[string]any {
	t.Helper()
	m, code := call(t, e, "status.get", nil)
	if code != "" {
		t.Fatal(code)
	}
	return m
}

func TestEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("end-to-end test")
	}
	// Gateway engine.
	gw := newTestEngine(t)
	wgPort, ctrlPort := freeUDPPorts(t)
	if _, code := call(t, gw, "settings.set", map[string]any{"gateway": map[string]any{
		"wg_port": wgPort, "ctrl_port": ctrlPort, "geo": map[string]any{"enabled": false}}}); code != "" {
		t.Fatal("settings:", code)
	}
	if _, code := call(t, gw, "gateway.enable", nil); code != "" {
		t.Fatal("enable:", code)
	}
	gst := status(t, gw)["gateway"].(map[string]any)
	if gst["enabled"] != true || gst["network"] == nil {
		t.Fatalf("gateway status %v", gst)
	}
	netID := gst["network"].(map[string]any)["id"].(string)
	rv, _ := call(t, gw, "keyring.reveal", map[string]any{"id": netID})
	keyText := rv["key_text"].(string)

	// Client engine with a userspace tunnel.
	tun := &nsTunnel{}
	cl, err := New(Options{DataDir: t.TempDir(), AppVersion: "1.0.0", Log: eventlog.New(200),
		Platform: Platform{NewTunnel: func() (tunnel.Tunnel, error) { return tun, nil }}})
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()

	res, code := call(t, cl, "gateways.manual_add", map[string]any{"label": "Test GW", "host": "127.0.0.1", "ctrl_port": ctrlPort})
	if code != "" {
		t.Fatal("manual_add:", code)
	}
	manualID := res["id"].(string)
	findManual := func() map[string]any {
		m, _ := call(t, cl, "gateways.list", nil)
		for _, g := range m["gateways"].([]any) {
			gm := g.(map[string]any)
			if mm, ok := gm["manual"].(map[string]any); ok && mm["id"] == manualID {
				return gm
			}
		}
		return nil
	}
	g := findManual()
	if g == nil || g["access"] != "locked" {
		t.Fatalf("manual entry should be locked first: %v", g)
	}
	res, code = call(t, cl, "gateways.unlock", map[string]any{"gateway_id": g["id"], "key_text": keyText})
	if code != "" || res["method"] != "info" {
		t.Fatalf("unlock via INFO: %v %s", res, code)
	}
	g = findManual()
	if g["access"] != "member" {
		t.Fatalf("after unlock: %v", g["access"])
	}
	gid := g["id"].(string)
	if strings.HasPrefix(gid, "m-") {
		t.Fatal("gateway public key not learned from INFO")
	}

	info, code := call(t, cl, "gateways.info", map[string]any{"gateway_id": gid})
	if code != "" {
		t.Fatal("info:", code)
	}
	doc := info["info"].(map[string]any)
	if doc["pubkey"] != gid || doc["subnet"] == nil || doc["tz"] == nil || doc["now"] == nil {
		t.Fatalf("info doc %v", doc)
	}

	if _, code := call(t, cl, "client.connect", map[string]any{"gateway_id": gid}); code != "" {
		t.Fatal("connect:", code)
	}
	var cst map[string]any
	waitUntil(t, func() bool {
		cst = status(t, cl)["client"].(map[string]any)
		if e, _ := cst["error"].(string); e != "" {
			t.Fatalf("client error: %s", e)
		}
		return cst["state"] == "connected"
	})
	if n := status(t, gw)["gateway"].(map[string]any)["clients"]; n != float64(1) {
		t.Fatalf("gateway clients = %v", n)
	}

	// Ping the gateway's tunnel address through WireGuard + the gVisor stack.
	assigned := netip.MustParseAddr(cst["assigned_ip"].(string))
	gwIP := netip.AddrFrom4([4]byte{assigned.As4()[0], assigned.As4()[1], assigned.As4()[2], 1})
	tun.mu.Lock()
	tnet := tun.tnet
	tun.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	pc, err := tnet.DialContext(ctx, "ping4", gwIP.String())
	if err != nil {
		t.Fatal(err)
	}
	pc.SetDeadline(time.Now().Add(5 * time.Second))
	echo := []byte{8, 0, 0, 0, 0, 1, 0, 1, 'p', 'v', 'n'}
	if _, err := pc.Write(echo); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	if _, err := pc.Read(buf); err != nil {
		t.Fatalf("no ping reply through the tunnel: %v", err)
	}
	pc.Close()

	// The gateway must not have written anything about the client to disk or log.
	for _, line := range gw.log.Lines() {
		if strings.Contains(line, assigned.String()) {
			t.Fatalf("gateway log mentions the client address: %q", line)
		}
	}

	call(t, cl, "client.disconnect", nil)
	waitUntil(t, func() bool {
		return status(t, gw)["gateway"].(map[string]any)["clients"] == float64(0)
	})
	if status(t, cl)["client"].(map[string]any)["state"] != "idle" {
		t.Fatal("client not idle after disconnect")
	}
}
