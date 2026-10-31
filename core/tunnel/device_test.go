//go:build windows || darwin || linux

package tunnel

import (
	"encoding/hex"
	"net/netip"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/conn/bindtest"
	"golang.zx2c4.com/wireguard/tun/tuntest"

	"github.com/cyberkyd01/privatevpn/core/eventlog"
)

// TestDeviceUAPI feeds our UAPI text to the real wireguard-go parser on an
// in-memory TUN and bind (no privileges, no sockets) and reads it back.
func TestDeviceUAPI(t *testing.T) {
	binds := bindtest.NewChannelBinds()
	old := newBind
	newBind = func() conn.Bind { return binds[0] }
	defer func() { newBind = old }()

	log := eventlog.New(100)
	c := testConfig()
	w, err := startDevice(tuntest.NewChannelTUN().TUN(), c, 20566, log)
	if err != nil {
		t.Fatalf("startDevice: %v", err)
	}
	defer w.close()

	get, err := w.dev.IpcGet()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"private_key=" + hex.EncodeToString(c.PrivateKey[:]),
		"fwmark=20566",
		"public_key=" + hex.EncodeToString(c.Peer.PublicKey[:]),
		"preshared_key=" + hex.EncodeToString(c.Peer.PresharedKey[:]),
		"persistent_keepalive_interval=25",
		"allowed_ip=0.0.0.0/0",
	} {
		if !strings.Contains(get, want+"\n") {
			t.Errorf("IpcGet lacks %q", want)
		}
	}
	if strings.Count(get, "allowed_ip=") != 1 {
		t.Errorf("expected exactly one allowed_ip:\n%s", get)
	}
	st, err := w.status()
	if err != nil || st.HandshakeAgeSec != -1 {
		t.Errorf("status before handshake: %+v %v", st, err)
	}
	if err := w.setEndpoint(netip.MustParseAddrPort("203.0.113.9:4000")); err != nil {
		t.Errorf("setEndpoint: %v", err)
	}
	get, _ = w.dev.IpcGet()
	if !strings.Contains(get, "endpoint=127.0.0.1:4000\n") { // bindtest renders every endpoint as 127.0.0.1:<port>
		t.Errorf("endpoint not updated:\n%s", get)
	}

	// The keepalive triggers a handshake whose send fails on the fake bind:
	// the error must reach the log without peer tags or addresses.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && len(log.Lines()) == 0 {
		time.Sleep(20 * time.Millisecond)
	}
	for _, l := range log.Lines() {
		if strings.Contains(l, "peer(") || strings.Contains(l, "127.0.0.1") || strings.Contains(l, "203.0.113.9") {
			t.Errorf("unredacted log line: %s", l)
		}
	}
}

func TestDeviceRejectsBadUAPI(t *testing.T) {
	binds := bindtest.NewChannelBinds()
	old := newBind
	newBind = func() conn.Bind { return binds[0] }
	defer func() { newBind = old }()

	c := testConfig()
	c.Peer.Endpoint = netip.AddrPort{} // renders "endpoint=invalid AddrPort"
	if _, err := startDevice(tuntest.NewChannelTUN().TUN(), c, 0, eventlog.New(10)); err == nil {
		t.Fatal("invalid endpoint accepted")
	} else if strings.Contains(err.Error(), "invalid AddrPort") {
		t.Errorf("error quotes the value: %v", err)
	}
}
