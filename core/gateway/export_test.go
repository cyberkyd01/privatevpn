package gateway

import (
	"bytes"
	"encoding/hex"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

// testNet is a TEST-NET-1 address that passes the destination policy; with
// setRedirect, flows to it are dialled to the same port on 127.0.0.1.
// (Loopback itself stays denied, and gVisor on both ends drops loopback-
// addressed packets as martians.)
var testNet = netip.MustParseAddr("192.0.2.1")

func setRedirect(t testing.TB) {
	redirectForTesting = func(dst netip.AddrPort) netip.AddrPort {
		if dst.Addr() == testNet {
			return netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), dst.Port())
		}
		return dst
	}
	t.Cleanup(func() { redirectForTesting = nil })
}

// viaTestNet returns the tunnel-side address for a local server.
func viaTestNet(local net.Addr) netip.AddrPort {
	var port int
	switch a := local.(type) {
	case *net.TCPAddr:
		port = a.Port
	case *net.UDPAddr:
		port = a.Port
	}
	return netip.AddrPortFrom(testNet, uint16(port))
}

// fakeClock replaces the lease clock of gateways started afterwards.
type fakeClock struct{ off atomic.Int64 }

func (c *fakeClock) now() time.Time          { return time.Now().Add(time.Duration(c.off.Load())) }
func (c *fakeClock) advance(d time.Duration) { c.off.Add(int64(d)) }

func setFakeClock(t testing.TB) *fakeClock {
	c := &fakeClock{}
	nowFunc = c.now
	t.Cleanup(func() { nowFunc = time.Now })
	return c
}

// peerKeys returns the public keys configured on the WireGuard device.
func (g *Gateway) peerKeys() map[[32]byte]bool {
	var buf bytes.Buffer
	if err := g.wg.IpcGetOperation(&buf); err != nil {
		return nil
	}
	out := map[[32]byte]bool{}
	for _, line := range bytes.Split(buf.Bytes(), []byte{'\n'}) {
		if v, ok := bytes.CutPrefix(line, []byte("public_key=")); ok {
			var k [32]byte
			if n, _ := hex.Decode(k[:], v); n == 32 {
				out[k] = true
			}
		}
	}
	return out
}
