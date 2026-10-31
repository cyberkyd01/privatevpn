package gwstack

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

var (
	gwPrefix = netip.MustParsePrefix("10.77.1.1/24")
	clientIP = netip.MustParseAddr("10.77.1.2")
	testNet  = netip.MustParseAddr("192.0.2.1") // redirected to 127.0.0.1
)

// harness wires a netstack client TUN straight into a Device (no
// WireGuard), with a switchable lease for clientIP.
type harness struct {
	d      *Device
	cnet   *netstack.Net
	client atomic.Pointer[Client]
}

func newHarness(t *testing.T, lim Limits, upstream netip.AddrPort) *harness {
	t.Helper()
	h := &harness{}
	d, err := New(Config{
		Prefix: gwPrefix,
		MTU:    1280,
		Limits: lim,
		Lookup: func(src netip.Addr) *Client {
			if src == clientIP {
				return h.client.Load()
			}
			return nil
		},
		DNSUpstreams: func() []netip.AddrPort { return []netip.AddrPort{upstream} },
		RedirectForTesting: func(dst netip.AddrPort) netip.AddrPort {
			if dst.Addr() == testNet {
				return netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), dst.Port())
			}
			return dst
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctun, cnet, err := netstack.CreateNetTUN([]netip.Addr{clientIP}, nil, 1280)
	if err != nil {
		t.Fatal(err)
	}
	h.d, h.cnet = d, cnet
	go pump(ctun, d)
	go pump(d, ctun)
	t.Cleanup(func() { d.Close(); ctun.Close() })
	return h
}

func pump(from, to tun.Device) {
	bufs, sizes := [][]byte{make([]byte, 65535)}, []int{0}
	for {
		n, err := from.Read(bufs, sizes, 0)
		if err != nil {
			return
		}
		if n == 1 {
			to.Write([][]byte{bufs[0][:sizes[0]]}, 0)
		}
	}
}

func (h *harness) dial(port int) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return h.cnet.DialContextTCPAddrPort(ctx, netip.AddrPortFrom(testNet, uint16(port)))
}

// holdServer accepts connections and reports when each one closes.
func holdServer(t *testing.T) (port int, closed <-chan struct{}) {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	ch := make(chan struct{}, 16)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				io.Copy(io.Discard, c)
				c.Close()
				ch <- struct{}{}
			}()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port, ch
}

func TestUnleasedSourceRefused(t *testing.T) {
	up := newFakeUpstream(t, false)
	h := newHarness(t, testLimits(), up.addr())
	port, _ := holdServer(t)

	start := time.Now()
	if c, err := h.dial(port); err == nil {
		c.Close()
		t.Fatal("unleased source connected")
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("no RST for unleased source")
	}
	// DNS from an unleased source is dropped too.
	uc, err := h.cnet.DialUDPAddrPort(netip.AddrPort{}, netip.AddrPortFrom(gwPrefix.Addr(), 53))
	if err != nil {
		t.Fatal(err)
	}
	uc.Write(buildQuery(t, 1, "example.com.", dnsmessage.TypeA, 0))
	uc.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if _, err := uc.Read(make([]byte, 512)); err == nil {
		t.Fatal("DNS answered for unleased source")
	}
	uc.Close()

	h.client.Store(h.d.NewClient())
	c, err := h.dial(port)
	if err != nil {
		t.Fatalf("leased source: %v", err)
	}
	c.Close()
}

func TestFlowCapsAndClientClose(t *testing.T) {
	lim := testLimits()
	lim.TCPPerClient = 2
	up := newFakeUpstream(t, false)
	h := newHarness(t, lim, up.addr())
	cl := h.d.NewClient()
	h.client.Store(cl)
	port, closed := holdServer(t)

	var conns []net.Conn
	for i := range 2 {
		c, err := h.dial(port)
		if err != nil {
			t.Fatalf("conn %d: %v", i, err)
		}
		conns = append(conns, c)
	}
	if c, err := h.dial(port); err == nil {
		c.Close()
		t.Fatal("per-client TCP cap not enforced")
	}
	if tcp, _ := cl.Flows(); tcp != 2 || h.d.Stats().TCPFlows != 2 {
		t.Fatalf("flows: client %d, global %d", tcp, h.d.Stats().TCPFlows)
	}

	cl.Close()
	for i := range 2 {
		select {
		case <-closed:
		case <-time.After(3 * time.Second):
			t.Fatalf("upstream conn %d not closed by Client.Close", i)
		}
	}
	if h.d.Stats().TCPFlows != 0 || h.d.admit(cl, false) != nil {
		t.Fatal("closed client still has or accepts flows")
	}
	for _, c := range conns {
		c.Close()
	}
}

func TestAdmitLimits(t *testing.T) {
	lim := testLimits()
	lim.UDPPerClient, lim.UDPGlobal = 3, 4
	d, err := New(Config{Prefix: gwPrefix, MTU: 1280, Limits: lim})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	a, b := d.NewClient(), d.NewClient()
	for i := range 3 {
		if d.admit(a, true) == nil {
			t.Fatalf("a flow %d refused", i)
		}
	}
	if d.admit(a, true) != nil {
		t.Fatal("per-client UDP cap")
	}
	f := d.admit(b, true)
	if f == nil || d.admit(b, true) != nil {
		t.Fatal("global UDP cap")
	}
	f.close()
	f.close() // idempotent
	if d.admit(b, true) == nil {
		t.Fatal("slot not released")
	}

	lim.FlowRate, lim.FlowBurst = 0, 2
	d2, err := New(Config{Prefix: gwPrefix, MTU: 1280, Limits: lim})
	if err != nil {
		t.Fatal(err)
	}
	defer d2.Close()
	c := d2.NewClient()
	if d2.admit(c, false) == nil || d2.admit(c, false) == nil || d2.admit(c, false) != nil {
		t.Fatal("new-flow rate limit")
	}

	// Device.Close closes every client.
	d.Close()
	if d.admit(a, false) != nil || d.Stats().UDPFlows != 0 {
		t.Fatal("flows survive Device.Close")
	}
	if nc := d.NewClient(); d.admit(nc, false) != nil {
		t.Fatal("client created after Close accepts flows")
	}
}

type closeCounter struct{ n atomic.Int32 }

func (c *closeCounter) Close() error { c.n.Add(1); return nil }

func TestIdleTimeout(t *testing.T) {
	d, err := New(Config{Prefix: gwPrefix, MTU: 1280, Limits: testLimits()})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	cl := d.NewClient()
	idle, busy := d.admit(cl, true), d.admit(cl, true)
	var ci, cb closeCounter
	idle.attach(200*time.Millisecond, &ci)
	busy.attach(200*time.Millisecond, &cb)
	for range 10 {
		time.Sleep(50 * time.Millisecond)
		busy.touch()
	}
	if ci.n.Load() != 1 || !idle.isClosed() {
		t.Fatal("idle flow not closed")
	}
	if cb.n.Load() != 0 || busy.isClosed() {
		t.Fatal("active flow closed")
	}
	time.Sleep(500 * time.Millisecond)
	if cb.n.Load() != 1 {
		t.Fatal("flow not closed after going idle")
	}
	if _, udp := cl.Flows(); udp != 0 {
		t.Fatalf("%d UDP flows left", udp)
	}
}

func TestRedactedTypes(t *testing.T) {
	d, err := New(Config{Prefix: gwPrefix, MTU: 1280, Limits: testLimits()})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	c := d.NewClient()
	f := d.admit(c, false)
	for _, v := range []any{c, f, &query{}} {
		if s := fmt.Sprintf("%v %s", v, v); s != "<redacted> <redacted>" {
			t.Errorf("%T formats as %q", v, s)
		}
	}
}
