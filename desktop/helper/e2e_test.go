//go:build !android

package helper

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cyberkyd01/privatevpn/core/eventlog"
	"github.com/cyberkyd01/privatevpn/core/tunnel"
)

// fakeTunnel records what the helper asks of the native tunnel. It mirrors
// the kill-switch contract: Up(KillSwitch) installs a block, Down removes
// it (and counts), Close keeps it.
type fakeTunnel struct {
	mu     sync.Mutex
	log    *eventlog.Log
	up     bool
	block  bool
	downs  int
	cfg    tunnel.Config
	ep     netip.AddrPort
	hosts  map[netip.Addr]bool
	closed bool
	upErr  error
	notify func(tunnel.Event)
}

func newFakeTunnel(log *eventlog.Log) *fakeTunnel {
	return &fakeTunnel{log: log, hosts: map[netip.Addr]bool{}}
}

func (f *fakeTunnel) Up(cfg tunnel.Config) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.upErr != nil {
		return "", f.upErr
	}
	f.up, f.cfg, f.ep = true, cfg, cfg.Peer.Endpoint
	f.block = cfg.KillSwitch
	f.log.Printf("tunnel", "up on utun9, address %s", cfg.Address)
	return "utun9", nil
}
func (f *fakeTunnel) SetEndpoint(ep netip.AddrPort) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ep = ep
	return nil
}
func (f *fakeTunnel) Status() (tunnel.Status, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.up {
		return tunnel.Status{HandshakeAgeSec: -1}, errors.New("tunnel: not up")
	}
	return tunnel.Status{IfName: "utun9", HandshakeAgeSec: 12, RxBytes: 123, TxBytes: 456,
		Warnings: []string{tunnel.WarnDNSNotSet}, KillSwitchActive: f.block}, nil
}
func (f *fakeTunnel) RouteAdd(dst netip.Addr) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.hosts[dst] = true
	return nil
}
func (f *fakeTunnel) RouteDel(dst netip.Addr) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.hosts, dst)
	return nil
}
func (f *fakeTunnel) Down() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.up, f.block = false, false
	f.downs++
	return nil
}
func (f *fakeTunnel) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.up, f.closed = false, true // the block, if any, stays
	return nil
}
func (f *fakeTunnel) blockState() (block bool, downs int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.block, f.downs
}
func (f *fakeTunnel) SetNotify(fn func(tunnel.Event)) {
	f.mu.Lock()
	f.notify = fn
	f.mu.Unlock()
}
func (f *fakeTunnel) EndpointRouteOK() bool { return true }
func (f *fakeTunnel) fire(ev tunnel.Event) {
	f.mu.Lock()
	fn := f.notify
	f.mu.Unlock()
	if fn != nil {
		fn(ev)
	}
}
func (f *fakeTunnel) snapshot() (up, closed bool, hosts int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.up, f.closed, len(f.hosts)
}

type fakeProc struct{ done chan struct{} }

func (p *fakeProc) Done() <-chan struct{} { return p.done }
func (p *fakeProc) Kill()                 {}

// harness wires a Client to an in-process helper (serve + teardown on
// close, exactly like Run) over conn pairs made by mkConn.
type harness struct {
	c        *Client
	ft       *fakeTunnel
	clog     *eventlog.Log
	launches atomic.Int32
	server   net.Conn // helper side of the current connection
	served   chan struct{}
	mu       sync.Mutex
}

func newHarness(t *testing.T, helperVersion string, mkConn func() (client, server net.Conn)) *harness {
	h := &harness{clog: eventlog.New(200)}
	hlog := eventlog.New(200)
	h.ft = newFakeTunnel(hlog)
	h.c = newClient("1.0.0", h.clog, func(ctx context.Context) (io.ReadWriteCloser, process, error) {
		h.launches.Add(1)
		a, b := mkConn()
		p := &fakeProc{done: make(chan struct{})}
		served := make(chan struct{})
		h.mu.Lock()
		h.server, h.served = b, served
		h.mu.Unlock()
		go func() {
			_ = serve(b, h.ft, helperVersion, hlog)
			h.ft.Close() // Run's teardown on connection close
			b.Close()
			close(served)
			close(p.done)
		}()
		return a, p, nil
	})
	t.Cleanup(func() { h.c.Close() })
	return h
}

func (h *harness) killHelper() {
	h.mu.Lock()
	s, served := h.server, h.served
	h.mu.Unlock()
	s.Close()
	<-served
}

func pipePair() (net.Conn, net.Conn) { return net.Pipe() }

func testCfg(t *testing.T) tunnel.Config {
	t.Helper()
	var c tunnel.Config
	for i := range c.PrivateKey {
		c.PrivateKey[i], c.Peer.PublicKey[i], c.Peer.PresharedKey[i] = byte(i+1), byte(i+2), byte(i+3)
	}
	c.Address = netip.MustParsePrefix("10.77.42.2/24")
	c.DNS = []netip.Addr{netip.MustParseAddr("10.77.42.1")}
	c.MTU = 1280
	c.Peer.Endpoint = netip.MustParseAddrPort("192.168.1.10:51820")
	c.Peer.Keepalive = 25
	c.SinkIPv6 = true
	return c
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); time.Sleep(5 * time.Millisecond) {
		if cond() {
			return
		}
	}
	t.Fatalf("timed out waiting for %s", what)
}

func hasLine(l *eventlog.Log, sub string) bool {
	for _, line := range l.Lines() {
		if strings.Contains(line, sub) {
			return true
		}
	}
	return false
}

func TestClientHelperFlow(t *testing.T) {
	h := newHarness(t, "1.0.0", pipePair)
	c := h.c
	var events []tunnel.Event
	var evMu sync.Mutex
	c.SetNotify(func(ev tunnel.Event) { evMu.Lock(); events = append(events, ev); evMu.Unlock() })

	// Nothing launches before Up (Down is the exception, see
	// TestDownWithoutTunnelLaunchesHelper).
	if _, err := c.Status(); err == nil || h.launches.Load() != 0 {
		t.Fatalf("Status before Up: %v, launches %d", err, h.launches.Load())
	}
	if err := c.SetEndpoint(netip.MustParseAddrPort("203.0.113.9:51820")); err == nil || h.launches.Load() != 0 {
		t.Fatal("SetEndpoint before Up succeeded or launched")
	}
	cfg := testCfg(t)
	ifname, err := c.Up(cfg)
	if err != nil || ifname != "utun9" {
		t.Fatalf("Up: %q %v", ifname, err)
	}
	h.ft.mu.Lock()
	gotCfg := h.ft.cfg
	h.ft.mu.Unlock()
	if gotCfg.PrivateKey != cfg.PrivateKey || gotCfg.Peer.PresharedKey != cfg.Peer.PresharedKey || gotCfg.Address != cfg.Address || gotCfg.Peer.Endpoint != cfg.Peer.Endpoint {
		t.Fatal("config not transferred intact")
	}
	st, err := c.Status()
	want := tunnel.Status{IfName: "utun9", HandshakeAgeSec: 12, RxBytes: 123, TxBytes: 456, Warnings: []string{tunnel.WarnDNSNotSet}}
	if err != nil || !reflect.DeepEqual(st, want) || !c.EndpointRouteOK() {
		t.Fatalf("Status: %+v %v ok=%v", st, err, c.EndpointRouteOK())
	}
	if err := c.SetEndpoint(netip.MustParseAddrPort("203.0.113.9:51820")); err != nil {
		t.Fatalf("SetEndpoint: %v", err)
	}
	if err := c.RouteAdd(netip.MustParseAddr("198.51.100.7")); err != nil {
		t.Fatalf("RouteAdd: %v", err)
	}
	if err := c.RouteAdd(netip.MustParseAddr("192.168.1.50")); err == nil {
		t.Fatal("private RouteAdd accepted")
	}
	if _, _, n := h.ft.snapshot(); n != 1 {
		t.Fatalf("helper hosts = %d", n)
	}
	if err := c.RouteDel(netip.MustParseAddr("198.51.100.7")); err != nil {
		t.Fatalf("RouteDel: %v", err)
	}

	// Unsolicited events and helper log lines reach the main process.
	h.ft.fire(tunnel.Event{State: "error", Message: "lost the route to the gateway"})
	waitFor(t, "tunnel event", func() bool { evMu.Lock(); defer evMu.Unlock(); return len(events) == 1 })
	waitFor(t, "forwarded helper log", func() bool { return hasLine(h.clog, "helper: tunnel: up on utun9, address 10.77.42.2/24") })

	if err := c.Down(); err != nil {
		t.Fatalf("Down: %v", err)
	}
	if up, _, _ := h.ft.snapshot(); up {
		t.Fatal("still up after Down")
	}
	// Same helper for the session.
	if _, err := c.Up(cfg); err != nil || h.launches.Load() != 1 {
		t.Fatalf("second Up: %v, launches %d", err, h.launches.Load())
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "helper teardown on close", func() bool { _, closed, _ := h.ft.snapshot(); return closed })
	if _, err := c.Up(cfg); err == nil {
		t.Fatal("Up after Close succeeded")
	}
	evMu.Lock()
	defer evMu.Unlock()
	if len(events) != 1 {
		t.Errorf("a deliberate Close must not raise an error event: %+v", events)
	}
}

func TestRoutesReplayedToNewHelper(t *testing.T) {
	h := newHarness(t, "1.0.0", pipePair)
	if err := h.c.RouteAdd(netip.MustParseAddr("198.51.100.7")); err != nil || h.launches.Load() != 0 {
		t.Fatalf("RouteAdd before Up: %v launches %d", err, h.launches.Load())
	}
	if err := h.c.RouteDel(netip.MustParseAddr("198.51.100.8")); err != nil {
		t.Fatal(err)
	}
	if _, err := h.c.Up(testCfg(t)); err != nil {
		t.Fatal(err)
	}
	if _, _, n := h.ft.snapshot(); n != 1 {
		t.Fatalf("replayed hosts = %d, want 1", n)
	}
}

func TestHelperDeathIsFinal(t *testing.T) {
	h := newHarness(t, "1.0.0", pipePair)
	var gone atomic.Bool
	h.c.SetNotify(func(ev tunnel.Event) {
		if ev.State == "error" {
			gone.Store(true)
		}
	})
	if _, err := h.c.Up(testCfg(t)); err != nil {
		t.Fatal(err)
	}
	h.killHelper()
	waitFor(t, "helper-gone event", gone.Load)
	if _, err := h.c.Status(); !errors.Is(err, ErrHelperGone) {
		t.Fatalf("Status after death: %v", err)
	}
	if _, err := h.c.Up(testCfg(t)); !errors.Is(err, ErrHelperGone) {
		t.Fatalf("Up after death: %v", err)
	}
	if err := h.c.RouteAdd(netip.MustParseAddr("198.51.100.7")); !errors.Is(err, ErrHelperGone) {
		t.Fatalf("RouteAdd after death: %v", err)
	}
	if err := h.c.Down(); !errors.Is(err, ErrHelperGone) {
		t.Fatalf("Down after death: %v (the block may still be in place; the caller must use a fresh helper)", err)
	}
	if n := h.launches.Load(); n != 1 {
		t.Fatalf("helper relaunched automatically (%d launches)", n)
	}
	if !hasLine(h.clog, "helper: stopped") {
		t.Error("death not logged")
	}
}

func TestVersionMismatch(t *testing.T) {
	h := newHarness(t, "2.0.0", pipePair)
	_, err := h.c.Up(testCfg(t))
	if err == nil || !strings.Contains(err.Error(), "version mismatch") {
		t.Fatalf("Up: %v", err)
	}
	waitFor(t, "helper exit", func() bool { _, closed, _ := h.ft.snapshot(); return closed })
	if _, err := h.c.Up(testCfg(t)); !errors.Is(err, ErrHelperGone) || h.launches.Load() != 1 {
		t.Fatalf("second Up: %v launches %d", err, h.launches.Load())
	}
}

func TestCancelledPromptCanRetry(t *testing.T) {
	var n atomic.Int32
	c := newClient("1.0.0", eventlog.New(10), func(context.Context) (io.ReadWriteCloser, process, error) {
		n.Add(1)
		return nil, nil, tunnel.ErrNotElevated
	})
	defer c.Close()
	for i := 0; i < 2; i++ {
		if _, err := c.Up(testCfg(t)); !errors.Is(err, tunnel.ErrNotElevated) {
			t.Fatalf("Up %d: %v", i, err)
		}
	}
	if n.Load() != 2 {
		t.Fatalf("launches = %d, want 2 (a cancelled prompt is not final)", n.Load())
	}
}

func TestUpErrorPropagates(t *testing.T) {
	h := newHarness(t, "1.0.0", pipePair)
	h.ft.upErr = tunnel.ErrNotElevated
	if _, err := h.c.Up(testCfg(t)); !errors.Is(err, tunnel.ErrNotElevated) {
		t.Fatalf("not_elevated: %v", err)
	}
	h.ft.mu.Lock()
	h.ft.upErr = errors.New("tunnel: route add: exit status 1: add host 203.0.113.9: gateway 192.168.1.1")
	h.ft.mu.Unlock()
	_, err := h.c.Up(testCfg(t))
	if err == nil || strings.Contains(err.Error(), "203.0.113.9") || strings.Contains(err.Error(), "192.168.1.1") {
		t.Fatalf("error not redacted: %v", err)
	}
}

// rawSession speaks the wire protocol directly to serve.
type rawSession struct {
	t    *testing.T
	conn net.Conn
	r    *bufio.Reader
	done chan error
	ft   *fakeTunnel
}

func newRawSession(t *testing.T) *rawSession {
	a, b := net.Pipe()
	s := &rawSession{t: t, conn: a, r: bufio.NewReader(a), done: make(chan error, 1), ft: newFakeTunnel(eventlog.New(10))}
	go func() { s.done <- serve(b, s.ft, "1.0.0", eventlog.New(10)) }()
	t.Cleanup(func() { a.Close() })
	return s
}

// do sends one raw line and returns the next non-event reply.
func (s *rawSession) do(line string) map[string]any {
	s.t.Helper()
	if _, err := io.WriteString(s.conn, line+"\n"); err != nil {
		s.t.Fatalf("write: %v", err)
	}
	for {
		b, err := readLine(s.r, MaxLine)
		if err != nil {
			s.t.Fatalf("read: %v", err)
		}
		var m map[string]any
		if err := json.Unmarshal(b, &m); err != nil {
			s.t.Fatalf("bad reply %q", b)
		}
		if _, isEv := m["ev"]; !isEv {
			return m
		}
	}
}

func expectCode(t *testing.T, m map[string]any, code string) {
	t.Helper()
	if m["ok"] != false || m["code"] != code {
		t.Fatalf("got %v, want code %s", m, code)
	}
}

func TestServeValidation(t *testing.T) {
	s := newRawSession(t)
	expectCode(t, s.do(`{"id":1,"op":"status"}`), codeHelloRequired)
	expectCode(t, s.do(`{"id":2,"op":"hello"}`), codeBadRequest)
	expectCode(t, s.do(`not json`), codeBadRequest)
	m := s.do(`{"id":3,"op":"hello","version":"1.0.0"}`)
	if m["ok"] != true || m["version"] != "1.0.0" || m["elevated"] != true || m["id"] != float64(3) {
		t.Fatalf("hello: %v", m)
	}
	expectCode(t, s.do(`{"id":4,"op":"status","extra":1}`), codeBadRequest)
	expectCode(t, s.do(`{"id":5,"op":"status","dst":"203.0.113.9/32"}`), codeBadRequest)
	expectCode(t, s.do(`{"id":6,"op":"frobnicate"}`), codeBadRequest)
	for _, dst := range []string{"10.0.0.1/32", "192.168.1.1", "127.0.0.1/32", "203.0.113.0/24", "2001:db8::1/128", "224.0.0.1/32", "0.0.0.0/32", "x"} {
		expectCode(t, s.do(`{"id":7,"op":"route_add","dst":"`+dst+`"}`), codeBadRequest)
	}
	if _, _, n := s.ft.snapshot(); n != 0 {
		t.Fatal("invalid route reached the tunnel")
	}
	if m := s.do(`{"id":8,"op":"route_add","dst":"203.0.113.9/32"}`); m["ok"] != true {
		t.Fatalf("valid route_add: %v", m)
	}
	expectCode(t, s.do(`{"id":9,"op":"set_endpoint","endpoint":"[2001:db8::1]:51820"}`), codeBadRequest)
	expectCode(t, s.do(`{"id":10,"op":"up","config":{"private_key":"AA=="}}`), codeBadRequest)
	cfgJSON, _ := json.Marshal(testCfg(t))
	bad := strings.Replace(string(cfgJSON), `"mtu":1280`, `"mtu":100`, 1)
	expectCode(t, s.do(`{"id":11,"op":"up","config":`+bad+`}`), codeBadRequest)
	if m := s.do(`{"id":12,"op":"up","config":` + string(cfgJSON) + `}`); m["ok"] != true || m["ifname"] != "utun9" {
		t.Fatalf("up: %v", m)
	}
	m = s.do(`{"id":13,"op":"status"}`)
	if m["ok"] != true || m["handshake_age_sec"] != float64(12) || m["rx"] != float64(123) || m["tx"] != float64(456) || m["endpoint_ok"] != true ||
		m["kill_switch_active"] != false || !reflect.DeepEqual(m["warnings"], []any{tunnel.WarnDNSNotSet}) {
		t.Fatalf("status: %v", m)
	}
	if m := s.do(`{"id":14,"op":"down"}`); m["ok"] != true {
		t.Fatalf("down: %v", m)
	}
	// down is idempotent and fine with nothing up.
	if m := s.do(`{"id":16,"op":"down"}`); m["ok"] != true {
		t.Fatalf("second down: %v", m)
	}
	expectCode(t, s.do(`{"id":17,"op":"down","dst":"1.2.3.4"}`), codeBadRequest)
	if m := s.do(`{"id":15,"op":"exit"}`); m["ok"] != true {
		t.Fatalf("exit: %v", m)
	}
	if err := <-s.done; err != nil {
		t.Fatalf("serve after exit: %v", err)
	}
}

func TestServeLineLimitAndEOF(t *testing.T) {
	s := newRawSession(t)
	go io.WriteString(s.conn, `{"id":1,"op":"hello","version":"`+strings.Repeat("9", MaxLine)+"\"}\n")
	go io.Copy(io.Discard, s.conn)
	select {
	case err := <-s.done:
		if !errors.Is(err, errLineTooLong) {
			t.Fatalf("oversized line: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("serve did not stop on an oversized line")
	}

	s2 := newRawSession(t)
	s2.conn.Close()
	if err := <-s2.done; err != nil {
		t.Fatalf("EOF: %v", err)
	}
}

func TestServeVersionMismatchExits(t *testing.T) {
	s := newRawSession(t)
	expectCode(t, s.do(`{"id":1,"op":"hello","version":"0.9.0"}`), codeVersionMismatch)
	if err := <-s.done; err != nil {
		t.Fatalf("serve: %v", err)
	}
}

func ksCfg(t *testing.T) tunnel.Config {
	c := testCfg(t)
	c.KillSwitch, c.AllowLAN = true, true
	return c
}

// The kill switch flag travels over the wire and the status reply carries
// the warning codes and the block state.
func TestKillSwitchOverTheWire(t *testing.T) {
	h := newHarness(t, "1.0.0", pipePair)
	if _, err := h.c.Up(ksCfg(t)); err != nil {
		t.Fatal(err)
	}
	h.ft.mu.Lock()
	got := h.ft.cfg
	h.ft.mu.Unlock()
	if !got.KillSwitch || !got.AllowLAN {
		t.Fatalf("kill_switch/allow_lan not transferred: %+v", got)
	}
	st, err := h.c.Status()
	if err != nil || !st.KillSwitchActive || !reflect.DeepEqual(st.Warnings, []string{tunnel.WarnDNSNotSet}) {
		t.Fatalf("Status: %+v %v", st, err)
	}
}

// Losing the helper (pipe closed, crash) removes the tunnel but keeps the
// block: traffic must not fall back to the physical network.
func TestPipeCloseKeepsBlock(t *testing.T) {
	h := newHarness(t, "1.0.0", pipePair)
	if _, err := h.c.Up(ksCfg(t)); err != nil {
		t.Fatal(err)
	}
	h.killHelper()
	up, closed, _ := h.ft.snapshot()
	block, downs := h.ft.blockState()
	if up || !closed || !block || downs != 0 {
		t.Fatalf("after pipe close: up=%v closed=%v block=%v downs=%d; want tunnel gone, block kept", up, closed, block, downs)
	}
}

// An explicit Close (app quit without Disconnect, failure paths) exits the
// helper and keeps the block too; only Down lifts it.
func TestCloseKeepsBlockDownRemovesIt(t *testing.T) {
	h := newHarness(t, "1.0.0", pipePair)
	if _, err := h.c.Up(ksCfg(t)); err != nil {
		t.Fatal(err)
	}
	if err := h.c.Down(); err != nil {
		t.Fatalf("Down: %v", err)
	}
	if block, downs := h.ft.blockState(); block || downs != 1 {
		t.Fatalf("after Down: block=%v downs=%d", block, downs)
	}
	if _, err := h.c.Up(ksCfg(t)); err != nil {
		t.Fatal(err)
	}
	h.c.Close()
	waitFor(t, "helper exit", func() bool { _, closed, _ := h.ft.snapshot(); return closed })
	if block, downs := h.ft.blockState(); !block || downs != 1 {
		t.Fatalf("after Close: block=%v downs=%d; Close must not lift the block", block, downs)
	}
	if h.launches.Load() != 1 {
		t.Fatalf("launches = %d", h.launches.Load())
	}
}

// A fresh Client (the engine's way to remove a leftover block after a
// crash) launches a helper just to send down, and down works with no
// tunnel up.
func TestDownWithoutTunnelLaunchesHelper(t *testing.T) {
	h := newHarness(t, "1.0.0", pipePair)
	h.ft.mu.Lock()
	h.ft.block = true // leftover from an earlier session
	h.ft.mu.Unlock()
	if err := h.c.Down(); err != nil {
		t.Fatalf("Down: %v", err)
	}
	if h.launches.Load() != 1 {
		t.Fatalf("launches = %d, want 1", h.launches.Load())
	}
	if block, downs := h.ft.blockState(); block || downs != 1 {
		t.Fatalf("leftover block not removed: block=%v downs=%d", block, downs)
	}
	// Idempotent, same helper.
	if err := h.c.Down(); err != nil || h.launches.Load() != 1 {
		t.Fatalf("second Down: %v launches %d", err, h.launches.Load())
	}
	if _, downs := h.ft.blockState(); downs != 2 {
		t.Fatalf("downs = %d", downs)
	}
	// After Close, Down is a no-op (the caller makes a fresh Client).
	h.c.Close()
	if err := h.c.Down(); err != nil || h.launches.Load() != 1 {
		t.Fatalf("Down after Close: %v launches %d", err, h.launches.Load())
	}
	// A cancelled prompt is reported, not swallowed.
	c := newClient("1.0.0", eventlog.New(10), func(context.Context) (io.ReadWriteCloser, process, error) {
		return nil, nil, tunnel.ErrNotElevated
	})
	defer c.Close()
	if err := c.Down(); !errors.Is(err, tunnel.ErrNotElevated) {
		t.Fatalf("Down with refused elevation: %v", err)
	}
}
