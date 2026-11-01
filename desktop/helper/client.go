//go:build !android

package helper

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/cyberkyd01/private-vpn-pro/core/eventlog"
	"github.com/cyberkyd01/private-vpn-pro/core/tunnel"
)

// ErrHelperGone is returned once the privileged helper has exited or its
// connection broke. The Client never relaunches it by itself (that would be
// a surprise elevation prompt): on explicit user action the caller builds a
// new tunnel with New.
var ErrHelperGone = errors.New("the privileged tunnel helper has stopped; reconnect to restart it")

var errClientClosed = errors.New("helper: client closed")

// Timeouts.
var (
	connectTimeout = 60 * time.Second // elevation prompt + helper start
	upTimeout      = 90 * time.Second // first use installs the Wintun driver
	callTimeout    = 15 * time.Second
	downTimeout    = 45 * time.Second // removes WFP/pf/route objects, daemons and units
	closeTimeout   = 5 * time.Second
)

// launchFunc starts the helper and connects to it. It applies
// connectTimeout itself (on Windows only after the UAC prompt returned) and
// aborts when ctx is cancelled (Close).

// process is a launched helper (or its launcher: osascript, pkexec).
type process interface {
	Done() <-chan struct{} // closed when it has exited
	Kill()
}

type launchFunc func(ctx context.Context) (io.ReadWriteCloser, process, error)

// Client implements tunnel.Tunnel by driving one privileged helper process
// for the session (§13.5). It launches the helper lazily on the first Up.
type Client struct {
	version string
	log     *eventlog.Log
	launch  launchFunc

	opMu sync.Mutex // serialises public operations

	mu         sync.Mutex
	conn       io.ReadWriteCloser
	proc       process
	cancel     context.CancelFunc // aborts a launch in progress
	nextID     uint64
	pending    map[uint64]chan inbound
	dead       bool
	closed     bool
	hosts      map[netip.Addr]struct{} // dual-role routes, replayed to a new helper
	notify     func(tunnel.Event)
	endpointOK bool

	wmu sync.Mutex // serialises writes to conn
}

// New returns the client-mode tunnel for the unprivileged desktop process:
// a *Client that launches `exePath tunnel-helper …` elevated on first Up
// (Windows UAC, macOS administrator prompt, Linux pkexec). On Linux, when
// this process already has CAP_NET_ADMIN, it returns tunnel.NewNative
// instead (no helper, no prompt).
func New(exePath, version string, log *eventlog.Log) tunnel.Tunnel {
	return newPlatform(exePath, version, log)
}

func newClient(version string, log *eventlog.Log, launch launchFunc) *Client {
	if log == nil {
		log = eventlog.Default
	}
	return &Client{version: version, log: log, launch: launch, hosts: map[netip.Addr]struct{}{}}
}

// SetNotify implements tunnel.Notifier: fn receives helper "tunnel" events
// and an "error" event when the helper goes away. fn runs on its own
// goroutine and may call back into the Client.
func (c *Client) SetNotify(fn func(tunnel.Event)) {
	c.mu.Lock()
	c.notify = fn
	c.mu.Unlock()
}

// EndpointRouteOK implements tunnel.EndpointRouteReporter with the value of
// the last status reply.
func (c *Client) EndpointRouteOK() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.endpointOK
}

// ensure starts the helper if needed. Caller holds opMu.
func (c *Client) ensure() error {
	c.mu.Lock()
	switch {
	case c.closed:
		c.mu.Unlock()
		return errClientClosed
	case c.dead:
		c.mu.Unlock()
		return ErrHelperGone
	case c.conn != nil:
		c.mu.Unlock()
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	c.cancel = cancel
	c.mu.Unlock()

	c.log.Printf("helper", "requesting administrator rights for the client tunnel")
	conn, proc, err := c.launch(ctx)
	cancel()

	c.mu.Lock()
	c.cancel = nil
	if c.closed {
		c.mu.Unlock()
		if conn != nil {
			conn.Close()
		}
		return errClientClosed
	}
	if err != nil {
		c.mu.Unlock()
		if errors.Is(err, tunnel.ErrNotElevated) {
			c.log.Printf("helper", "elevation was refused or cancelled")
		} else {
			c.log.Printf("helper", "start failed: %v", err)
		}
		return err // not dead: a later Up may prompt again
	}
	c.conn, c.proc = conn, proc
	c.pending = map[uint64]chan inbound{}
	c.mu.Unlock()
	go c.readLoop(conn)

	resp, err := c.call(request{Op: opHello, Version: c.version}, callTimeout)
	if err != nil {
		return err
	}
	if !resp.OK {
		c.fail(false)
		if resp.Code == codeVersionMismatch {
			return fmt.Errorf("helper: version mismatch (helper %s, app %s); restart Private VPN Pro", resp.Version, c.version)
		}
		return fmt.Errorf("helper: hello refused: %s", resp.Error)
	}
	if resp.Elevated == nil || !*resp.Elevated {
		c.fail(false)
		return tunnel.ErrNotElevated
	}
	c.log.Printf("helper", "connected (version %s)", resp.Version)

	c.mu.Lock()
	hosts := make([]netip.Addr, 0, len(c.hosts))
	for h := range c.hosts {
		hosts = append(hosts, h)
	}
	c.mu.Unlock()
	for _, h := range hosts {
		if _, err := c.callOK(request{Op: opRouteAdd, Dst: h.String() + "/32"}, callTimeout); err != nil {
			c.log.Printf("helper", "replaying a host route failed: %v", err)
		}
	}
	return nil
}

func (c *Client) readLoop(conn io.ReadWriteCloser) {
	r := bufio.NewReaderSize(conn, 4096)
	for {
		line, err := readLine(r, MaxLine)
		if err != nil {
			c.fail(true)
			return
		}
		var m inbound
		if json.Unmarshal(line, &m) != nil {
			continue
		}
		if m.Ev != "" {
			c.handleEvent(m)
			continue
		}
		c.mu.Lock()
		ch, ok := c.pending[m.ID]
		delete(c.pending, m.ID)
		c.mu.Unlock()
		if ok {
			ch <- m
		}
	}
}

func (c *Client) handleEvent(m inbound) {
	switch m.Ev {
	case evLog:
		// "<RFC3339> <component>: <message>" from the helper's own log.
		msg := m.Message
		if _, rest, ok := strings.Cut(msg, " "); ok {
			msg = rest
		}
		c.log.Printf("helper", "%s", msg)
	case evTunnel:
		c.mu.Lock()
		fn := c.notify
		c.mu.Unlock()
		if fn != nil {
			// Async: the handler may call back into the Client, whose
			// replies this goroutine has to read.
			go fn(tunnel.Event{State: m.State, Message: m.Message})
		}
	}
}

// fail marks the helper as gone: closes the connection, fails pending calls
// and (if unexpected) emits an error event.
func (c *Client) fail(unexpected bool) {
	c.mu.Lock()
	if c.dead {
		c.mu.Unlock()
		return
	}
	c.dead = true
	conn, pending, fn, closed := c.conn, c.pending, c.notify, c.closed
	c.pending = nil
	c.endpointOK = false
	c.mu.Unlock()
	if conn != nil {
		conn.Close()
	}
	for _, ch := range pending {
		close(ch)
	}
	if unexpected && !closed {
		c.log.Printf("helper", "stopped")
		if fn != nil {
			go fn(tunnel.Event{State: "error", Message: "the privileged tunnel helper stopped"})
		}
	}
}

// call sends req and waits for its response.
func (c *Client) call(req request, timeout time.Duration) (inbound, error) {
	c.mu.Lock()
	if c.dead || c.conn == nil {
		c.mu.Unlock()
		return inbound{}, ErrHelperGone
	}
	c.nextID++
	req.ID = c.nextID
	ch := make(chan inbound, 1)
	c.pending[req.ID] = ch
	conn := c.conn
	c.mu.Unlock()

	b, err := marshalLine(req)
	clear(req.Config)
	if err != nil {
		c.mu.Lock()
		delete(c.pending, req.ID)
		c.mu.Unlock()
		return inbound{}, err
	}
	c.wmu.Lock()
	_, err = conn.Write(b)
	c.wmu.Unlock()
	clear(b) // may hold the session private key
	if err != nil {
		c.fail(true)
		return inbound{}, ErrHelperGone
	}
	t := time.NewTimer(timeout)
	defer t.Stop()
	select {
	case m, ok := <-ch:
		if !ok {
			return inbound{}, ErrHelperGone
		}
		return m, nil
	case <-t.C:
		// The protocol state is unknown now: drop the helper (it tears
		// the tunnel down when the connection closes).
		c.log.Printf("helper", "no reply to %s; stopping the helper", req.Op)
		c.fail(true)
		return inbound{}, ErrHelperGone
	}
}

// callOK is call plus mapping ok=false to an error.
func (c *Client) callOK(req request, timeout time.Duration) (inbound, error) {
	m, err := c.call(req, timeout)
	if err != nil {
		return m, err
	}
	if !m.OK {
		if m.Code == codeNotElevated {
			return m, tunnel.ErrNotElevated
		}
		return m, errors.New("helper: " + m.Error)
	}
	return m, nil
}

func (c *Client) state() (launched, dead, closed bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.conn != nil, c.dead, c.closed
}

// Up launches the helper if needed (elevation prompt) and brings the
// tunnel up in it.
func (c *Client) Up(cfg tunnel.Config) (string, error) {
	if err := cfg.Validate(); err != nil {
		return "", err
	}
	c.opMu.Lock()
	defer c.opMu.Unlock()
	if err := c.ensure(); err != nil {
		return "", err
	}
	js, err := json.Marshal(cfg)
	if err != nil {
		return "", err
	}
	m, err := c.callOK(request{Op: opUp, Config: js}, upTimeout)
	if err != nil {
		return "", err
	}
	return m.IfName, nil
}

func (c *Client) SetEndpoint(ep netip.AddrPort) error {
	if err := tunnel.CheckEndpoint(ep); err != nil {
		return err
	}
	c.opMu.Lock()
	defer c.opMu.Unlock()
	if err := c.live(); err != nil {
		return err
	}
	_, err := c.callOK(request{Op: opSetEndpoint, Endpoint: ep.String()}, callTimeout)
	return err
}

// live reports why no request can be sent (nil if one can).
func (c *Client) live() error {
	launched, dead, closed := c.state()
	switch {
	case closed:
		return errClientClosed
	case dead:
		return ErrHelperGone
	case !launched:
		return errors.New("helper: tunnel is not up")
	}
	return nil
}

func (c *Client) Status() (tunnel.Status, error) {
	c.opMu.Lock()
	defer c.opMu.Unlock()
	if err := c.live(); err != nil {
		return tunnel.Status{HandshakeAgeSec: -1}, err
	}
	m, err := c.callOK(request{Op: opStatus}, callTimeout)
	if err != nil {
		return tunnel.Status{HandshakeAgeSec: -1}, err
	}
	st := tunnel.Status{IfName: m.IfName, HandshakeAgeSec: -1}
	if m.HandshakeAgeSec != nil {
		st.HandshakeAgeSec = *m.HandshakeAgeSec
	}
	if m.Rx != nil {
		st.RxBytes = *m.Rx
	}
	if m.Tx != nil {
		st.TxBytes = *m.Tx
	}
	if len(m.Warnings) > 0 {
		st.Warnings = append([]string(nil), m.Warnings...)
	}
	st.KillSwitchActive = m.KillSwitchActive != nil && *m.KillSwitchActive
	c.mu.Lock()
	c.endpointOK = m.EndpointOK != nil && *m.EndpointOK
	c.mu.Unlock()
	return st, nil
}

// RouteAdd records dst (replayed if a helper starts later) and forwards it
// to a running helper.
func (c *Client) RouteAdd(dst netip.Addr) error {
	if err := tunnel.CheckPublicIPv4(dst); err != nil {
		return err
	}
	c.opMu.Lock()
	defer c.opMu.Unlock()
	c.mu.Lock()
	if _, ok := c.hosts[dst]; !ok && len(c.hosts) >= tunnel.MaxHostRoutes {
		c.mu.Unlock()
		return errors.New("helper: too many host routes")
	}
	c.hosts[dst] = struct{}{}
	c.mu.Unlock()
	return c.forwardRoute(opRouteAdd, dst)
}

func (c *Client) RouteDel(dst netip.Addr) error {
	if err := tunnel.CheckPublicIPv4(dst); err != nil {
		return err
	}
	c.opMu.Lock()
	defer c.opMu.Unlock()
	c.mu.Lock()
	delete(c.hosts, dst)
	c.mu.Unlock()
	return c.forwardRoute(opRouteDel, dst)
}

func (c *Client) forwardRoute(op string, dst netip.Addr) error {
	launched, dead, closed := c.state()
	switch {
	case closed:
		return errClientClosed
	case dead:
		return ErrHelperGone
	case !launched:
		return nil // no tunnel, no /1 routes, nothing to bypass yet
	}
	_, err := c.callOK(request{Op: op, Dst: dst.String() + "/32"}, callTimeout)
	return err
}

// Down removes the tunnel and the kill-switch block in the helper; the
// helper keeps running for the session. When no helper runs it launches one
// (elevation prompt): a block left by a crashed session can only be removed
// by a privileged process, and the engine creates a fresh Client just for
// that. After the helper died it reports ErrHelperGone (the block, if any,
// is still in place); after Close it is a no-op.
func (c *Client) Down() error {
	c.opMu.Lock()
	defer c.opMu.Unlock()
	_, dead, closed := c.state()
	switch {
	case closed:
		return nil
	case dead:
		return ErrHelperGone
	}
	if err := c.ensure(); err != nil {
		return err
	}
	_, err := c.callOK(request{Op: opDown}, downTimeout)
	return err
}

// Close sends exit, closes the connection (the helper removes the tunnel
// and exits) and waits briefly for it. It also aborts a launch in progress.
// It never lifts a kill-switch block: the engine calls Close on failure
// paths, which must stay blocked; an explicit Disconnect calls Down first.
func (c *Client) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	if c.cancel != nil {
		c.cancel()
	}
	conn, proc, dead := c.conn, c.proc, c.dead
	c.mu.Unlock()
	if conn != nil && !dead {
		_, _ = c.call(request{Op: opExit}, closeTimeout)
	}
	c.fail(false)
	if proc != nil {
		select {
		case <-proc.Done():
		case <-time.After(closeTimeout):
		}
	}
	return nil
}
