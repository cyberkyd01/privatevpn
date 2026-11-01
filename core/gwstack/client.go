package gwstack

import (
	"context"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cyberkyd01/private-vpn-pro/core/eventlog"
	"golang.org/x/time/rate"
)

// Client is the forwarding state of one lease: its flows, flow counters and
// rate limiters. Memory only; String() is redacted.
type Client struct {
	eventlog.Redacted

	d       *Device
	ctx     context.Context // cancelled on Close; bounds dials and DNS queries
	cancel  context.CancelFunc
	newFlow *rate.Limiter
	dnsRate *rate.Limiter
	dnsSem  chan struct{}

	mu       sync.Mutex
	closed   bool
	flows    map[*flow]struct{}
	tcp, udp int
}

// Close ends every flow of the client and rejects new ones. Idempotent.
func (c *Client) Close() {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.closed = true
	fl := make([]*flow, 0, len(c.flows))
	for f := range c.flows {
		fl = append(fl, f)
	}
	c.mu.Unlock()
	c.cancel()
	for _, f := range fl {
		f.close()
	}
	c.d.mu.Lock()
	delete(c.d.clients, c)
	c.d.mu.Unlock()
}

// Flows returns the client's open TCP and UDP flow counts.
func (c *Client) Flows() (tcp, udp int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.tcp, c.udp
}

// flow is one forwarded TCP connection or UDP association. String() is
// redacted.
type flow struct {
	eventlog.Redacted

	c    *Client
	udp  bool
	last atomic.Int64 // unix nanos of the last activity

	mu     sync.Mutex
	closed bool
	conns  []io.Closer
	idle   time.Duration
	timer  *time.Timer
}

// admit registers a new flow for c if its rate and the per-client and global
// caps allow; nil means refuse.
func (d *Device) admit(c *Client, udp bool) *flow {
	l := d.cfg.Limits
	global, gmax, pmax := &d.tcpFlows, l.TCPGlobal, l.TCPPerClient
	if udp {
		global, gmax, pmax = &d.udpFlows, l.UDPGlobal, l.UDPPerClient
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	n := &c.tcp
	if udp {
		n = &c.udp
	}
	if c.closed || *n >= pmax || !c.newFlow.Allow() {
		return nil
	}
	if global.Add(1) > int64(gmax) {
		global.Add(-1)
		return nil
	}
	*n++
	f := &flow{c: c, udp: udp}
	c.flows[f] = struct{}{}
	return f
}

// attach hands the flow its sockets and starts the idle timer. If the flow
// was closed meanwhile, the sockets are closed and attach reports false.
func (f *flow) attach(idle time.Duration, conns ...io.Closer) bool {
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		for _, c := range conns {
			c.Close()
		}
		return false
	}
	f.conns = conns
	f.idle = idle
	f.touch()
	f.timer = time.AfterFunc(idle, f.checkIdle)
	f.mu.Unlock()
	return true
}

func (f *flow) touch() { f.last.Store(time.Now().UnixNano()) }

func (f *flow) checkIdle() {
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		return
	}
	left := f.idle - time.Duration(time.Now().UnixNano()-f.last.Load())
	if left > 0 {
		f.timer.Reset(left)
		f.mu.Unlock()
		return
	}
	f.mu.Unlock()
	f.close()
}

func (f *flow) isClosed() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.closed
}

// close releases the flow's sockets and counters. Idempotent.
func (f *flow) close() {
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		return
	}
	f.closed = true
	conns := f.conns
	f.conns = nil
	if f.timer != nil {
		f.timer.Stop()
	}
	f.mu.Unlock()
	for _, c := range conns {
		c.Close()
	}
	c, d := f.c, f.c.d
	c.mu.Lock()
	delete(c.flows, f)
	if f.udp {
		c.udp--
	} else {
		c.tcp--
	}
	c.mu.Unlock()
	if f.udp {
		d.udpFlows.Add(-1)
	} else {
		d.tcpFlows.Add(-1)
	}
}
