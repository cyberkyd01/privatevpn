package gateway

import (
	"bytes"
	"encoding/hex"
	"net/netip"
	"sync"
)

// Dual role (§7.4): while this device's own client tunnel is up, replies to
// a client whose WireGuard endpoint is public and off-link would follow the
// tunnel's routes. EndpointHook adds a /32 for such endpoints via the
// physical gateway. Endpoints are learned from wireguard-go every
// endpointInterval; routes are reference-counted (clients behind one NAT
// share an address).

// checkEndpoints reconciles learned endpoints with requested routes.
func (g *Gateway) checkEndpoints() { g.reconcileEndpoints(g.peerEndpoints()) }

func (g *Gateway) reconcileEndpoints(eps map[[32]byte]netip.Addr) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return
	}
	for _, l := range g.table.byKey {
		ep := eps[l.pub]
		want := g.offLink(ep)
		if ep == l.endpoint && want == l.routed {
			continue
		}
		g.unrouteLocked(l)
		l.endpoint = ep
		if want {
			g.routeLocked(l)
		}
	}
}

// offLink reports whether ep needs a host route: public IPv4 and not inside
// one of the host's on-link subnets.
func (g *Gateway) offLink(ep netip.Addr) bool {
	if !ep.Is4() || !ep.IsGlobalUnicast() || ep.IsPrivate() || cgnat.Contains(ep) {
		return false
	}
	if p := g.onLink.Load(); p != nil {
		for _, pfx := range *p {
			if pfx.Contains(ep) {
				return false
			}
		}
	}
	return true
}

func (g *Gateway) routeLocked(l *lease) {
	g.routes[l.endpoint]++
	if g.routes[l.endpoint] == 1 {
		g.hooks.push(l.endpoint, true)
	}
	l.routed = true
}

func (g *Gateway) unrouteLocked(l *lease) {
	if !l.routed {
		return
	}
	l.routed = false
	if n := g.routes[l.endpoint] - 1; n > 0 {
		g.routes[l.endpoint] = n
		return
	}
	delete(g.routes, l.endpoint)
	g.hooks.push(l.endpoint, false)
}

// peerEndpoints reads each peer's current endpoint from wireguard-go. The
// UAPI dump also holds the private key, so the buffer is wiped.
func (g *Gateway) peerEndpoints() map[[32]byte]netip.Addr {
	var buf bytes.Buffer
	buf.Grow(1024 + 512*g.ClientCount())
	err := g.wg.IpcGetOperation(&buf)
	raw := buf.Bytes()
	defer clear(raw[:cap(raw)])
	if err != nil {
		return nil
	}
	out := map[[32]byte]netip.Addr{}
	var cur [32]byte
	have := false
	for b := raw; len(b) > 0; {
		var line []byte
		line, b, _ = bytes.Cut(b, []byte{'\n'})
		k, v, ok := bytes.Cut(line, []byte{'='})
		if !ok {
			continue
		}
		switch string(k) {
		case "public_key":
			n, err := hex.Decode(cur[:], v)
			have = err == nil && n == len(cur)
		case "endpoint":
			if ap, err := netip.ParseAddrPort(string(v)); have && err == nil {
				out[cur] = ap.Addr().Unmap()
			}
		}
	}
	return out
}

// hookQueue runs EndpointHook calls in order on one goroutine, so a slow
// hook (helper IPC) never blocks the lease table.
type hookQueue struct {
	fn   func(netip.Addr, bool)
	mu   sync.Mutex
	ops  []hookOp
	wake chan struct{}
	quit chan struct{}
	done chan struct{}
}

type hookOp struct {
	ep  netip.Addr
	add bool
}

func newHookQueue(fn func(netip.Addr, bool)) *hookQueue {
	q := &hookQueue{fn: fn}
	if fn == nil {
		return q
	}
	q.wake = make(chan struct{}, 1)
	q.quit = make(chan struct{})
	q.done = make(chan struct{})
	go q.run()
	return q
}

func (q *hookQueue) push(ep netip.Addr, add bool) {
	if q.fn == nil {
		return
	}
	q.mu.Lock()
	q.ops = append(q.ops, hookOp{ep, add})
	q.mu.Unlock()
	select {
	case q.wake <- struct{}{}:
	default:
	}
}

func (q *hookQueue) run() {
	defer close(q.done)
	for {
		select {
		case <-q.wake:
			q.drain()
		case <-q.quit:
			q.drain()
			return
		}
	}
}

func (q *hookQueue) drain() {
	for {
		q.mu.Lock()
		ops := q.ops
		q.ops = nil
		q.mu.Unlock()
		if len(ops) == 0 {
			return
		}
		for _, op := range ops {
			q.fn(op.ep, op.add)
		}
	}
}

// close runs the pending calls (route removals at shutdown) and stops.
func (q *hookQueue) close() {
	if q.fn == nil {
		return
	}
	close(q.quit)
	<-q.done
}
