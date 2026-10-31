package engine

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/cyberkyd01/privatevpn/core/api"
	"github.com/cyberkyd01/privatevpn/core/control"
	"github.com/cyberkyd01/privatevpn/core/netbind"
	"github.com/cyberkyd01/privatevpn/core/netkey"
	"github.com/cyberkyd01/privatevpn/core/state"
	"github.com/cyberkyd01/privatevpn/core/tunnel"
	"github.com/cyberkyd01/privatevpn/core/wire"
)

// Client session timing (§6.5, §9.1); atomic so tests can shorten them
// while goroutines of earlier tests wind down.
var renewNs, rejoinNs, handshakeNs atomic.Int64

func init() {
	renewNs.Store(int64(30 * time.Second))
	rejoinNs.Store(int64(5 * time.Second))
	handshakeNs.Store(int64(30 * time.Second))
}

func renewInterval() time.Duration    { return time.Duration(renewNs.Load()) }
func rejoinInterval() time.Duration   { return time.Duration(rejoinNs.Load()) }
func handshakeTimeout() time.Duration { return time.Duration(handshakeNs.Load()) }

const (
	renewFailures = 3
	// staleHandshake: WireGuard rejects session keys 180 s after the last
	// handshake; beyond this the tunnel carries nothing (traffic is held).
	staleHandshake = 200
	linuxFwMark    = 20566
)

// session is one client connection. Fields after mu are guarded by mu.
type session struct {
	gwID, name, netID, netLabel string
	pub                         [32]byte
	hasPub                      bool
	sub                         netkey.Subkeys
	eps                         []netip.AddrPort
	ctx                         context.Context
	cancel                      context.CancelFunc
	endOnce                     sync.Once

	mu            sync.Mutex
	state         string // joining | tunnel_up | connected | degraded | blocked
	ctrl          netip.AddrPort
	priv, cpub    [32]byte
	resp          wire.JoinResp
	leased        bool
	leaseOK       bool // lease currently valid at the gateway
	tunUp         bool // a tunnel (and its kill switch) is installed for this session
	tunLost       bool // the tunnel process died; its OS block may still hold
	ks            bool // the installed tunnel carries the kill switch
	connectedOnce bool
	ifname        string
	since         time.Time
	upAt          time.Time
	degradedSince time.Time
	st            tunnel.Status
	problem       *api.Error // why the session is degraded/blocked
}

func init() {
	handle(api.ClientConnect, (*core).clientConnectH)
	handle(api.ClientDisconnect, func(c *core, _ []byte) (any, *api.Error) {
		c.setResume("") // the user chose to disconnect: don't come back after a restart
		return nil, c.clientDisconnect()
	})
	handle(api.ClientSelftest, (*core).clientSelftest)
}

func (c *core) clientConnectH(args []byte) (any, *api.Error) {
	a, aerr := decode[struct {
		GatewayID string `json:"gateway_id"`
	}](args)
	if aerr != nil {
		return nil, aerr
	}
	it, aerr := c.findItem(a.GatewayID)
	if aerr != nil {
		return nil, aerr
	}
	if it.Access != "member" || it.Network == nil {
		return nil, api.Errf(api.CodeLocked, http.StatusConflict, "enter this gateway's key first")
	}
	k, ok := c.keyEntry(it.Network.ID)
	if !ok {
		return nil, api.Errf(api.CodeLocked, http.StatusConflict, "enter this gateway's key first")
	}
	eps := c.ctrlEndpoints(it)
	if len(eps) == 0 {
		return nil, api.Errf(api.CodeUnreachable, http.StatusGatewayTimeout, "%s is not reachable right now", it.Name)
	}
	c.opMu.Lock()
	defer c.opMu.Unlock()
	select {
	case <-c.stop:
		return nil, api.Errf(api.CodeConflict, http.StatusConflict, "shutting down")
	default:
	}
	c.mu.Lock()
	old, gwOn := c.sess, c.gw != nil
	c.mu.Unlock()
	if gwOn && !netbind.CanMark() {
		return nil, api.Errf(api.CodeConflict, http.StatusConflict,
			"dual role on Linux needs CAP_NET_ADMIN (setcap cap_net_admin+ep privatevpn); turn gateway mode off before connecting")
	}
	inherit := false
	if old != nil {
		// Switching gateways: keep the old tunnel (and its block) installed
		// until the new one replaces it, so there is no unprotected gap.
		inherit = c.handOver(old)
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &session{gwID: it.ID, name: it.Name, netID: it.Network.ID, netLabel: it.Network.Label,
		pub: it.pub, hasPub: it.hasPub, sub: c.subkeysFor(k), eps: eps, ctx: ctx, cancel: cancel,
		state: "joining", since: time.Now(), tunUp: inherit}
	if inherit {
		s.ifname = old.ifname
	}
	c.mu.Lock()
	c.sess, c.lastErr = s, nil
	c.mu.Unlock()
	c.log.Printf("client", "connecting to %q", it.Name)
	c.emitStatus()
	go c.runSession(s)
	return nil, nil
}

func (c *core) clientDisconnect() *api.Error {
	c.mu.Lock()
	s := c.sess
	c.mu.Unlock()
	if s != nil {
		return c.endSession(s, "")
	}
	return c.unblockLeftover()
}

// failSession reports a failure. Before a tunnel exists the session simply
// ends (nothing was protected yet). Once a tunnel is installed the session is
// held instead — the kill switch keeps traffic blocked — until the user
// explicitly disconnects (fail closed).
func (c *core) failSession(s *session, aerr *api.Error) {
	c.log.Printf("client", "connection problem: %s", aerr.Message)
	c.emitError(aerr)
	s.mu.Lock()
	hold := s.tunUp && s.ctx.Err() == nil
	if hold {
		s.state, s.problem = "blocked", aerr
		if s.degradedSince.IsZero() {
			s.degradedSince = time.Now()
		}
	}
	s.mu.Unlock()
	if hold {
		c.emitStatus()
		return
	}
	c.mu.Lock()
	if c.sess == s {
		c.lastErr = aerr
	}
	c.mu.Unlock()
	c.endSession(s, aerr.Message)
}

// tunnelLost handles the tunnel process dying (e.g. the desktop helper
// crashed): the OS-level block stays, the session is held as blocked, and a
// fresh tunnel is created only on an explicit Reconnect or Disconnect.
func (c *core) tunnelLost(s *session) {
	s.mu.Lock()
	s.tunLost = true
	s.mu.Unlock()
	c.mu.Lock()
	c.tun = nil // dead; do not Close (that would mean an explicit teardown)
	c.mu.Unlock()
	msg := "the tunnel process stopped unexpectedly — your Internet traffic stays blocked to protect your real IP; Reconnect, or Disconnect to use the Internet without the VPN"
	s.mu.Lock()
	ks := s.ks
	s.mu.Unlock()
	if !ks && !isAndroid {
		msg = "the tunnel process stopped unexpectedly — traffic is NOT protected (kill switch is off); Reconnect or Disconnect"
	}
	c.failSession(s, api.Errf("tunnel_lost", http.StatusServiceUnavailable, "%s", msg))
}

// handOver retires a session for a gateway switch without removing its
// tunnel; it reports whether a tunnel stays installed.
func (c *core) handOver(s *session) bool {
	kept := false
	s.endOnce.Do(func() {
		s.cancel()
		s.mu.Lock()
		leased, ctrl, cpub, token := s.leased, s.ctrl, s.cpub, s.resp.LeaseToken
		kept = s.tunUp
		s.leased, s.tunUp = false, false
		s.priv = [32]byte{}
		s.mu.Unlock()
		if leased {
			control.NewClient(s.sub.Control).Leave(ctrl, cpub, token)
		}
		c.mu.Lock()
		if c.sess == s {
			c.sess = nil
		}
		c.mu.Unlock()
	})
	return kept
}

func (c *core) killSwitchOn() bool {
	st := c.store.Get()
	return !isAndroid && st.Client != nil && st.Client.KillSwitch
}

func (c *core) setKillSwitchEngaged(on bool) {
	if isAndroid {
		return
	}
	c.store.Update(func(st *state.State) error {
		if st.Client != nil {
			st.Client.KillSwitchEngaged = on
		}
		return nil
	})
}

// unblockLeftover removes a block left behind by a crashed session (the
// state file says one may be installed). On desktop this starts a helper and
// may show an administrator prompt.
func (c *core) unblockLeftover() *api.Error {
	st := c.store.Get()
	if isAndroid || st.Client == nil || !st.Client.KillSwitchEngaged {
		return nil
	}
	t, err := c.getTunnel()
	if err != nil {
		return api.Errf(api.CodeElevation, http.StatusForbidden, "could not start the tunnel helper to remove the block: %v", err)
	}
	if err := t.Down(); err != nil {
		c.dropTunnel()
		return api.Errf(api.CodeElevation, http.StatusForbidden, "the block could not be removed (%s) — try again, run \"privatevpn unblock\" as administrator, or restart the computer", errClass(err))
	}
	c.setKillSwitchEngaged(false)
	netbind.SetBypass(false)
	c.log.Printf("client", "kill switch released")
	c.emitStatus()
	return nil
}

// endSession is the explicit teardown of a session (user Disconnect, app
// quit, or a failure before any tunnel existed); it runs exactly once.
func (c *core) endSession(s *session, reason string) (aerr *api.Error) {
	s.endOnce.Do(func() {
		s.cancel()
		s.mu.Lock()
		leased, tunUp, ctrl, cpub, token := s.leased, s.tunUp, s.ctrl, s.cpub, s.resp.LeaseToken
		s.leased, s.tunUp = false, false
		s.mu.Unlock()
		if leased {
			control.NewClient(s.sub.Control).Leave(ctrl, cpub, token)
		}
		if tunUp {
			t := c.currentTunnel()
			var err error
			if t == nil { // tunnel process lost: a fresh helper removes the block
				t, err = c.getTunnel()
			}
			if err == nil {
				err = t.Down()
			}
			if err != nil {
				c.log.Printf("client", "tunnel down: %s", errClass(err))
				c.dropTunnel()
				aerr = api.Errf(api.CodeElevation, http.StatusForbidden, "the tunnel could not be removed (%s) — Disconnect again, run \"privatevpn unblock\" as administrator, or restart the computer", errClass(err))
			} else {
				c.setKillSwitchEngaged(false)
			}
			netbind.SetBypass(false)
		}
		s.mu.Lock()
		s.priv = [32]byte{}
		s.mu.Unlock()
		c.mu.Lock()
		if c.sess == s {
			c.sess = nil
		}
		g := c.gw
		c.mu.Unlock()
		if g != nil {
			g.refreshPolicy()
		}
		if reason == "" {
			c.log.Printf("client", "disconnected from %q", s.name)
		}
		c.emitStatus()
	})
	return aerr
}

func (c *core) currentTunnel() tunnel.Tunnel {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.tun
}

func (c *core) getTunnel() (tunnel.Tunnel, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.tun != nil {
		return c.tun, nil
	}
	if c.e.opts.Platform.NewTunnel == nil {
		return nil, errors.New("client mode is not available on this device")
	}
	t, err := c.e.opts.Platform.NewTunnel()
	if err != nil {
		return nil, err
	}
	c.tun = t
	return t, nil
}

func (c *core) dropTunnel() {
	c.mu.Lock()
	t := c.tun
	c.tun = nil
	c.mu.Unlock()
	if t != nil {
		t.Close()
	}
}

func (c *core) join(s *session) (wire.JoinResp, netip.AddrPort, error) {
	s.mu.Lock()
	cpub := s.cpub
	s.mu.Unlock()
	cl := control.NewClient(s.sub.Control)
	var lastErr error = control.ErrTimeout
	for _, ep := range s.eps {
		ctx, cancel := context.WithTimeout(s.ctx, 8*time.Second)
		resp, err := cl.Join(ctx, ep, cpub, 0)
		cancel()
		if err == nil {
			return resp, ep, nil
		}
		lastErr = err
		if s.ctx.Err() != nil {
			break
		}
	}
	return wire.JoinResp{}, netip.AddrPort{}, lastErr
}

func joinError(name string, err error) *api.Error {
	var re *control.RemoteError
	if errors.As(err, &re) {
		switch re.Code {
		case wire.ErrPoolFull:
			return api.Errf(api.CodeConflict, http.StatusConflict, "%s is full", name)
		case wire.ErrNotAccepting:
			return api.Errf(api.CodeConflict, http.StatusConflict, "%s is not accepting connections", name)
		}
		return api.Errf(api.CodeConflict, http.StatusConflict, "%s refused the connection (%s)", name, re.Code)
	}
	return api.Errf(api.CodeUnreachable, http.StatusGatewayTimeout,
		"no answer from %s — check that both devices' clocks are correct and the gateway's firewall allows UDP", name)
}

func (c *core) runSession(s *session) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		c.failSession(s, api.Internal(err))
		return
	}
	s.mu.Lock()
	copy(s.priv[:], priv.Bytes())
	copy(s.cpub[:], priv.PublicKey().Bytes())
	s.mu.Unlock()

	resp, ep, err := c.join(s)
	if err != nil {
		if s.ctx.Err() != nil {
			return
		}
		s.mu.Lock()
		inherited := s.tunUp
		s.mu.Unlock()
		if inherited {
			// A previous tunnel is still installed and blocking: keep
			// retrying the new gateway instead of falling back to direct.
			if t, terr := c.getTunnel(); terr == nil {
				s.mu.Lock()
				s.state, s.degradedSince, s.problem = "degraded", time.Now(), joinError(s.name, err)
				s.mu.Unlock()
				c.emitStatus()
				c.sessionLoop(s, t)
				return
			}
		}
		c.failSession(s, joinError(s.name, err))
		return
	}
	if s.hasPub && resp.GatewayPub != s.pub {
		c.failSession(s, api.Errf(api.CodeConflict, http.StatusConflict, "the gateway answered with a different identity; not connecting"))
		return
	}
	// endSession decides what to release under s.mu after cancelling ctx, so
	// every "now I hold X" transition checks ctx under the same lock and
	// releases X itself if the session already ended.
	s.mu.Lock()
	ended := s.ctx.Err() != nil
	if !ended {
		s.resp, s.ctrl, s.leased = resp, ep, true
	}
	cpub := s.cpub
	s.mu.Unlock()
	if ended {
		control.NewClient(s.sub.Control).Leave(ep, cpub, resp.LeaseToken)
		return
	}
	if aerr := c.checkSubnet(resp.Assigned); aerr != nil {
		c.failSession(s, aerr)
		return
	}

	t, err := c.getTunnel()
	if err != nil {
		c.failSession(s, api.Errf(api.CodeElevation, http.StatusForbidden, "%v", err))
		return
	}
	s.mu.Lock()
	inherited := s.tunUp
	s.mu.Unlock()
	ifname, err := t.Up(c.tunnelConfig(s, resp, ep))
	if err != nil {
		if errors.Is(err, tunnel.ErrNotElevated) {
			c.e.emit(map[string]any{"type": api.EventElevationNeeded, "reason": "client"})
			c.dropTunnel()
			c.failSession(s, api.Errf(api.CodeElevation, http.StatusForbidden, "administrator approval is needed to connect"))
			return
		}
		c.undoPartialUp(t, inherited)
		c.dropTunnel()
		c.failSession(s, api.Errf(api.CodeInternal, http.StatusInternalServerError, "could not create the tunnel: %s", errClass(err)))
		return
	}
	s.mu.Lock()
	ended = s.ctx.Err() != nil
	if !ended {
		s.tunUp, s.tunLost, s.ifname, s.state = true, false, ifname, "tunnel_up"
		s.upAt, s.leaseOK = time.Now(), true
		netbind.SetBypass(true)
	}
	s.mu.Unlock()
	if ended {
		// Disconnected while the tunnel was coming up (e.g. during the
		// elevation prompt): endSession saw no tunnel, so take it down here.
		if err := t.Down(); err != nil {
			c.log.Printf("client", "tunnel down: %s", errClass(err))
		}
		return
	}
	// A tunnel (and its block) now exists for this gateway: from here on a
	// restart must come back to it unless the user disconnects — not only
	// once the first handshake succeeded.
	c.setResume(s.gwID)
	if c.killSwitchOn() {
		c.setKillSwitchEngaged(true)
	}
	netbind.RefreshPhysical(ifname)
	c.mu.Lock()
	g := c.gw
	c.mu.Unlock()
	if g != nil {
		g.refreshPolicy()
	}
	c.emitStatus()
	c.sessionLoop(s, t)
}

// undoPartialUp runs after Up failed with a live helper. A native tunnel
// installs the kill-switch block before the TUN, routes and DNS, and keeps it
// on failure; when no block was engaged before this attempt nothing was ever
// protected, so the block is lifted again (Down is idempotent) — otherwise
// the state file would say "not blocked" while the OS blocks everything. If
// that fails the engaged flag is set so the UI reports the block and
// Disconnect retries. With a block already engaged (inherited from the
// previous session or left by a crash) it stays, as fail-closed requires.
func (c *core) undoPartialUp(t tunnel.Tunnel, inherited bool) {
	st := c.store.Get()
	if isAndroid || inherited || st.Client == nil || st.Client.KillSwitchEngaged || !st.Client.KillSwitch {
		return
	}
	if err := t.Down(); err != nil {
		c.log.Printf("client", "could not undo a failed tunnel start (%s); treating the kill switch as engaged", errClass(err))
		c.setKillSwitchEngaged(true)
	}
}

// refreshEndpoints re-reads the gateway's control addresses from discovery
// before a re-JOIN: a gateway that came back with a new address (DHCP lease
// change, restart) is otherwise never reached again. Addresses seen now come
// first; the ones the session started with stay as a fallback.
func (c *core) refreshEndpoints(s *session) {
	it, aerr := c.findItem(s.gwID)
	if aerr != nil || it.Access != "member" {
		return
	}
	s.eps = mergeEndpoints(c.ctrlEndpoints(it), s.eps)
}

// mergeEndpoints returns fresh followed by the entries of old that are not
// in fresh, without duplicates.
func mergeEndpoints(fresh, old []netip.AddrPort) []netip.AddrPort {
	out := make([]netip.AddrPort, 0, len(fresh)+len(old))
	seen := make(map[netip.AddrPort]bool, len(fresh)+len(old))
	for _, list := range [][]netip.AddrPort{fresh, old} {
		for _, ep := range list {
			if !ep.IsValid() || seen[ep] {
				continue
			}
			seen[ep] = true
			out = append(out, ep)
		}
	}
	return out
}

func (c *core) tunnelConfig(s *session, resp wire.JoinResp, ep netip.AddrPort) tunnel.Config {
	s.mu.Lock()
	priv := s.priv
	s.mu.Unlock()
	cfg := tunnel.Config{
		PrivateKey: priv,
		Address:    netip.PrefixFrom(resp.Assigned, int(resp.PrefixLen)),
		DNS:        []netip.Addr{resp.DNS},
		MTU:        int(resp.MTU),
		Peer: tunnel.Peer{PublicKey: resp.GatewayPub, PresharedKey: s.sub.PSK,
			Endpoint: netip.AddrPortFrom(ep.Addr(), resp.WGPort), Keepalive: int(resp.Keepalive)},
		SinkIPv6: true,
	}
	if st := c.store.Get(); st.Client != nil && !isAndroid {
		cfg.KillSwitch, cfg.AllowLAN = st.Client.KillSwitch, st.Client.AllowLAN
	}
	s.mu.Lock()
	s.ks = cfg.KillSwitch
	s.mu.Unlock()
	if runtime.GOOS == "linux" {
		cfg.FwMark = linuxFwMark
	}
	return cfg
}

// checkSubnet refuses tunnel subnets that overlap our own gateway subnet or
// a LAN we are attached to (§7.2).
func (c *core) checkSubnet(assigned netip.Addr) *api.Error {
	p := netip.PrefixFrom(assigned, 24).Masked()
	c.mu.Lock()
	g := c.gw
	c.mu.Unlock()
	if g != nil && g.subnet.Overlaps(p) {
		return api.Errf(api.CodeConflict, http.StatusConflict, "address conflict with this device's own gateway — change one gateway's subnet in its settings")
	}
	for _, lp := range localPrefixes() {
		if lp.Overlaps(p) {
			return api.Errf(api.CodeConflict, http.StatusConflict, "address conflict with your local network — change the gateway's subnet in its settings")
		}
	}
	return nil
}

func localPrefixes() []netip.Prefix {
	var out []netip.Prefix
	ifs, _ := net.Interfaces()
	for _, ifi := range ifs {
		if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := ifi.Addrs()
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok {
				if ip, ok := netip.AddrFromSlice(ipn.IP); ok && ip.Unmap().Is4() {
					ones, _ := ipn.Mask.Size()
					if ones > 0 {
						out = append(out, netip.PrefixFrom(ip.Unmap(), ones).Masked())
					}
				}
			}
		}
	}
	return out
}

func (c *core) recordConnected(s *session) {
	now := time.Now().Unix()
	c.store.Update(func(st *state.State) error {
		if st.Client != nil && !isAndroid {
			st.Client.ResumeGatewayID = s.gwID
		}
		if s.hasPub {
			upsertKnown(st, pubID(s.pub), s.name, s.netID, now)
		}
		for i := range st.Keyring {
			if st.Keyring[i].ID == s.netID {
				st.Keyring[i].LastUsed = now
			}
		}
		return nil
	})
	c.gatewaysChanged()
}

// sessionLoop runs while a tunnel is installed: it tracks the handshake,
// renews the lease, re-joins after losing contact and never removes the
// tunnel — traffic stays inside it (blocked if the gateway is gone) until
// the user disconnects.
func (c *core) sessionLoop(s *session, t tunnel.Tunnel) {
	cl := control.NewClient(s.sub.Control)
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	nextRenew := time.Now().Add(renewInterval())
	s.mu.Lock()
	if !s.leaseOK {
		nextRenew = time.Now()
	}
	s.mu.Unlock()
	var nextEmit time.Time
	failures := 0
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-tick.C:
		}
		now := time.Now()
		st, err := t.Status()
		if err != nil {
			if s.ctx.Err() == nil {
				c.tunnelLost(s)
			}
			return
		}
		s.mu.Lock()
		s.st = st
		hsOK := st.HandshakeAgeSec >= 0 && st.HandshakeAgeSec <= staleHandshake
		prev := s.state
		switch {
		case s.leaseOK && hsOK:
			s.state, s.degradedSince, s.problem = "connected", time.Time{}, nil
		case prev == "tunnel_up" && now.Sub(s.upAt) < handshakeTimeout():
			// waiting for the first handshake
		default:
			if s.state != "degraded" {
				s.degradedSince = now
			}
			s.state = "degraded"
			if !hsOK {
				s.problem = api.Errf("no_handshake", http.StatusGatewayTimeout,
					"no WireGuard response from %s — traffic is held in the tunnel (not sent outside it); reconnecting automatically. If this persists, check that the gateway is on and its firewall allows UDP %d", s.name, s.resp.WGPort)
			} else if !s.leaseOK {
				s.problem = api.Errf(api.CodeUnreachable, http.StatusGatewayTimeout, "lost contact with %s — traffic is held in the tunnel; reconnecting automatically", s.name)
			}
		}
		first := s.state == "connected" && !s.connectedOnce
		if first {
			s.connectedOnce, s.since = true, now
		}
		cur, leaseOK := s.state, s.leaseOK
		ctrl, cpub, token := s.ctrl, s.cpub, s.resp.LeaseToken
		s.mu.Unlock()
		if first {
			c.log.Printf("client", "connected to %q", s.name)
			c.recordConnected(s)
		} else if cur != prev && cur == "connected" {
			c.log.Printf("client", "connection to %q restored", s.name)
		} else if cur != prev && cur == "degraded" {
			c.log.Printf("client", "connection to %q interrupted; traffic held", s.name)
		}
		if cur != prev || now.After(nextEmit) {
			c.emitStatus()
			nextEmit = now.Add(2 * time.Second)
		}

		if now.Before(nextRenew) {
			continue
		}
		if !leaseOK {
			nextRenew = now.Add(rejoinInterval())
			c.refreshEndpoints(s)
			resp, ep, err := c.join(s)
			if err != nil || (s.hasPub && resp.GatewayPub != s.pub) {
				continue
			}
			if aerr := c.checkSubnet(resp.Assigned); aerr != nil {
				c.failSession(s, aerr)
				return
			}
			s.mu.Lock()
			changed := resp.Assigned != s.resp.Assigned || resp.WGPort != s.resp.WGPort || ep != s.ctrl || resp.GatewayPub != s.resp.GatewayPub
			s.resp, s.ctrl, s.leased, s.leaseOK = resp, ep, true, true
			s.mu.Unlock()
			if changed {
				ifname, err := t.Up(c.tunnelConfig(s, resp, ep))
				if err != nil {
					c.failSession(s, api.Errf(api.CodeInternal, http.StatusInternalServerError,
						"could not rebuild the tunnel (%s) — traffic stays blocked; Reconnect or Disconnect", errClass(err)))
					return
				}
				if s.ctx.Err() != nil {
					t.Down() // ended during the rebuild; endSession's Down may have run first
					return
				}
				s.mu.Lock()
				s.ifname, s.upAt = ifname, time.Now()
				if s.state == "degraded" && !s.connectedOnce {
					s.state = "tunnel_up"
				}
				s.mu.Unlock()
				if c.killSwitchOn() {
					c.setKillSwitchEngaged(true)
				}
			}
			failures = 0
			nextRenew = now.Add(renewInterval())
			continue
		}
		ctx, cancel := context.WithTimeout(s.ctx, 5*time.Second)
		_, err = cl.Renew(ctx, ctrl, cpub, token)
		cancel()
		nextRenew = now.Add(renewInterval())
		var re *control.RemoteError
		switch {
		case err == nil:
			failures = 0
		case errors.As(err, &re) && re.Code == wire.ErrUnknownLease:
			failures = renewFailures // gateway restarted: re-join now
		default:
			failures++
		}
		if failures >= renewFailures {
			s.mu.Lock()
			s.leaseOK = false
			s.mu.Unlock()
			nextRenew = now
		}
	}
}

// clientSelftest checks DNS through the gateway and a TCP connection.
func (c *core) clientSelftest(_ []byte) (any, *api.Error) {
	if isAndroid {
		return nil, api.Unsupported()
	}
	c.mu.Lock()
	s := c.sess
	c.mu.Unlock()
	if s == nil {
		return nil, api.Errf(api.CodeConflict, http.StatusConflict, "not connected")
	}
	s.mu.Lock()
	dns := s.resp.DNS
	s.mu.Unlock()
	start := time.Now()
	dnsOK := dnsProbe(dns)
	tcpOK := false
	if conn, err := net.DialTimeout("tcp", "1.1.1.1:443", 5*time.Second); err == nil {
		conn.Close()
		tcpOK = true
	}
	return map[string]any{"dns_ok": dnsOK, "tcp_ok": tcpOK, "ms": time.Since(start).Milliseconds()}, nil
}

func dnsProbe(server netip.Addr) bool {
	conn, err := net.DialTimeout("udp", netip.AddrPortFrom(server, 53).String(), 3*time.Second)
	if err != nil {
		return false
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	var idb [2]byte
	rand.Read(idb[:])
	id := uint16(idb[0])<<8 | uint16(idb[1])
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: id, RecursionDesired: true})
	b.StartQuestions()
	b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName("example.com."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET})
	q, err := b.Finish()
	if err != nil {
		return false
	}
	if _, err := conn.Write(q); err != nil {
		return false
	}
	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil {
		return false
	}
	var p dnsmessage.Parser
	h, err := p.Start(buf[:n])
	return err == nil && h.ID == id && h.Response && h.RCode == dnsmessage.RCodeSuccess
}
