// Package control implements the UDP control plane (ARCHITECTURE §6.3–§6.7):
// the gateway-side server and the client-side requester for JOIN, RENEW,
// LEAVE and INFO.
package control

import (
	"context"
	"crypto/cipher"
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/cyberkyd01/privatevpn/core/eventlog"
	"github.com/cyberkyd01/privatevpn/core/wire"
)

// Protocol constants (§6.7).
const (
	TimestampWindow = 60 * time.Second
	nonceTTL        = 120 * time.Second
	nonceCacheMax   = 8192
	perIPMax        = 4096
	authFailLimit   = 30
	authFailWindow  = 60 * time.Second
	banDuration     = 60 * time.Second
)

// JoinResult is what a Handler returns for an accepted JOIN.
type JoinResult struct {
	Assigned, GatewayIP, DNS netip.Addr
	WGPort, MTU, Keepalive   int
	LeaseSec                 uint32
	Token                    [16]byte
	LANAccess                bool
}

// String hides the lease token.
func (JoinResult) String() string { return "<redacted>" }

// Handler is implemented by the gateway engine.
type Handler interface {
	Join(clientPub [32]byte, mtuHint int) (JoinResult, wire.ErrCode)
	Renew(clientPub [32]byte, token [16]byte) (leaseSec uint32, lanAccess bool, code wire.ErrCode)
	Leave(clientPub [32]byte, token [16]byte)
	// Info returns the §10.5 JSON document (≤ wire.MaxInfoJSON bytes).
	Info() []byte
}

// ServerConfig configures a control server.
type ServerConfig struct {
	Port       int
	ControlKey [32]byte
	GatewayPub [32]byte
	Handler    Handler
	Log        *eventlog.Log
	// ListenConfig is optional (used for socket options).
	ListenConfig *net.ListenConfig
}

// Server is the gateway's control listener. It is silent towards anything
// that does not authenticate.
type Server struct {
	cfg    ServerConfig
	conn   *net.UDPConn
	aead   cipher.AEAD
	global *rate.Limiter
	info   *rate.Limiter // INFO total (§6.6: 20/s); the reply is ~1.2 KB and Info() is not free
	now    func() time.Time

	mu     sync.Mutex
	peers  map[netip.Addr]*peerState
	nonces map[wire.Nonce]time.Time
	order  []nonceEntry

	stats Stats
	done  chan struct{}
	wg    sync.WaitGroup
}

// Stats are aggregate counters (no addresses).
type Stats struct {
	Received, Dropped, AuthFailures, Replays, Answered uint64
}

type nonceEntry struct {
	n  wire.Nonce
	at time.Time
}

type peerState struct {
	join, info, lease *rate.Limiter
	fails             int
	failStart         time.Time
	bannedUntil       time.Time
	lastSeen          time.Time
}

// Listen opens the control socket on 0.0.0.0:Port and starts serving.
func Listen(cfg ServerConfig) (*Server, error) {
	if cfg.Handler == nil {
		return nil, errors.New("control: nil handler")
	}
	if cfg.Log == nil {
		cfg.Log = eventlog.Default
	}
	lc := cfg.ListenConfig
	if lc == nil {
		lc = &net.ListenConfig{}
	}
	pc, err := lc.ListenPacket(context.Background(), "udp4", netip.AddrPortFrom(netip.IPv4Unspecified(), uint16(cfg.Port)).String())
	if err != nil {
		return nil, err
	}
	s := &Server{
		cfg:    cfg,
		conn:   pc.(*net.UDPConn),
		aead:   wire.NewAEAD(cfg.ControlKey),
		global: rate.NewLimiter(200, 400),
		info:   rate.NewLimiter(20, 40),
		now:    time.Now,
		peers:  map[netip.Addr]*peerState{},
		nonces: map[wire.Nonce]time.Time{},
		done:   make(chan struct{}),
	}
	s.wg.Add(1)
	go s.serve()
	return s, nil
}

// Port returns the bound UDP port.
func (s *Server) Port() int { return s.conn.LocalAddr().(*net.UDPAddr).Port }

// Conn exposes the socket so beacons can be sent from the control port.
func (s *Server) Conn() *net.UDPConn { return s.conn }

// Stats returns aggregate counters.
func (s *Server) Stats() Stats {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stats
}

// Close stops the server.
func (s *Server) Close() error {
	select {
	case <-s.done:
		return nil
	default:
	}
	close(s.done)
	err := s.conn.Close()
	s.wg.Wait()
	return err
}

func (s *Server) serve() {
	defer s.wg.Done()
	buf := make([]byte, 1500)
	for {
		n, from, err := s.conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			select {
			case <-s.done:
				return
			default:
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			// Transient errors (e.g. ICMP port unreachable on Windows).
			time.Sleep(10 * time.Millisecond)
			continue
		}
		s.handle(buf[:n], from)
	}
}

func (s *Server) handle(b []byte, from netip.AddrPort) {
	now := s.now()
	src := from.Addr().Unmap()
	s.mu.Lock()
	s.stats.Received++
	s.mu.Unlock()

	if !s.global.AllowN(now, 1) {
		s.drop()
		return
	}
	t, ok := wire.PreCheck(b)
	if !ok || wire.IsResponse(t) || t == wire.TypeBeacon {
		s.drop()
		return
	}
	ps := s.peer(src, now)
	if now.Before(ps.bannedUntil) || !s.allowType(ps, t, now) {
		s.drop()
		return
	}
	_, nonce, pt, err := wire.Open(s.aead, b, nil)
	if err != nil {
		s.authFailure(ps, now)
		return
	}
	if !s.freshNonce(nonce, now) {
		s.mu.Lock()
		s.stats.Replays++
		s.mu.Unlock()
		return
	}

	switch t {
	case wire.TypeJoinReq:
		req, err := wire.ParseJoinReq(pt)
		if err != nil || !s.fresh(req.TS, now) {
			s.drop()
			return
		}
		res, code := s.cfg.Handler.Join(req.ClientPub, int(req.MTUHint))
		if code != wire.ErrNone {
			s.sendError(code, nonce, from, now)
			return
		}
		resp := wire.JoinResp{
			TS: uint64(now.Unix()), Assigned: res.Assigned, PrefixLen: 24,
			GatewayIP: res.GatewayIP, DNS: res.DNS, GatewayPub: s.cfg.GatewayPub,
			WGPort: uint16(res.WGPort), MTU: uint16(res.MTU), Keepalive: uint16(res.Keepalive),
			LeaseSec: res.LeaseSec, LeaseToken: res.Token,
		}
		if res.LANAccess {
			resp.Flags |= wire.JoinFlagLANAccess
		}
		s.reply(wire.TypeJoinResp, resp.Marshal(), nonce, from)

	case wire.TypeRenewReq:
		req, err := wire.ParseLeaseReq(pt)
		if err != nil || !s.fresh(req.TS, now) {
			s.drop()
			return
		}
		leaseSec, lan, code := s.cfg.Handler.Renew(req.ClientPub, req.LeaseToken)
		if code != wire.ErrNone {
			s.sendError(code, nonce, from, now)
			return
		}
		resp := wire.RenewResp{TS: uint64(now.Unix()), LeaseSec: leaseSec}
		if lan {
			resp.Flags |= wire.JoinFlagLANAccess
		}
		s.reply(wire.TypeRenewResp, resp.Marshal(), nonce, from)

	case wire.TypeLeave:
		req, err := wire.ParseLeaseReq(pt)
		if err != nil || !s.fresh(req.TS, now) {
			s.drop()
			return
		}
		s.cfg.Handler.Leave(req.ClientPub, req.LeaseToken)

	case wire.TypeInfoReq:
		req, err := wire.ParseInfoReq(pt)
		if err != nil || !s.fresh(req.TS, now) {
			s.drop()
			return
		}
		body, err := wire.InfoResp{TS: uint64(now.Unix()), JSON: s.cfg.Handler.Info()}.Marshal()
		if err != nil {
			s.cfg.Log.Printf("control", "info document too large; not sent")
			return
		}
		s.reply(wire.TypeInfoResp, body, nonce, from)

	default:
		s.drop()
	}
}

func (s *Server) reply(t wire.Type, pt []byte, reqNonce wire.Nonce, to netip.AddrPort) {
	d, _, err := wire.Seal(s.aead, t, pt, &reqNonce)
	if err != nil {
		return
	}
	if _, err := s.conn.WriteToUDPAddrPort(d, to); err == nil {
		s.mu.Lock()
		s.stats.Answered++
		s.mu.Unlock()
	}
}

func (s *Server) sendError(code wire.ErrCode, reqNonce wire.Nonce, to netip.AddrPort, now time.Time) {
	s.reply(wire.TypeError, wire.ErrorMsg{Code: code, TS: uint64(now.Unix())}.Marshal(), reqNonce, to)
}

func (s *Server) fresh(ts uint64, now time.Time) bool {
	d := now.Sub(time.Unix(int64(ts), 0))
	return d <= TimestampWindow && d >= -TimestampWindow
}

func (s *Server) drop() {
	s.mu.Lock()
	s.stats.Dropped++
	s.mu.Unlock()
}

// peer returns the per-source state, creating it if needed. When the table
// is full (a spoofed-source flood), the least recently seen source is
// evicted: refusing new sources instead would let the flood lock real
// clients out for as long as it lasts, while an evicted source merely loses
// its limiter history.
func (s *Server) peer(src netip.Addr, now time.Time) *peerState {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ps, ok := s.peers[src]; ok {
		ps.lastSeen = now
		return ps
	}
	if len(s.peers) >= perIPMax {
		for a, ps := range s.peers {
			if now.Sub(ps.lastSeen) > authFailWindow && now.After(ps.bannedUntil) {
				delete(s.peers, a)
			}
		}
		for len(s.peers) >= perIPMax {
			var oldest netip.Addr
			var oldestAt time.Time
			for a, ps := range s.peers {
				if oldest == (netip.Addr{}) || ps.lastSeen.Before(oldestAt) {
					oldest, oldestAt = a, ps.lastSeen
				}
			}
			delete(s.peers, oldest)
		}
	}
	ps := &peerState{
		join:     rate.NewLimiter(5, 10),
		info:     rate.NewLimiter(2, 4),
		lease:    rate.NewLimiter(10, 20),
		lastSeen: now,
	}
	s.peers[src] = ps
	return ps
}

func (s *Server) allowType(ps *peerState, t wire.Type, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch t {
	case wire.TypeJoinReq:
		return ps.join.AllowN(now, 1)
	case wire.TypeInfoReq:
		return ps.info.AllowN(now, 1) && s.info.AllowN(now, 1)
	case wire.TypeRenewReq, wire.TypeLeave:
		return ps.lease.AllowN(now, 1)
	}
	return false
}

func (s *Server) authFailure(ps *peerState, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stats.AuthFailures++
	if now.Sub(ps.failStart) > authFailWindow {
		ps.failStart, ps.fails = now, 0
	}
	ps.fails++
	if ps.fails >= authFailLimit {
		ps.bannedUntil = now.Add(banDuration)
		ps.fails = 0
	}
}

// freshNonce records n and reports whether it was not seen in the last 120 s.
func (s *Server) freshNonce(n wire.Nonce, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for len(s.order) > 0 && (now.Sub(s.order[0].at) > nonceTTL || len(s.order) >= nonceCacheMax) {
		delete(s.nonces, s.order[0].n)
		s.order = s.order[1:]
	}
	if _, seen := s.nonces[n]; seen {
		return false
	}
	s.nonces[n] = now
	s.order = append(s.order, nonceEntry{n, now})
	return true
}
