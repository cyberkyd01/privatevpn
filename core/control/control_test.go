package control

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/cyberkyd01/private-vpn-pro/core/eventlog"
	"github.com/cyberkyd01/private-vpn-pro/core/wire"
)

type fakeHandler struct {
	mu     sync.Mutex
	joins  int
	leaves int
	token  [16]byte
	code   wire.ErrCode
}

func (h *fakeHandler) Join(pub [32]byte, mtu int) (JoinResult, wire.ErrCode) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.joins++
	if h.code != wire.ErrNone {
		return JoinResult{}, h.code
	}
	return JoinResult{
		Assigned: netip.MustParseAddr("10.77.42.2"), GatewayIP: netip.MustParseAddr("10.77.42.1"),
		DNS: netip.MustParseAddr("10.77.42.1"), WGPort: 51820, MTU: 1280, Keepalive: 25,
		LeaseSec: 120, Token: h.token,
	}, wire.ErrNone
}

func (h *fakeHandler) Renew(pub [32]byte, tok [16]byte) (uint32, bool, wire.ErrCode) {
	if tok != h.token {
		return 0, false, wire.ErrUnknownLease
	}
	return 120, true, wire.ErrNone
}

func (h *fakeHandler) Leave(pub [32]byte, tok [16]byte) {
	h.mu.Lock()
	h.leaves++
	h.mu.Unlock()
}

func (h *fakeHandler) Info() []byte { return []byte(`{"v":1,"name":"test"}`) }

func startServer(t *testing.T, key [32]byte, h Handler) (*Server, netip.AddrPort) {
	t.Helper()
	s, err := Listen(ServerConfig{Port: 0, ControlKey: key, GatewayPub: [32]byte{9}, Handler: h, Log: eventlog.New(10)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s, netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(s.Port()))
}

func TestJoinRenewInfoLeave(t *testing.T) {
	key := [32]byte{1, 2, 3}
	h := &fakeHandler{token: [16]byte{7}}
	s, addr := startServer(t, key, h)
	c := NewClient(key)
	ctx := context.Background()

	resp, err := c.Join(ctx, addr, [32]byte{5}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Assigned.String() != "10.77.42.2" || resp.GatewayPub != [32]byte{9} || resp.LeaseToken != h.token {
		t.Fatalf("join resp %+v", resp)
	}
	rr, err := c.Renew(ctx, addr, [32]byte{5}, h.token)
	if err != nil || rr.LeaseSec != 120 || rr.Flags&wire.JoinFlagLANAccess == 0 {
		t.Fatalf("renew %+v %v", rr, err)
	}
	_, err = c.Renew(ctx, addr, [32]byte{5}, [16]byte{1})
	var re *RemoteError
	if !errors.As(err, &re) || re.Code != wire.ErrUnknownLease {
		t.Fatalf("renew with wrong token: %v", err)
	}
	info, err := c.Info(ctx, addr)
	if err != nil || string(info) != `{"v":1,"name":"test"}` {
		t.Fatalf("info %q %v", info, err)
	}
	if err := c.Leave(addr, [32]byte{5}, h.token); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		h.mu.Lock()
		n := h.leaves
		h.mu.Unlock()
		if n == 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if h.leaves != 1 {
		t.Fatal("leave not delivered")
	}
	if st := s.Stats(); st.AuthFailures != 0 {
		t.Fatalf("unexpected auth failures %+v", st)
	}
}

func TestWrongKeyIsSilent(t *testing.T) {
	h := &fakeHandler{}
	s, addr := startServer(t, [32]byte{1}, h)
	old := infoSchedule
	infoSchedule = []time.Duration{200 * time.Millisecond}
	defer func() { infoSchedule = old }()
	_, err := NewClient([32]byte{2}).Info(context.Background(), addr)
	if !errors.Is(err, ErrTimeout) {
		t.Fatalf("want timeout, got %v", err)
	}
	if s.Stats().AuthFailures == 0 {
		t.Fatal("auth failure not counted")
	}
}

func TestReplayAndStaleDropped(t *testing.T) {
	key := [32]byte{4}
	h := &fakeHandler{}
	s, addr := startServer(t, key, h)
	a := wire.NewAEAD(key)
	conn, err := net.ListenUDP("udp4", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	d, _, _ := wire.Seal(a, wire.TypeJoinReq, wire.JoinReq{TS: uint64(time.Now().Unix())}.Marshal(), nil)
	stale, _, _ := wire.Seal(a, wire.TypeJoinReq, wire.JoinReq{TS: uint64(time.Now().Add(-5 * time.Minute).Unix())}.Marshal(), nil)
	for _, b := range [][]byte{d, d, d, stale} {
		conn.WriteToUDPAddrPort(b, addr)
	}
	time.Sleep(300 * time.Millisecond)
	h.mu.Lock()
	joins := h.joins
	h.mu.Unlock()
	if joins != 1 {
		t.Fatalf("handler saw %d joins, want 1 (replays and stale must be dropped)", joins)
	}
	if s.Stats().Replays != 2 {
		t.Fatalf("replays = %d", s.Stats().Replays)
	}
}

func TestBanAfterAuthFailures(t *testing.T) {
	h := &fakeHandler{}
	s, addr := startServer(t, [32]byte{1}, h)
	bad := wire.NewAEAD([32]byte{2})
	conn, _ := net.ListenUDP("udp4", nil)
	defer conn.Close()
	// Rate limits cap JOINs at burst 10 per source, so use RENEW (burst 20)
	// spread over time to accumulate 30 failures.
	for i := 0; i < authFailLimit; i++ {
		d, _, _ := wire.Seal(bad, wire.TypeRenewReq, wire.LeaseReq{TS: uint64(time.Now().Unix())}.Marshal(), nil)
		conn.WriteToUDPAddrPort(d, addr)
		time.Sleep(110 * time.Millisecond)
	}
	time.Sleep(100 * time.Millisecond)
	s.mu.Lock()
	ps := s.peers[netip.MustParseAddr("127.0.0.1")]
	banned := ps != nil && time.Now().Before(ps.bannedUntil)
	s.mu.Unlock()
	if !banned {
		t.Fatalf("source not banned after %d failures (stats %+v)", authFailLimit, s.Stats())
	}
}

func TestPeerTableEvictsOldestSource(t *testing.T) {
	s, _ := startServer(t, [32]byte{1}, &fakeHandler{})
	now := time.Now()
	// A flood from perIPMax spoofed addresses fills the table; every entry
	// is "recent", so nothing is stale.
	for i := 0; i < perIPMax; i++ {
		src := netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)})
		s.peer(src, now.Add(time.Duration(i)*time.Millisecond))
	}
	newcomer := netip.MustParseAddr("192.0.2.1")
	ps := s.peer(newcomer, now.Add(time.Second))
	s.mu.Lock()
	defer s.mu.Unlock()
	if ps == nil || s.peers[newcomer] != ps {
		t.Fatal("new source refused while the table is full")
	}
	if len(s.peers) != perIPMax {
		t.Fatalf("table size %d, want %d", len(s.peers), perIPMax)
	}
	if _, ok := s.peers[netip.AddrFrom4([4]byte{10, 0, 0, 0})]; ok {
		t.Fatal("least recently seen source not evicted")
	}
}

func TestInfoGlobalLimit(t *testing.T) {
	key := [32]byte{6}
	s, _ := startServer(t, key, &fakeHandler{})
	a := wire.NewAEAD(key)
	// 60 INFO requests from 60 sources: per-source limits never trigger,
	// the 20/s (burst 40) total does.
	for i := 1; i <= 60; i++ {
		d, _, _ := wire.Seal(a, wire.TypeInfoReq, wire.InfoReq{TS: uint64(time.Now().Unix())}.Marshal(), nil)
		s.handle(d, netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, byte(i)}), 40000))
	}
	if st := s.Stats(); st.Dropped != 20 || st.AuthFailures != 0 {
		t.Fatalf("stats %+v, want 20 dropped by the INFO total limit", st)
	}
}

func TestErrorFromGateway(t *testing.T) {
	key := [32]byte{3}
	_, addr := startServer(t, key, &fakeHandler{code: wire.ErrPoolFull})
	_, err := NewClient(key).Join(context.Background(), addr, [32]byte{1}, 0)
	var re *RemoteError
	if !errors.As(err, &re) || re.Code != wire.ErrPoolFull {
		t.Fatalf("want pool_full, got %v", err)
	}
}

func TestValidateJoinResp(t *testing.T) {
	good := wire.JoinResp{
		Assigned: netip.MustParseAddr("10.77.1.2"), GatewayIP: netip.MustParseAddr("10.77.1.1"),
		PrefixLen: 24, GatewayPub: [32]byte{1}, MTU: 1280, LeaseSec: 120, WGPort: 51820, Keepalive: 25,
	}
	if err := ValidateJoinResp(good); err != nil {
		t.Fatal(err)
	}
	bad := good
	bad.Assigned = netip.MustParseAddr("8.8.8.8")
	if ValidateJoinResp(bad) == nil {
		t.Fatal("public tunnel address accepted")
	}
	bad = good
	bad.GatewayIP = netip.MustParseAddr("10.77.2.1")
	if ValidateJoinResp(bad) == nil {
		t.Fatal("cross-subnet accepted")
	}
}
