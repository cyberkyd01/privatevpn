package beacon

import (
	"context"
	"math/rand/v2"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/ipv4"

	"github.com/cyberkyd01/private-vpn-pro/core/eventlog"
	"github.com/cyberkyd01/private-vpn-pro/core/wire"
)

// Discovery defaults (§6.2, §7.1).
const (
	Port     = 51822
	Interval = 3 * time.Second
)

// Group is the discovery multicast group.
var Group = netip.MustParseAddr("239.255.77.77")

// eligible reports whether an interface may carry beacons: up, broadcast or
// multicast capable, not loopback and not one of our tunnel interfaces.
func eligible(ifi net.Interface) bool {
	if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagLoopback != 0 {
		return false
	}
	if ifi.Flags&(net.FlagBroadcast|net.FlagMulticast) == 0 {
		return false
	}
	n := strings.ToLower(ifi.Name)
	for _, p := range []string{"pvp", "utun", "private vpn pro", "wg", "tun"} {
		if strings.HasPrefix(n, p) {
			return false
		}
	}
	return true
}

type ifaceAddr struct {
	ifi       net.Interface
	addr      netip.Addr
	broadcast netip.Addr
}

func ifaceAddrs() []ifaceAddr {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []ifaceAddr
	for _, ifi := range ifs {
		if !eligible(ifi) {
			continue
		}
		addrs, err := ifi.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip, ok := netip.AddrFromSlice(ipn.IP)
			if !ok {
				continue
			}
			ip = ip.Unmap()
			if !ip.Is4() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
				continue
			}
			ones, bits := ipn.Mask.Size()
			if bits != 32 || ones >= 31 {
				continue
			}
			v := ip.As4()
			m := net.CIDRMask(ones, 32)
			for i := 0; i < 4; i++ {
				v[i] |= ^m[i]
			}
			out = append(out, ifaceAddr{ifi: ifi, addr: ip, broadcast: netip.AddrFrom4(v)})
		}
	}
	return out
}

// Sender periodically sends beacons from the gateway's control socket.
type Sender struct {
	conn   *net.UDPConn
	pc     *ipv4.PacketConn
	build  func() (wire.Beacon, [32]byte) // body (counter/instance/ts filled here) + K_beacon
	log    *eventlog.Log
	inst   uint64
	ctr    uint32
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// StartSender begins sending. build is called for every beacon round.
func StartSender(conn *net.UDPConn, build func() (wire.Beacon, [32]byte), log *eventlog.Log) *Sender {
	if log == nil {
		log = eventlog.Default
	}
	enableBroadcast(conn)
	ctx, cancel := context.WithCancel(context.Background())
	s := &Sender{conn: conn, pc: ipv4.NewPacketConn(conn), build: build, log: log,
		inst: rand.Uint64(), cancel: cancel}
	s.pc.SetMulticastTTL(1)
	s.pc.SetMulticastLoopback(false)
	s.wg.Add(1)
	go s.run(ctx)
	return s
}

func (s *Sender) run(ctx context.Context) {
	defer s.wg.Done()
	for {
		s.sendRound()
		jitter := time.Duration(rand.Int64N(int64(Interval/5))) - Interval/10
		select {
		case <-ctx.Done():
			return
		case <-time.After(Interval + jitter):
		}
	}
}

func (s *Sender) sendRound() {
	b, k := s.build()
	s.ctr++
	b.InstanceID, b.Counter, b.TS = s.inst, s.ctr, uint64(time.Now().Unix())
	d := b.Seal(k)
	group := &net.UDPAddr{IP: Group.AsSlice(), Port: Port}
	sentBcast := map[netip.Addr]bool{}
	for _, ia := range ifaceAddrs() {
		ifi := ia.ifi
		if err := s.pc.SetMulticastInterface(&ifi); err == nil {
			s.conn.WriteToUDP(d, group)
		}
		if !sentBcast[ia.broadcast] {
			sentBcast[ia.broadcast] = true
			s.conn.WriteToUDPAddrPort(d, netip.AddrPortFrom(ia.broadcast, Port))
		}
	}
}

// Stop ends sending.
func (s *Sender) Stop() {
	s.cancel()
	s.wg.Wait()
}

// Receiver listens for beacons on 0.0.0.0:Port.
type Receiver struct {
	conn   *net.UDPConn
	pc     *ipv4.PacketConn
	onRaw  func(raw []byte, from netip.Addr)
	mu     sync.Mutex
	joined map[int]bool
	done   chan struct{}
	wg     sync.WaitGroup
}

// StartReceiver opens the discovery socket and joins the group on every
// eligible interface.
func StartReceiver(port int, onRaw func(raw []byte, from netip.Addr)) (*Receiver, error) {
	lc := net.ListenConfig{Control: reuseControl}
	pc, err := lc.ListenPacket(context.Background(), "udp4", netip.AddrPortFrom(netip.IPv4Unspecified(), uint16(port)).String())
	if err != nil {
		return nil, err
	}
	conn := pc.(*net.UDPConn)
	r := &Receiver{conn: conn, pc: ipv4.NewPacketConn(conn), onRaw: onRaw, joined: map[int]bool{}, done: make(chan struct{})}
	r.Rejoin()
	r.wg.Add(1)
	go r.run()
	return r, nil
}

// Rejoin (re)joins the multicast group on all eligible interfaces; call it
// on network changes.
func (r *Receiver) Rejoin() {
	r.mu.Lock()
	defer r.mu.Unlock()
	group := &net.UDPAddr{IP: Group.AsSlice()}
	seen := map[int]bool{}
	for _, ia := range ifaceAddrs() {
		if seen[ia.ifi.Index] {
			continue
		}
		seen[ia.ifi.Index] = true
		ifi := ia.ifi
		r.pc.LeaveGroup(&ifi, group) // ignore error: re-join cleanly after address changes
		if err := r.pc.JoinGroup(&ifi, group); err == nil {
			r.joined[ifi.Index] = true
		}
	}
}

func (r *Receiver) run() {
	defer r.wg.Done()
	buf := make([]byte, 1500)
	for {
		n, from, err := r.conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			select {
			case <-r.done:
				return
			default:
			}
			time.Sleep(20 * time.Millisecond)
			continue
		}
		if n != wire.BeaconLen {
			continue
		}
		r.onRaw(append([]byte(nil), buf[:n]...), from.Addr())
	}
}

// Close stops the receiver.
func (r *Receiver) Close() {
	select {
	case <-r.done:
		return
	default:
	}
	close(r.done)
	r.conn.Close()
	r.wg.Wait()
}
