// Package gwstack is the gateway data plane (ARCHITECTURE §8): a gVisor IPv4
// stack exposed to wireguard-go as a tun.Device, acting as a router whose
// TCP and UDP forwarders terminate client flows and re-originate them with
// ordinary OS sockets (bound per core/netbind), plus the DNS forwarder on the
// gateway address and the destination policy.
//
// Nothing here logs: client addresses, destinations and DNS names never
// leave this package.
package gwstack

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/time/rate"
	"golang.zx2c4.com/wireguard/tun"
	"gvisor.dev/gvisor/pkg/buffer"
	glog "gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

const (
	nicID     = 1
	queueSize = 512
	ifName    = "pvn-gw"
)

// gVisor logs to stderr through a process-wide logger, some of it captured
// by package-level loggers at init; point it at nothing (§12.1). Package
// init is single-threaded, so replacing the emitter here is safe.
func init() {
	l := glog.Log()
	l.SetLevel(glog.Warning)
	l.Emitter = discard{}
	glog.SetTarget(discard{})
}

type discard struct{}

func (discard) Emit(int, glog.Level, time.Time, string, ...any) {}

// Limits bounds per-client and global resource use (§8.7).
type Limits struct {
	TCPPerClient, TCPGlobal int
	UDPPerClient, UDPGlobal int
	FlowRate                float64 // new flows per second per client
	FlowBurst               int
	TCPMaxInFlight          int // SYNs with a dial in progress
	TCPDialTimeout          time.Duration
	TCPIdle                 time.Duration
	UDPIdle                 time.Duration
	DNSIdle                 time.Duration // UDP flows to port 53 and DNS-forwarder flows
	DNSRate                 float64       // queries per second per client
	DNSBurst                int
	DNSTimeout              time.Duration
	DNSInFlight             int // concurrent upstream queries per client
	// TCPBufferSize caps each gVisor TCP endpoint's send and receive buffer
	// (0 = defaultTCPBuffer). gVisor's own default is 1 MiB each, growing
	// to 4 MiB, which at the flow caps lets one member exhaust memory with
	// stalled flows.
	TCPBufferSize int
}

const defaultTCPBuffer = 256 << 10

// Config configures a Device.
type Config struct {
	// Prefix is the gateway address within its subnet, e.g. 10.77.42.1/24.
	Prefix netip.Prefix
	MTU    int
	Limits Limits
	// Lookup returns the forwarding state of the client currently leased src,
	// or nil. It is called on the packet path and must not block.
	Lookup func(src netip.Addr) *Client
	// DNSUpstreams is called per query; empty means 1.1.1.1:53, 9.9.9.9:53.
	DNSUpstreams func() []netip.AddrPort
	// RedirectForTesting maps a policy-approved destination to the address
	// actually dialled (tests point a TEST-NET address at a local server).
	// It is ignored outside test binaries.
	RedirectForTesting func(netip.AddrPort) netip.AddrPort
}

// Stats are aggregate counters.
type Stats struct {
	TCPFlows, UDPFlows int
	RxBytes, TxBytes   uint64 // IP bytes from / to clients
}

// Device is the gVisor stack as a tun.Device (§8.1).
type Device struct {
	cfg      Config
	gw       netip.Addr
	policy   *Policy
	redirect func(netip.AddrPort) netip.AddrPort // tests only
	dns      *dnsForwarder
	ep       *channel.Endpoint
	stack    *stack.Stack
	events   chan tun.Event
	ctx      context.Context
	cancel   context.CancelFunc

	tcpFlows, udpFlows atomic.Int64
	rxBytes, txBytes   atomic.Uint64

	mu        sync.Mutex
	clients   map[*Client]struct{}
	closed    bool
	closeOnce sync.Once
}

var _ tun.Device = (*Device)(nil)

// New builds the stack. The caller hands the Device to wireguard-go, which
// closes it.
func New(cfg Config) (*Device, error) {
	gw := cfg.Prefix.Addr()
	if !gw.Is4() || cfg.Prefix.Bits() < 8 || cfg.Prefix.Bits() > 30 {
		return nil, errors.New("gwstack: invalid gateway prefix")
	}
	if cfg.MTU < 576 {
		return nil, errors.New("gwstack: invalid MTU")
	}
	ctx, cancel := context.WithCancel(context.Background())
	d := &Device{
		cfg:     cfg,
		gw:      gw,
		policy:  NewPolicy(gw, cfg.Prefix),
		ep:      channel.New(queueSize, uint32(cfg.MTU), ""),
		events:  make(chan tun.Event, 1),
		ctx:     ctx,
		cancel:  cancel,
		clients: map[*Client]struct{}{},
	}
	if testing.Testing() {
		d.redirect = cfg.RedirectForTesting
	}
	d.cfg.RedirectForTesting = nil
	d.dns = &dnsForwarder{upstreams: cfg.DNSUpstreams, timeout: cfg.Limits.DNSTimeout}
	d.stack = stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol4},
		HandleLocal:        false,
	})
	if err := d.setup(); err != nil {
		d.stack.Close()
		cancel()
		return nil, err
	}
	d.events <- tun.EventUp
	return d, nil
}

func (d *Device) setup() error {
	s := d.stack
	sack := tcpip.TCPSACKEnabled(true)
	if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, &sack); err != nil {
		return fmt.Errorf("gwstack: SACK: %v", err)
	}
	// Bounded per-flow memory (§8.7): fixed-size buffers, no auto-tuning.
	bufSize := d.cfg.Limits.TCPBufferSize
	if bufSize <= 0 {
		bufSize = defaultTCPBuffer
	}
	bufSize = max(bufSize, tcp.MinBufferSize)
	moderate := tcpip.TCPModerateReceiveBufferOption(false)
	rcv := tcpip.TCPReceiveBufferSizeRangeOption{Min: tcp.MinBufferSize, Default: bufSize, Max: bufSize}
	snd := tcpip.TCPSendBufferSizeRangeOption{Min: tcp.MinBufferSize, Default: bufSize, Max: bufSize}
	for _, opt := range []tcpip.SettableTransportProtocolOption{&moderate, &rcv, &snd} {
		if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, opt); err != nil {
			return fmt.Errorf("gwstack: TCP buffers: %v", err)
		}
	}
	if err := s.CreateNIC(nicID, d.ep); err != nil {
		return fmt.Errorf("gwstack: CreateNIC: %v", err)
	}
	addr := tcpip.ProtocolAddress{
		Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   tcpip.AddrFrom4(d.gw.As4()),
			PrefixLen: d.cfg.Prefix.Bits(),
		},
	}
	if err := s.AddProtocolAddress(nicID, addr, stack.AddressProperties{}); err != nil {
		return fmt.Errorf("gwstack: AddProtocolAddress: %v", err)
	}
	if err := s.SetPromiscuousMode(nicID, true); err != nil {
		return fmt.Errorf("gwstack: promiscuous: %v", err)
	}
	if err := s.SetSpoofing(nicID, true); err != nil {
		return fmt.Errorf("gwstack: spoofing: %v", err)
	}
	s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: nicID}})
	// No ICMP errors (port unreachable for dropped UDP, etc.); echo replies
	// are not rate limited and still work.
	s.SetICMPLimit(rate.Limit(0))
	s.SetICMPBurst(0)

	tf := tcp.NewForwarder(s, 0, d.cfg.Limits.TCPMaxInFlight, d.handleTCP)
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tf.HandlePacket)
	uf := udp.NewForwarder(s, d.handleUDP)
	s.SetTransportProtocolHandler(udp.ProtocolNumber, uf.HandlePacket)
	return nil
}

// Policy returns the destination policy.
func (d *Device) Policy() *Policy { return d.policy }

// Stats returns aggregate counters.
func (d *Device) Stats() Stats {
	return Stats{
		TCPFlows: int(d.tcpFlows.Load()),
		UDPFlows: int(d.udpFlows.Load()),
		RxBytes:  d.rxBytes.Load(),
		TxBytes:  d.txBytes.Load(),
	}
}

// NewClient returns forwarding state for a new lease. Close it when the
// lease ends.
func (d *Device) NewClient() *Client {
	l := d.cfg.Limits
	ctx, cancel := context.WithCancel(d.ctx)
	c := &Client{
		d:       d,
		ctx:     ctx,
		cancel:  cancel,
		newFlow: rate.NewLimiter(rate.Limit(l.FlowRate), l.FlowBurst),
		dnsRate: rate.NewLimiter(rate.Limit(l.DNSRate), l.DNSBurst),
		dnsSem:  make(chan struct{}, max(l.DNSInFlight, 1)),
		flows:   map[*flow]struct{}{},
	}
	d.mu.Lock()
	if d.closed {
		c.closed = true
		cancel()
	} else {
		d.clients[c] = struct{}{}
	}
	d.mu.Unlock()
	return c
}

func (d *Device) lookup(src netip.Addr) *Client {
	if d.cfg.Lookup == nil || !d.policy.subnet.Contains(src) || src == d.gw {
		return nil
	}
	return d.cfg.Lookup(src)
}

// File implements tun.Device.
func (d *Device) File() *os.File { return nil }

// Name implements tun.Device.
func (d *Device) Name() (string, error) { return ifName, nil }

// MTU implements tun.Device.
func (d *Device) MTU() (int, error) { return d.cfg.MTU, nil }

// BatchSize implements tun.Device.
func (d *Device) BatchSize() int { return 1 }

// Events implements tun.Device.
func (d *Device) Events() <-chan tun.Event { return d.events }

// Read implements tun.Device: one packet from the stack towards a client.
func (d *Device) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	pkt := d.ep.ReadContext(d.ctx)
	if pkt == nil {
		return 0, os.ErrClosed
	}
	view := pkt.ToView()
	pkt.DecRef()
	n, err := view.Read(bufs[0][offset:])
	view.Release()
	if err != nil {
		return 0, nil // empty packet; any other error would stop wireguard-go
	}
	sizes[0] = n
	d.txBytes.Add(uint64(n))
	return 1, nil
}

// Write implements tun.Device: packets from clients into the stack.
func (d *Device) Write(bufs [][]byte, offset int) (int, error) {
	for _, b := range bufs {
		pkt := b[offset:]
		if !d.admitPacket(pkt) {
			continue
		}
		d.rxBytes.Add(uint64(len(pkt)))
		pkb := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(pkt)})
		d.ep.InjectInbound(ipv4.ProtocolNumber, pkb)
		pkb.DecRef()
	}
	return len(bufs), nil
}

// admitPacket drops non-IPv4 and, because the NIC is promiscuous (gVisor
// would answer echo for any address), all ICMP except echo requests to the
// gateway from a leased client.
func (d *Device) admitPacket(pkt []byte) bool {
	if len(pkt) < header.IPv4MinimumSize || pkt[0]>>4 != 4 {
		return false
	}
	if pkt[9] != uint8(header.ICMPv4ProtocolNumber) {
		return true
	}
	dst := netip.AddrFrom4([4]byte(pkt[16:20]))
	src := netip.AddrFrom4([4]byte(pkt[12:16]))
	if !d.policy.AllowICMP(dst) || d.lookup(src) == nil {
		return false
	}
	if header.IPv4(pkt).FragmentOffset() != 0 {
		return true // tail of a datagram whose first fragment was checked
	}
	ihl := int(pkt[0]&0x0f) * 4
	return ihl >= header.IPv4MinimumSize && len(pkt) >= ihl+header.ICMPv4MinimumSize &&
		header.ICMPv4Type(pkt[ihl]) == header.ICMPv4Echo
}

// Close tears down every flow and the stack. Idempotent.
func (d *Device) Close() error {
	d.closeOnce.Do(func() {
		d.cancel()
		d.mu.Lock()
		d.closed = true
		cl := d.clients
		d.clients = nil
		d.mu.Unlock()
		for c := range cl {
			c.Close()
		}
		d.stack.RemoveNIC(nicID)
		d.stack.Close()
		d.ep.Close()
		close(d.events)
	})
	return nil
}

// target returns the address to dial for an approved destination.
func (d *Device) target(dst netip.AddrPort) string {
	if d.redirect != nil {
		dst = d.redirect(dst)
	}
	return dst.String()
}

func addrOf(a tcpip.Address) netip.Addr {
	if a.Len() != 4 {
		return netip.Addr{}
	}
	return netip.AddrFrom4(a.As4())
}
