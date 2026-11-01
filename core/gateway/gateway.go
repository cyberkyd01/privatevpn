// Package gateway is the gateway engine (ARCHITECTURE §8): the WireGuard
// device, the in-memory lease table and address pool, and the gwstack data
// plane behind it. Client state lives in process memory only and is never
// logged or persisted (§12.1).
package gateway

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cyberkyd01/private-vpn-pro/core/eventlog"
	"github.com/cyberkyd01/private-vpn-pro/core/gwstack"
	"github.com/cyberkyd01/private-vpn-pro/core/netbind"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
)

const logTag = "gateway"

// Config configures a gateway.
type Config struct {
	PrivateKey   [32]byte                      // static WireGuard key
	PresharedKey [32]byte                      // network-wide K_psk, set on every peer
	ListenPort   int                           // WireGuard UDP; 0 = 51820
	Subnet       netip.Prefix                  // /24; gateway is .1, clients .2–.254; zero = DeriveSubnet
	MTU          int                           // 0 = 1280
	LANAccess    bool                          // initial "Allow my local network"
	DNSUpstreams func() []netip.AddrPort       // called per query; empty = 1.1.1.1:53, 9.9.9.9:53
	ExtraDeny    func() []netip.Prefix         // host addresses, dual-role client-tunnel subnet; re-read by RefreshPolicy
	EndpointHook func(ep netip.Addr, add bool) // optional dual-role /32 route management for off-LAN client endpoints (§7.4)
	Log          *eventlog.Log                 // nil = eventlog.Default
}

// Lease is what JOIN/RENEW return to a client. String() is redacted.
type Lease struct {
	IP, GatewayIP netip.Addr
	Token         [16]byte
	LeaseSec      uint32
	MTU           int
	LANAccess     bool
}

func (Lease) String() string { return "<redacted>" }

// Stats are aggregate counters (§12.1 rule 5).
type Stats struct {
	Clients, TCPFlows, UDPFlows int
	RxBytes, TxBytes            uint64 // IP bytes from / to clients
}

var (
	ErrPoolFull     = errors.New("gateway: address pool full")
	ErrUnknownLease = errors.New("gateway: unknown lease")
	ErrClosed       = errors.New("gateway: closed")
	ErrInvalidKey   = errors.New("gateway: invalid client key")
	errPeerSetup    = errors.New("gateway: peer setup failed")
)

// Test hooks, set only by _test files before Start. gwstack additionally
// ignores redirectForTesting outside test binaries.
var (
	redirectForTesting func(netip.AddrPort) netip.AddrPort // dial target override for approved flows
	nowFunc            = time.Now                          // lease clock
)

var privateRanges = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
}

var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// DeriveSubnet returns 10.77.H.0/24 with H = 1 + (SHA-256("pvp1 subnet" ||
// pub)[0] mod 254) (§7.2).
func DeriveSubnet(gwPub [32]byte) netip.Prefix {
	h := sha256.Sum256(append([]byte("pvp1 subnet"), gwPub[:]...))
	return netip.PrefixFrom(netip.AddrFrom4([4]byte{10, 77, 1 + h[0]%254, 0}), 24)
}

// Gateway is a running gateway. Methods are safe for concurrent use.
type Gateway struct {
	cfg    Config
	log    *eventlog.Log
	pub    [32]byte
	subnet netip.Prefix
	gwIP   netip.Addr
	mtu    int
	port   int
	stack  *gwstack.Device
	wg     *device.Device
	hooks  *hookQueue
	now    func() time.Time

	mu     sync.Mutex
	closed bool
	table  *leaseTable
	routes map[netip.Addr]int // EndpointHook refcount per endpoint

	// ipMu guards byIP, read on the packet path. It is never held across a
	// wireguard-go call: peer removal waits for the peer's receive goroutine,
	// which may be inside gwstack waiting for this lock.
	ipMu sync.RWMutex
	byIP map[netip.Addr]*gwstack.Client

	onLink atomic.Pointer[[]netip.Prefix]
	stop   chan struct{}
	loops  sync.WaitGroup
}

// Start brings up the gVisor stack and the WireGuard device on ListenPort
// (all addresses, never interface-bound).
func Start(cfg Config) (*Gateway, error) {
	if cfg.PrivateKey == ([32]byte{}) {
		return nil, errors.New("gateway: missing private key")
	}
	sk, err := ecdh.X25519().NewPrivateKey(cfg.PrivateKey[:])
	if err != nil {
		return nil, errors.New("gateway: invalid private key")
	}
	g := &Gateway{
		cfg:    cfg,
		log:    cfg.Log,
		mtu:    cfg.MTU,
		port:   cfg.ListenPort,
		now:    nowFunc,
		routes: map[netip.Addr]int{},
		byIP:   map[netip.Addr]*gwstack.Client{},
		stop:   make(chan struct{}),
	}
	copy(g.pub[:], sk.PublicKey().Bytes())
	if g.log == nil {
		g.log = eventlog.Default
	}
	g.subnet = cfg.Subnet
	if !g.subnet.IsValid() {
		g.subnet = DeriveSubnet(g.pub)
	}
	if err := validSubnet(g.subnet); err != nil {
		return nil, err
	}
	g.subnet = g.subnet.Masked()
	g.gwIP = g.subnet.Addr().Next()
	if g.mtu == 0 {
		g.mtu = defaultMTU
	}
	if g.mtu < minMTU || g.mtu > 1420 {
		return nil, errors.New("gateway: MTU out of range")
	}
	if g.port == 0 {
		g.port = defaultListenPort
	}
	if g.port < 1 || g.port > 65535 {
		return nil, errors.New("gateway: invalid listen port")
	}
	g.table = newLeaseTable(g.subnet)

	g.stack, err = gwstack.New(gwstack.Config{
		Prefix:             netip.PrefixFrom(g.gwIP, g.subnet.Bits()),
		MTU:                g.mtu,
		Limits:             stackLimits(),
		Lookup:             g.lookup,
		DNSUpstreams:       cfg.DNSUpstreams,
		RedirectForTesting: redirectForTesting,
	})
	if err != nil {
		return nil, err
	}
	g.stack.Policy().SetLANAccess(cfg.LANAccess)
	g.refreshPolicy()

	g.wg = device.NewDevice(g.stack, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	if err := g.wg.IpcSet("private_key=" + hex.EncodeToString(cfg.PrivateKey[:]) + "\nlisten_port=" + strconv.Itoa(g.port) + "\n"); err != nil {
		g.wg.Close()
		return nil, errors.New("gateway: WireGuard configuration failed")
	}
	if err := g.wg.Up(); err != nil {
		g.wg.Close()
		return nil, fmt.Errorf("gateway: cannot open UDP port %d: %w", g.port, err)
	}
	if runtime.GOOS == "linux" {
		g.trySetMark()
	}
	g.hooks = newHookQueue(cfg.EndpointHook)
	g.loops.Add(1)
	go g.run()
	g.log.Printf(logTag, "started: UDP %d, subnet %s", g.port, g.subnet)
	return g, nil
}

func validSubnet(p netip.Prefix) error {
	if !p.Addr().Is4() || p.Bits() != 24 {
		return errors.New("gateway: subnet must be an IPv4 /24")
	}
	for _, r := range privateRanges {
		if r.Contains(p.Masked().Addr()) {
			return nil
		}
	}
	return errors.New("gateway: subnet must be inside 10.0.0.0/8, 172.16.0.0/12 or 192.168.0.0/16")
}

// trySetMark marks the WireGuard sockets so replies to off-LAN clients skip
// this device's own client tunnel on Linux (§7.4). It needs CAP_NET_ADMIN;
// on failure the mark is cleared so later rebinds do not fail.
func (g *Gateway) trySetMark() {
	if err := g.wg.IpcSet("fwmark=" + strconv.Itoa(netbind.FwMark) + "\n"); err != nil {
		_ = g.wg.IpcSet("fwmark=0\n")
		g.log.Printf(logTag, "WireGuard sockets unmarked (no CAP_NET_ADMIN)")
	}
}

func (g *Gateway) run() {
	defer g.loops.Done()
	sweep := time.NewTicker(sweepInterval)
	defer sweep.Stop()
	var epC <-chan time.Time
	if g.cfg.EndpointHook != nil {
		t := time.NewTicker(endpointInterval)
		defer t.Stop()
		epC = t.C
	}
	for {
		select {
		case <-g.stop:
			return
		case <-sweep.C:
			g.sweep()
		case <-epC:
			g.checkEndpoints()
		}
	}
}

// sweep removes expired leases.
func (g *Gateway) sweep() {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return
	}
	exp := g.table.expired(g.now())
	for _, l := range exp {
		g.removeLocked(l)
	}
	if len(exp) > 0 {
		g.log.Printf(logTag, "%d lease(s) expired, %d client(s)", len(exp), len(g.table.byKey))
	}
}

func (g *Gateway) lookup(src netip.Addr) *gwstack.Client {
	g.ipMu.RLock()
	defer g.ipMu.RUnlock()
	return g.byIP[src]
}

func (g *Gateway) clampMTU(hint int) int {
	if hint == 0 {
		return g.mtu
	}
	return min(g.mtu, max(hint, minMTU))
}

func (g *Gateway) leaseOf(l *lease) Lease {
	return Lease{
		IP:        l.ip,
		GatewayIP: g.gwIP,
		Token:     l.token,
		LeaseSec:  uint32(leaseLifetime / time.Second),
		MTU:       l.mtu,
		LANAccess: g.stack.Policy().LANAccess(),
	}
}

func peerAdd(pub, psk [32]byte, ip netip.Addr) string {
	return "public_key=" + hex.EncodeToString(pub[:]) +
		"\npreshared_key=" + hex.EncodeToString(psk[:]) +
		"\nreplace_allowed_ips=true\nallowed_ip=" + netip.PrefixFrom(ip, 32).String() + "\n"
}

func peerRemove(pub [32]byte) string {
	return "public_key=" + hex.EncodeToString(pub[:]) + "\nremove=true\n"
}

// Join leases an address to clientPub and adds it as a WireGuard peer. For a
// key that already holds a lease it refreshes and returns that lease.
func (g *Gateway) Join(clientPub [32]byte, mtuHint int) (Lease, error) {
	if clientPub == ([32]byte{}) || clientPub == g.pub {
		return Lease{}, ErrInvalidKey
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return Lease{}, ErrClosed
	}
	if l := g.table.byKey[clientPub]; l != nil {
		l.expires = g.now().Add(leaseLifetime)
		l.mtu = g.clampMTU(mtuHint)
		return g.leaseOf(l), nil
	}
	l, err := g.table.add(clientPub)
	if err != nil {
		return Lease{}, err
	}
	rand.Read(l.token[:])
	l.expires = g.now().Add(leaseLifetime)
	l.mtu = g.clampMTU(mtuHint)
	l.client = g.stack.NewClient()
	if err := g.wg.IpcSet(peerAdd(clientPub, g.cfg.PresharedKey, l.ip)); err != nil {
		_ = g.wg.IpcSet(peerRemove(clientPub))
		l.client.Close()
		g.table.remove(l)
		g.log.Printf(logTag, "peer setup failed")
		return Lease{}, errPeerSetup
	}
	g.ipMu.Lock()
	g.byIP[l.ip] = l.client
	g.ipMu.Unlock()
	g.log.Printf(logTag, "client joined, %d client(s)", len(g.table.byKey))
	return g.leaseOf(l), nil
}

// leaseFor returns the live lease of clientPub if token matches. g.mu held.
func (g *Gateway) leaseFor(clientPub [32]byte, token [16]byte) (*lease, error) {
	if g.closed {
		return nil, ErrClosed
	}
	l := g.table.byKey[clientPub]
	if l == nil || subtle.ConstantTimeCompare(l.token[:], token[:]) != 1 || g.now().After(l.expires) {
		return nil, ErrUnknownLease // an expired lease awaits the sweep
	}
	return l, nil
}

// Renew extends a lease by the lease lifetime.
func (g *Gateway) Renew(clientPub [32]byte, token [16]byte) (Lease, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	l, err := g.leaseFor(clientPub, token)
	if err != nil {
		return Lease{}, err
	}
	l.expires = g.now().Add(leaseLifetime)
	return g.leaseOf(l), nil
}

// Leave ends a lease now.
func (g *Gateway) Leave(clientPub [32]byte, token [16]byte) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	l, err := g.leaseFor(clientPub, token)
	if err != nil {
		return err
	}
	g.removeLocked(l)
	g.log.Printf(logTag, "client left, %d client(s)", len(g.table.byKey))
	return nil
}

// removeLocked ends a lease: no new flows, peer removed, flows closed,
// endpoint route released, address back to the pool. g.mu held.
func (g *Gateway) removeLocked(l *lease) {
	g.ipMu.Lock()
	delete(g.byIP, l.ip)
	g.ipMu.Unlock()
	if err := g.wg.IpcSet(peerRemove(l.pub)); err != nil {
		g.log.Printf(logTag, "peer removal failed")
	}
	l.client.Close()
	g.unrouteLocked(l)
	g.table.remove(l)
}

// ClientCount returns the number of leases.
func (g *Gateway) ClientCount() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.table.byKey)
}

// SetLANAccess switches "Allow my local network" for new flows.
func (g *Gateway) SetLANAccess(on bool) {
	if g.stack.Policy().LANAccess() == on {
		return
	}
	g.stack.Policy().SetLANAccess(on)
	state := "off"
	if on {
		state = "on"
	}
	g.log.Printf(logTag, "LAN access %s", state)
}

// LANAccess reports the current LAN access setting.
func (g *Gateway) LANAccess() bool { return g.stack.Policy().LANAccess() }

// RefreshPolicy re-reads ExtraDeny and the host's interface addresses; call
// it on every network change.
func (g *Gateway) RefreshPolicy() { g.refreshPolicy() }

func (g *Gateway) refreshPolicy() {
	var deny []netip.Prefix
	if g.cfg.ExtraDeny != nil {
		deny = append(deny, g.cfg.ExtraDeny()...)
	}
	host, onLink := localAddrs()
	g.stack.Policy().SetExtraDeny(append(deny, host...))
	g.onLink.Store(&onLink)
}

// localAddrs returns the host's own addresses (as host prefixes; loopback is
// denied by the fixed policy) and its on-link subnets. Errors (e.g. sandboxed
// platforms) leave the lists empty; ExtraDeny still applies.
func localAddrs() (host, onLink []netip.Prefix) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, nil
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
		if ip.IsLoopback() {
			continue
		}
		host = append(host, netip.PrefixFrom(ip, ip.BitLen()))
		ones, _ := ipn.Mask.Size()
		if ip.Is4() && ones > 32 {
			ones -= 96
		}
		if p, err := ip.Prefix(ones); err == nil {
			onLink = append(onLink, p)
		}
	}
	return host, onLink
}

// PublicKey returns the gateway's static public key.
func (g *Gateway) PublicKey() [32]byte { return g.pub }

// Subnet returns the tunnel subnet.
func (g *Gateway) Subnet() netip.Prefix { return g.subnet }

// ListenPort returns the WireGuard UDP port.
func (g *Gateway) ListenPort() int { return g.port }

// Stats returns aggregate counters.
func (g *Gateway) Stats() Stats {
	s := g.stack.Stats()
	return Stats{
		Clients:  g.ClientCount(),
		TCPFlows: s.TCPFlows,
		UDPFlows: s.UDPFlows,
		RxBytes:  s.RxBytes,
		TxBytes:  s.TxBytes,
	}
}

// Close drops every lease and flow and closes the WireGuard device. Clients
// are not notified (§8.9). Idempotent.
func (g *Gateway) Close() error {
	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		return nil
	}
	g.closed = true
	g.ipMu.Lock()
	clear(g.byIP)
	g.ipMu.Unlock()
	for _, l := range g.table.byKey {
		l.client.Close()
		g.unrouteLocked(l)
	}
	g.table = newLeaseTable(g.subnet)
	g.mu.Unlock()

	close(g.stop)
	g.wg.Close() // closes the stack too
	g.hooks.close()
	g.loops.Wait()
	g.log.Printf(logTag, "stopped")
	return nil
}
