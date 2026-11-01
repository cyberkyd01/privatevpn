//go:build windows

package tunnel

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"

	"github.com/cyberkyd01/private-vpn-pro/core/eventlog"
)

// Windows client tunnel (§9.2), run inside the elevated helper.
//
// Kill switch: persistent WFP filters (wfp_windows.go) installed before any
// route changes and replaced in one transaction on re-Up/SetEndpoint. BFE
// enforces them from boot, with or without the helper, until Down or
// `private-vpn-pro unblock` deletes them by key.

// fixedGUID keeps one Windows network profile for the adapter.
var fixedGUID = windows.GUID{
	Data1: 0xB6F0C2A1, Data2: 0x7D3E, Data3: 0x4C6A,
	Data4: [8]byte{0x9E, 0x2B, 0x5A, 0x1F, 0x3D, 0x8C, 0x0E, 0x77},
}

const adapterName = "Private VPN Pro"

// hostRouteMetric marks our /32 routes on the physical interface so a
// crashed helper's leftovers can be swept at the next start without
// persisting any address (§12.1). Prefix length, not metric, decides that
// they beat the tunnel's /1 routes.
const hostRouteMetric = 5056

// IsElevated reports whether the process token is elevated.
func IsElevated() bool { return windows.GetCurrentProcessToken().IsElevated() }

type winSession struct {
	tdev     tun.Device // owned until wg is set
	wg       *wgDevice
	luid     winipcfg.LUID
	ifname   string
	fw       *dnsBlocker // dynamic DNS-only protection (kill switch off)
	cb       *winipcfg.RouteChangeCallback
	debounce *debouncer
	ks       bool // the persistent block was installed for this session
	dns      []netip.Addr
	allowLAN bool
	warnings []string
}

type winTunnel struct {
	mu      sync.Mutex
	log     *eventlog.Log
	sess    *winSession
	ops     *winRouteOps
	routes  *hostRoutes
	notify  func(Event)
	closed  bool
	blockOn bool // a persistent block (ours or a leftover) is installed
}

// NewNative returns the Windows tunnel. It needs an elevated token and
// removes host routes left behind by a crashed helper (Wintun adapters die
// with the process; a kill-switch block is kept until Down).
func NewNative(log *eventlog.Log) (Tunnel, error) {
	if !IsElevated() {
		return nil, ErrNotElevated
	}
	t := &winTunnel{log: logOrDefault(log), ops: &winRouteOps{}}
	t.routes = newHostRoutes(t.ops)
	t.cleanupStale()
	t.blockOn = persistentBlockInstalled()
	if t.blockOn {
		t.log.Printf("tunnel", "a kill-switch block from an earlier session is in place; keeping it until Disconnect")
	}
	return t, nil
}

func (t *winTunnel) cleanupStale() {
	rows, err := winipcfg.GetIPForwardTable2(windows.AF_INET)
	if err != nil {
		return
	}
	n := 0
	for i := range rows {
		r := &rows[i]
		if r.DestinationPrefix.PrefixLength == 32 && r.Metric == hostRouteMetric && r.Delete() == nil {
			n++
		}
	}
	if n > 0 {
		t.log.Printf("tunnel", "removed %d stale host routes", n)
	}
}

func (t *winTunnel) SetNotify(fn func(Event)) {
	t.mu.Lock()
	t.notify = fn
	t.mu.Unlock()
}

func (t *winTunnel) emit(ev Event) {
	if t.notify != nil {
		go t.notify(ev)
	}
}

func (t *winTunnel) Up(cfg Config) (string, error) {
	if err := cfg.Validate(); err != nil {
		return "", err
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return "", errClosed
	}
	// A block already in place stays until the new one replaces it.
	t.downLocked(true)
	s, err := t.upLocked(cfg)
	if err != nil {
		t.log.Printf("tunnel", "up failed: %v", err)
		return "", err
	}
	t.sess = s
	t.log.Printf("tunnel", "up on %s, address %s, mtu %d", s.ifname, cfg.Address, cfg.MTU)
	for _, w := range s.warnings {
		t.log.Printf("tunnel", "warning: %s", w)
	}
	return s.ifname, nil
}

func (t *winTunnel) upLocked(cfg Config) (s *winSession, err error) {
	if !cfg.KillSwitch && (t.blockOn || persistentBlockInstalled()) {
		// The user does not want a kill switch: an old block would keep
		// the new gateway out.
		if err := removePersistentBlock(); err != nil {
			return nil, fmt.Errorf("tunnel: a leftover kill-switch block could not be removed: %w", err)
		}
		t.blockOn = false
		t.log.Printf("tunnel", "kill switch removed")
	}
	guid := fixedGUID
	tdev, err := tun.CreateTUNWithRequestedGUID(adapterName, &guid, cfg.MTU)
	if err != nil {
		return nil, fmt.Errorf("tunnel: create Wintun adapter (wintun.dll must be next to private-vpn-pro.exe): %w", err)
	}
	nt, ok := tdev.(*tun.NativeTun)
	if !ok {
		tdev.Close()
		return nil, errors.New("tunnel: unexpected TUN type")
	}
	s = &winSession{tdev: tdev, luid: winipcfg.LUID(nt.LUID()), ifname: adapterName, dns: cfg.DNS, allowLAN: cfg.AllowLAN}
	if n, e := tdev.Name(); e == nil {
		s.ifname = n
	}
	defer func() {
		if err != nil {
			t.teardown(s, t.blockOn)
		}
	}()

	// The block (with this session's permits) goes in before any route or
	// address exists: at no point can a packet reach the physical network
	// unless a permit allows it.
	if cfg.KillSwitch {
		spec := wfpSpec{KillSwitch: true, TunnelLUID: uint64(s.luid), Endpoint: cfg.Peer.Endpoint.Addr(), DNS: cfg.DNS, AllowLAN: cfg.AllowLAN}
		if e := installPersistentBlock(spec); e != nil {
			t.log.Printf("tunnel", "kill switch not installed: %v", e)
			s.warnings = addWarning(s.warnings, WarnKillSwitchFailed)
		} else {
			s.ks, t.blockOn = true, true
			if e := copyRecoveryExe(); e != nil {
				t.log.Printf("tunnel", "recovery copy of private-vpn-pro.exe not written: %v", e)
			}
		}
	}
	if !s.ks && len(cfg.DNS) > 0 {
		if s.fw, err = newDNSBlocker(cfg.DNS); err != nil {
			return s, fmt.Errorf("tunnel: DNS leak protection: %w", err)
		}
	}
	t.ops.setTunnel(s.luid)

	// Endpoint exclusion before the /1 routes so the handshake never loops.
	if err = t.routes.start(cfg.Peer.Endpoint.Addr()); err != nil {
		return s, fmt.Errorf("tunnel: endpoint route: %w", err)
	}
	if err = setAddress(s.luid, cfg.Address); err != nil {
		return s, err
	}
	routes4 := []*winipcfg.RouteData{
		{Destination: netip.MustParsePrefix("0.0.0.0/1"), NextHop: netip.IPv4Unspecified()},
		{Destination: netip.MustParsePrefix("128.0.0.0/1"), NextHop: netip.IPv4Unspecified()},
	}
	if err = s.luid.SetRoutesForFamily(windows.AF_INET, routes4); err != nil {
		return s, fmt.Errorf("tunnel: set routes: %w", err)
	}
	if err = configureInterface(s.luid, windows.AF_INET, cfg.MTU); err != nil {
		return s, err
	}
	if cfg.SinkIPv6 {
		routes6 := []*winipcfg.RouteData{
			{Destination: netip.MustParsePrefix("::/1"), NextHop: netip.IPv6Unspecified()},
			{Destination: netip.MustParsePrefix("8000::/1"), NextHop: netip.IPv6Unspecified()},
		}
		if e := s.luid.SetRoutesForFamily(windows.AF_INET6, routes6); e != nil {
			if s.ks {
				t.log.Printf("tunnel", "IPv6 sink routes not installed (IPv6 is blocked by the kill switch): %v", e)
			} else {
				t.log.Printf("tunnel", "IPv6 sink routes not installed (IPv6 is not blocked): %v", e)
				s.warnings = addWarning(s.warnings, WarnIPv6NotBlocked)
			}
		} else if e := configureInterface(s.luid, windows.AF_INET6, cfg.MTU); e != nil {
			t.log.Printf("tunnel", "IPv6 interface settings: %v", e)
		}
	}
	if e := s.luid.SetDNS(windows.AF_INET, cfg.DNS, nil); e != nil {
		t.log.Printf("tunnel", "system DNS not redirected: %v", e)
		s.warnings = addWarning(s.warnings, WarnDNSNotSet)
	}
	_ = s.luid.FlushDNS(windows.AF_INET6)
	wg, err := startDevice(s.tdev, cfg, 0, t.log)
	s.tdev = nil // closed by startDevice on failure, owned by wg otherwise
	if err != nil {
		return s, err
	}
	s.wg = wg

	s.debounce = newDebouncer(500*time.Millisecond, func() { t.reroute(s) })
	luid := s.luid
	s.cb, err = winipcfg.RegisterRouteChangeCallback(func(_ winipcfg.MibNotificationType, r *winipcfg.MibIPforwardRow2) {
		// Must not block or take t.mu: Unregister waits for callbacks.
		if r == nil || r.InterfaceLUID == luid || r.DestinationPrefix.RawPrefix.Family != windows.AF_INET ||
			(r.DestinationPrefix.PrefixLength == 32 && r.Metric == hostRouteMetric) {
			return
		}
		s.debounce.kick()
	})
	if err != nil {
		t.log.Printf("tunnel", "route monitor unavailable; endpoint route is not updated on network changes")
		err = nil
	}
	return s, nil
}

// setAddress mirrors wireguard-windows' addressconfig.go: if the address is
// still assigned to a disconnected interface, remove it there and retry.
func setAddress(luid winipcfg.LUID, addr netip.Prefix) error {
	addrs := []netip.Prefix{addr}
	err := luid.SetIPAddressesForFamily(windows.AF_INET, addrs)
	if errors.Is(err, windows.ERROR_OBJECT_ALREADY_EXISTS) {
		cleanupAddressOnDisconnectedInterfaces(addr.Addr())
		err = luid.SetIPAddressesForFamily(windows.AF_INET, addrs)
	}
	if err != nil {
		return fmt.Errorf("tunnel: set address: %w", err)
	}
	return nil
}

func cleanupAddressOnDisconnectedInterfaces(a netip.Addr) {
	ifaces, err := winipcfg.GetAdaptersAddresses(windows.AF_INET, winipcfg.GAAFlagDefault)
	if err != nil {
		return
	}
	for _, iface := range ifaces {
		if iface.OperStatus == winipcfg.IfOperStatusUp {
			continue
		}
		for ua := iface.FirstUnicastAddress; ua != nil; ua = ua.Next {
			if ip, ok := netip.AddrFromSlice(ua.Address.IP()); ok && ip.Unmap() == a {
				_ = iface.LUID.DeleteIPAddress(netip.PrefixFrom(a, int(ua.OnLinkPrefixLength)))
			}
		}
	}
}

// configureInterface sets metric 0 (our routes win metric ties), the MTU and
// disables router discovery / DAD on the tunnel interface.
func configureInterface(luid winipcfg.LUID, family winipcfg.AddressFamily, mtu int) error {
	row, err := luid.IPInterface(family)
	if err != nil {
		return fmt.Errorf("tunnel: interface settings: %w", err)
	}
	row.RouterDiscoveryBehavior = winipcfg.RouterDiscoveryDisabled
	row.DadTransmits = 0
	row.ManagedAddressConfigurationSupported = false
	row.OtherStatefulConfigurationSupported = false
	row.NLMTU = uint32(mtu)
	row.UseAutomaticMetric = false
	row.Metric = 0
	if err := row.Set(); err != nil {
		return fmt.Errorf("tunnel: interface settings: %w", err)
	}
	return nil
}

// reroute re-evaluates host routes after a routing change.
func (t *winTunnel) reroute(s *winSession) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.sess != s {
		return
	}
	wasOK := t.routes.endpointOK()
	if err := t.routes.reconcile(); err != nil {
		t.log.Printf("tunnel", "host route update failed: %v", err)
	}
	if wasOK && !t.routes.endpointOK() {
		t.emit(Event{State: "error", Message: "lost the route to the gateway"})
	} else if !wasOK && t.routes.endpointOK() {
		t.emit(Event{State: "up", Message: "route to the gateway restored"})
	}
}

// teardown removes the tunnel. The persistent block is never touched here;
// with keepBlock the endpoint host route also stays so the control plane
// can still reach the gateway.
func (t *winTunnel) teardown(s *winSession, keepBlock bool) {
	if s.debounce != nil {
		s.debounce.stop()
	}
	if s.cb != nil {
		_ = s.cb.Unregister()
	}
	s.fw.close()
	if !keepBlock {
		if err := t.routes.stop(); err != nil {
			t.log.Printf("tunnel", "removing host routes: %v", err)
		}
	}
	t.ops.setTunnel(0)
	// Closing the Wintun handle deletes the adapter with its addresses,
	// routes and DNS settings.
	if s.wg != nil {
		s.wg.close()
	} else if s.tdev != nil {
		s.tdev.Close()
	}
}

func (t *winTunnel) downLocked(keepBlock bool) {
	if t.sess == nil {
		return
	}
	t.teardown(t.sess, keepBlock && t.blockOn)
	t.sess = nil
	t.log.Printf("tunnel", "down")
}

// removeBlock lifts the kill switch (also a leftover one) and sweeps host
// routes.
func (t *winTunnel) removeBlock() error {
	if err := removePersistentBlock(); err != nil {
		return err
	}
	if t.blockOn {
		t.log.Printf("tunnel", "kill switch removed")
	}
	t.blockOn = false
	_ = removeIfExists(recoveryExePath())
	if err := t.routes.stop(); err != nil {
		t.log.Printf("tunnel", "removing host routes: %v", err)
	}
	t.cleanupStale()
	return nil
}

func (t *winTunnel) SetEndpoint(ep netip.AddrPort) error {
	if err := CheckEndpoint(ep); err != nil {
		return err
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.sess == nil {
		return errNotUp
	}
	s := t.sess
	if s.ks {
		// New permit first (one transaction), then the peer moves.
		spec := wfpSpec{KillSwitch: true, TunnelLUID: uint64(s.luid), Endpoint: ep.Addr(), DNS: s.dns, AllowLAN: s.allowLAN}
		if err := installPersistentBlock(spec); err != nil {
			return fmt.Errorf("tunnel: kill switch update: %w", err)
		}
	}
	rerr := t.routes.setEndpoint(ep.Addr())
	if err := s.wg.setEndpoint(ep); err != nil {
		return err
	}
	return rerr
}

func (t *winTunnel) Status() (Status, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.sess == nil {
		return Status{HandshakeAgeSec: -1, KillSwitchActive: t.blockOn}, errNotUp
	}
	st, err := t.sess.wg.status()
	st.IfName = t.sess.ifname
	st.Warnings = append([]string(nil), t.sess.warnings...)
	st.KillSwitchActive = t.blockOn
	return st, err
}

func (t *winTunnel) EndpointRouteOK() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.routes.endpointOK()
}

func (t *winTunnel) RouteAdd(dst netip.Addr) error {
	if err := CheckPublicIPv4(dst); err != nil {
		return err
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.routes.addHost(dst)
}

func (t *winTunnel) RouteDel(dst netip.Addr) error {
	if err := CheckPublicIPv4(dst); err != nil {
		return err
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.routes.delHost(dst)
}

// Down removes the tunnel and the kill switch (also a leftover one).
func (t *winTunnel) Down() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.downLocked(false)
	return t.removeBlock()
}

// Close removes the tunnel but keeps a kill-switch block in place.
func (t *winTunnel) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.downLocked(true)
	t.closed = true
	return nil
}

// recoveryExePath is an administrator-only copy of private-vpn-pro.exe kept
// while the kill switch is engaged, so `private-vpn-pro unblock` is available
// even if the app was deleted while blocked (the persistent filters would
// otherwise outlive every tool that can delete them). Program Files is
// writable by administrators only, so the copy cannot be swapped by a
// standard user before an administrator runs it.
func recoveryExePath() string {
	dir := os.Getenv("ProgramFiles")
	if dir == "" {
		dir = `C:\Program Files`
	}
	return filepath.Join(dir, "Private VPN Pro", "recovery", "private-vpn-pro.exe")
}

func copyRecoveryExe() error {
	src, err := os.Executable()
	if err != nil {
		return err
	}
	dst := recoveryExePath()
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	return copyFile(src, dst, 0o755)
}

// bootBlock: nothing to do on Windows — the persistent WFP objects are
// enforced by BFE from boot on their own.
func bootBlock(log *eventlog.Log) error {
	if persistentBlockInstalled() {
		log.Printf("tunnel", "kill switch filters are persistent; nothing to do")
	}
	return nil
}

// ---- host routes via winipcfg ----

type winRouteOps struct {
	mu  sync.Mutex
	our winipcfg.LUID // tunnel interface, excluded from the table
}

func (o *winRouteOps) setTunnel(l winipcfg.LUID) {
	o.mu.Lock()
	o.our = l
	o.mu.Unlock()
}

// table lists IPv4 routes of connected interfaces other than ours, with
// effective metric = route metric + interface metric, minus our host routes.
func (o *winRouteOps) table() ([]rtEntry, error) {
	o.mu.Lock()
	our := o.our
	o.mu.Unlock()
	ifRows, err := winipcfg.GetIPInterfaceTable(windows.AF_INET)
	if err != nil {
		return nil, fmt.Errorf("tunnel: interface table: %w", err)
	}
	ifMetric := make(map[winipcfg.LUID]uint32, len(ifRows))
	for i := range ifRows {
		if ifRows[i].Connected {
			ifMetric[ifRows[i].InterfaceLUID] = ifRows[i].Metric
		}
	}
	rows, err := winipcfg.GetIPForwardTable2(windows.AF_INET)
	if err != nil {
		return nil, fmt.Errorf("tunnel: route table: %w", err)
	}
	out := make([]rtEntry, 0, len(rows))
	for i := range rows {
		r := &rows[i]
		m, connected := ifMetric[r.InterfaceLUID]
		if !connected || r.InterfaceLUID == our || r.Loopback {
			continue
		}
		dst := r.DestinationPrefix.Prefix()
		if !dst.IsValid() || !dst.Addr().Is4() || dst.Addr().IsLoopback() {
			continue
		}
		if dst.Bits() == 32 && r.Metric == hostRouteMetric {
			continue // ours
		}
		out = append(out, rtEntry{Dst: dst.Masked(), Gateway: r.NextHop.Addr(), IfIndex: uint64(r.InterfaceLUID), Metric: r.Metric + m})
	}
	return out, nil
}

func nextHop(r hostRoute) netip.Addr {
	if r.Gateway.IsValid() {
		return r.Gateway
	}
	return netip.IPv4Unspecified()
}

func (o *winRouteOps) add(r hostRoute) error {
	err := winipcfg.LUID(r.IfIndex).AddRoute(netip.PrefixFrom(r.Dst, 32), nextHop(r), hostRouteMetric)
	if err != nil && !errors.Is(err, windows.ERROR_OBJECT_ALREADY_EXISTS) {
		return fmt.Errorf("tunnel: add host route: %w", err)
	}
	return nil
}

func (o *winRouteOps) del(r hostRoute) error {
	err := winipcfg.LUID(r.IfIndex).DeleteRoute(netip.PrefixFrom(r.Dst, 32), nextHop(r))
	if err != nil && !errors.Is(err, windows.ERROR_NOT_FOUND) {
		return fmt.Errorf("tunnel: delete host route: %w", err)
	}
	return nil
}
