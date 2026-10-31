//go:build darwin

package tunnel

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/tun"

	"github.com/cyberkyd01/privatevpn/core/eventlog"
)

// macOS client tunnel (§9.3), run inside the root helper.
//
// Kill switch: a pf ruleset in our own anchor (pfAnchor, evaluated by the
// stock /etc/pf.conf). pf sees every packet regardless of routes, so the
// gateway endpoint stays reachable even before a default route exists (boot)
// and interface-bound sockets cannot slip past. The anchor survives the
// helper and the app; a LaunchDaemon re-installs it at boot from a small
// root-owned state file; only Down (or `privatevpn unblock`) removes it.
const (
	ifconfigPath     = "/sbin/ifconfig"
	routePath        = "/sbin/route"
	networksetupPath = "/usr/sbin/networksetup"
	dscacheutilPath  = "/usr/bin/dscacheutil"
	killallPath      = "/usr/bin/killall"
	pfctlPath        = "/sbin/pfctl"
	launchctlPath    = "/bin/launchctl"

	// The DNS backup lives in a root-owned system directory rather than the
	// user's data dir: the helper is root and must not write through paths
	// the user controls (symlink attacks), and it must survive a reboot.
	dnsBackupDir  = "/Library/Application Support/PrivateVPN/run"
	dnsBackupFile = "dns-backup.json"
	ksStateFile   = "killswitch.json"

	// Boot persistence: a LaunchDaemon runs a root-owned copy of the
	// executable (never the user's, possibly user-writable, app bundle).
	ksBinDir      = "/Library/Application Support/PrivateVPN/bin"
	ksBinName     = "privatevpn"
	ksDaemonLabel = "app.privatevpn.killswitch"
	ksDaemonPlist = "/Library/LaunchDaemons/" + ksDaemonLabel + ".plist"
)

// Host routes we add carry RTF_PROTO2 so stale ones can be found after a
// crash without persisting any address (§12.1). The kernel itself uses
// RTF_PROTO3 (RTPRF_OURS) only.
const ourRouteFlag = unix.RTF_PROTO2

// IsElevated reports whether we run as root.
func IsElevated() bool { return os.Geteuid() == 0 }

func prepareCmd(*exec.Cmd) {}

type darwinSession struct {
	tdev     tun.Device // owned until wg is set
	wg       *wgDevice
	ifname   string
	dnsSet   bool
	watch    *routeWatcher
	routesC  *debouncer
	ks       bool // the pf block was installed for this session
	allowLAN bool
	warnings []string
}

type darwinTunnel struct {
	mu      sync.Mutex
	log     *eventlog.Log
	sess    *darwinSession
	routes  *hostRoutes
	notify  func(Event)
	closed  bool
	blockOn bool // a kill-switch block (ours or a leftover) is installed
}

// NewNative returns the macOS tunnel. It needs root. Leftovers of a crashed
// helper are repaired (DNS from the backup file, tagged host routes) unless
// a kill-switch block is in place: then everything stays as it is until an
// explicit Down.
func NewNative(log *eventlog.Log) (Tunnel, error) {
	if !IsElevated() {
		return nil, ErrNotElevated
	}
	t := &darwinTunnel{log: logOrDefault(log)}
	t.routes = newHostRoutes(darwinRouteOps{})
	t.blockOn = blockLeftover()
	if t.blockOn {
		t.log.Printf("tunnel", "a kill-switch block from an earlier session is in place; keeping it until Disconnect")
	} else {
		t.cleanupStale()
	}
	return t, nil
}

func (t *darwinTunnel) cleanupStale() {
	if err := restoreDNS(); err != nil {
		t.log.Printf("tunnel", "restoring DNS from backup failed: %v", err)
	}
	if n := sweepHostRoutes(nil); n > 0 {
		t.log.Printf("tunnel", "removed %d stale host routes", n)
	}
}

// sweepHostRoutes deletes our tagged host routes except those in keep.
func sweepHostRoutes(keep map[netip.Addr]hostRoute) int {
	n := 0
	rib, err := fetchRIB4()
	if err != nil {
		return 0
	}
	for _, m := range rib {
		if m.Flags&ourRouteFlag == 0 || m.Flags&unix.RTF_HOST == 0 {
			continue
		}
		dst, ok := msgDst4(m)
		if !ok {
			continue
		}
		if _, kept := keep[dst]; kept {
			continue
		}
		if _, err := run("route delete", routePath, "-q", "-n", "delete", "-inet", "-host", dst.String()); err == nil {
			n++
		}
	}
	return n
}

func (t *darwinTunnel) SetNotify(fn func(Event)) {
	t.mu.Lock()
	t.notify = fn
	t.mu.Unlock()
}

func (t *darwinTunnel) emit(ev Event) {
	if t.notify != nil {
		go t.notify(ev)
	}
}

func (t *darwinTunnel) Up(cfg Config) (string, error) {
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

func (t *darwinTunnel) upLocked(cfg Config) (s *darwinSession, err error) {
	if !cfg.KillSwitch && (t.blockOn || blockLeftover()) {
		// The user does not want a kill switch: an old block would keep
		// the new gateway out.
		if err := t.removeBlock(); err != nil {
			return nil, fmt.Errorf("tunnel: a leftover kill-switch block could not be removed: %w", err)
		}
	}
	tdev, err := tun.CreateTUN("utun", cfg.MTU)
	if err != nil {
		return nil, fmt.Errorf("tunnel: create utun: %w", err)
	}
	s = &darwinSession{tdev: tdev, allowLAN: cfg.AllowLAN}
	if s.ifname, err = tdev.Name(); err != nil {
		tdev.Close()
		return nil, errors.New("tunnel: utun has no name")
	}
	defer func() {
		if err != nil {
			t.teardown(s, t.blockOn)
		}
	}()
	local := cfg.Address.Addr()
	if _, err = run("ifconfig", ifconfigPath, s.ifname, "inet", local.String(), peerTunnelAddr(cfg.Address).String(),
		"netmask", netmask4(cfg.Address.Bits()), "mtu", fmt.Sprint(cfg.MTU), "up"); err != nil {
		return s, err
	}
	// Endpoint exclusion before the /1 routes so the handshake never loops.
	if err = t.routes.start(cfg.Peer.Endpoint.Addr()); err != nil {
		return s, fmt.Errorf("tunnel: endpoint route: %w", err)
	}
	if cfg.KillSwitch {
		// Permits for this session are installed in one atomic ruleset
		// swap before any route changes: no packet ever has a path to the
		// physical network that the block does not know about.
		sweepHostRoutes(t.routes.installed)
		if e := pfInstall(pfRules(s.ifname, cfg.Peer.Endpoint.Addr(), cfg.AllowLAN)); e != nil {
			t.log.Printf("tunnel", "kill switch not installed: %v", e)
			s.warnings = addWarning(s.warnings, WarnKillSwitchFailed)
		} else {
			s.ks, t.blockOn = true, true
			if e := persistBoot(cfg.Peer.Endpoint.Addr(), cfg.AllowLAN); e != nil {
				t.log.Printf("tunnel", "kill switch will not survive a reboot: %v", e)
				s.warnings = addWarning(s.warnings, WarnKillSwitchNotPersistent)
			}
		}
	}
	for _, p := range []string{"0.0.0.0/1", "128.0.0.0/1"} {
		if _, err = run("route add", routePath, "-q", "-n", "add", "-inet", p, "-interface", s.ifname); err != nil {
			return s, err
		}
	}
	if cfg.SinkIPv6 {
		for _, p := range []string{"::/1", "8000::/1"} {
			if _, e := run("route add", routePath, "-q", "-n", "add", "-inet6", p, "-interface", s.ifname); e != nil {
				if s.ks {
					t.log.Printf("tunnel", "IPv6 sink route not installed (IPv6 is blocked by the kill switch): %v", e)
				} else {
					t.log.Printf("tunnel", "IPv6 sink route not installed (IPv6 is not blocked): %v", e)
					s.warnings = addWarning(s.warnings, WarnIPv6NotBlocked)
				}
				break
			}
		}
	}
	if len(cfg.DNS) > 0 {
		s.dnsSet = true // restore even after a partial failure (no backup = no-op)
		if e := setDNS(cfg.DNS); e != nil {
			t.log.Printf("tunnel", "system DNS not redirected: %v", e)
			s.warnings = addWarning(s.warnings, WarnDNSNotSet)
		}
	}
	wg, err := startDevice(s.tdev, cfg, 0, t.log)
	s.tdev = nil // closed by startDevice on failure, owned by wg otherwise
	if err != nil {
		return s, err
	}
	s.wg = wg
	s.routesC = newDebouncer(time.Second, func() { t.reroute(s) })
	if s.watch, err = startRouteWatcher(s.routesC.kick); err != nil {
		t.log.Printf("tunnel", "route monitor unavailable; endpoint route is not updated on network changes")
		err = nil
	}
	return s, nil
}

// reroute re-evaluates host routes after a routing change.
func (t *darwinTunnel) reroute(s *darwinSession) {
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

// teardown removes the tunnel. With keepBlock the kill switch stays: DNS
// keeps pointing at the (dead) tunnel resolver and the endpoint host route
// stays so the control plane can still reach the gateway — Down undoes both.
func (t *darwinTunnel) teardown(s *darwinSession, keepBlock bool) {
	if s.routesC != nil {
		s.routesC.stop()
	}
	if s.watch != nil {
		s.watch.stop()
	}
	if s.dnsSet && !keepBlock {
		if err := restoreDNS(); err != nil {
			t.log.Printf("tunnel", "restoring DNS failed (retried at next start): %v", err)
		}
	}
	if !keepBlock {
		if err := t.routes.stop(); err != nil {
			t.log.Printf("tunnel", "removing host routes: %v", err)
		}
	}
	// Closing the utun removes its address and every route through it.
	if s.wg != nil {
		s.wg.close()
	} else if s.tdev != nil {
		s.tdev.Close()
	}
}

func (t *darwinTunnel) downLocked(keepBlock bool) {
	if t.sess == nil {
		return
	}
	t.teardown(t.sess, keepBlock && t.blockOn)
	t.sess = nil
	t.log.Printf("tunnel", "down")
}

// removeBlock lifts the kill switch: pf anchor, boot daemon, state file,
// DNS and tagged host routes (also leftovers of an earlier session).
func (t *darwinTunnel) removeBlock() error {
	err := pfRemove()
	if e := removeBoot(); e != nil {
		t.log.Printf("tunnel", "removing the boot-time block: %v", e)
		if err == nil {
			err = e
		}
	}
	if e := restoreDNS(); e != nil {
		t.log.Printf("tunnel", "restoring DNS failed (retried at next start): %v", e)
	}
	sweepHostRoutes(nil)
	if err == nil {
		t.blockOn = false
		t.log.Printf("tunnel", "kill switch removed")
	}
	return err
}

func (t *darwinTunnel) SetEndpoint(ep netip.AddrPort) error {
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
		// New permit first (one atomic ruleset swap), then the peer moves.
		if err := pfInstall(pfRules(s.ifname, ep.Addr(), s.allowLAN)); err != nil {
			return fmt.Errorf("tunnel: kill switch update: %w", err)
		}
		if err := writeKSState(ep.Addr(), s.allowLAN); err != nil {
			t.log.Printf("tunnel", "kill switch state not updated: %v", err)
		}
	}
	// Route first, so packets to the new endpoint never enter the tunnel.
	rerr := t.routes.setEndpoint(ep.Addr())
	if err := s.wg.setEndpoint(ep); err != nil {
		return err
	}
	return rerr
}

func (t *darwinTunnel) Status() (Status, error) {
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

func (t *darwinTunnel) EndpointRouteOK() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.routes.endpointOK()
}

func (t *darwinTunnel) RouteAdd(dst netip.Addr) error {
	if err := CheckPublicIPv4(dst); err != nil {
		return err
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.routes.addHost(dst)
}

func (t *darwinTunnel) RouteDel(dst netip.Addr) error {
	if err := CheckPublicIPv4(dst); err != nil {
		return err
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.routes.delHost(dst)
}

// Down removes the tunnel and the kill switch (also a leftover one).
func (t *darwinTunnel) Down() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.downLocked(false)
	return t.removeBlock()
}

// Close removes the tunnel but keeps a kill-switch block in place.
func (t *darwinTunnel) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.downLocked(true)
	t.closed = true
	return nil
}

// ---- kill switch: pf ----

// pfInstall loads rules into our anchor (replacing what was there, in one
// kernel operation), makes sure pf is enabled and that the main ruleset
// consults com.apple sub-anchors, and flushes the state table so no flow
// admitted earlier outlives the new rules.
func pfInstall(rules string) error {
	_, _ = run("pfctl enable", pfctlPath, "-E") // reference-counted enable; verified below
	if _, err := runInput("pfctl load", []byte(rules), pfctlPath, "-q", "-a", pfAnchor, "-f", "-"); err != nil {
		return err
	}
	info, err := run("pfctl info", pfctlPath, "-s", "info")
	if err != nil {
		return err
	}
	if !pfEnabled(info) {
		return errors.New("pf could not be enabled")
	}
	main, err := run("pfctl rules", pfctlPath, "-s", "rules")
	if err != nil {
		return err
	}
	if !pfMainHasAppleAnchor(main) {
		return errors.New("/etc/pf.conf does not evaluate com.apple anchors; the block would be ignored")
	}
	_, _ = run("pfctl flush states", pfctlPath, "-q", "-F", "states")
	return nil
}

// pfRemove empties our anchor. pf itself stays as it is (other services may
// rely on it; an enabled pf with the stock ruleset passes everything).
func pfRemove() error {
	_, err := run("pfctl flush", pfctlPath, "-q", "-a", pfAnchor, "-F", "rules")
	if err != nil && pfAnchorLeftover() {
		return err
	}
	return nil
}

func pfAnchorLeftover() bool {
	out, err := run("pfctl anchor rules", pfctlPath, "-q", "-a", pfAnchor, "-s", "rules")
	return err == nil && pfAnchorHasRules(out)
}

// blockLeftover reports whether a kill switch from an earlier session is in
// place (anchor rules or the persisted boot record).
func blockLeftover() bool {
	if _, err := os.Lstat(filepath.Join(dnsBackupDir, ksStateFile)); err == nil {
		return true
	}
	return pfAnchorLeftover()
}

// ---- kill switch: boot persistence ----

func writeKSState(ep netip.Addr, allowLAN bool) error {
	data, err := encodeKSState(ep, allowLAN)
	if err != nil {
		return err
	}
	return writeRootFile(dnsBackupDir, ksStateFile, data, 0o600)
}

// persistBoot records the boot block's inputs, copies the executable to a
// root-owned place and registers the LaunchDaemon (picked up at the next
// boot; it is not started now — the live ruleset already is in place).
func persistBoot(ep netip.Addr, allowLAN bool) error {
	if err := writeKSState(ep, allowLAN); err != nil {
		return err
	}
	bin, err := copyRootExe(ksBinDir, ksBinName)
	if err != nil {
		return err
	}
	return writeRootFile(filepath.Dir(ksDaemonPlist), filepath.Base(ksDaemonPlist), []byte(launchdPlist(ksDaemonLabel, bin)), 0o644)
}

// removeBoot unregisters the daemon and deletes the state file, the plist
// and the binary copy. Missing pieces are fine.
func removeBoot() error {
	_, _ = run("launchctl bootout", launchctlPath, "bootout", "system/"+ksDaemonLabel)
	var first error
	for _, p := range []string{ksDaemonPlist, filepath.Join(dnsBackupDir, ksStateFile), filepath.Join(ksBinDir, ksBinName)} {
		if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) && first == nil {
			first = err
		}
	}
	return first
}

// bootBlock is `privatevpn killswitch-boot`: re-install the block recorded
// by the last session (nothing to do when there is no record).
func bootBlock(log *eventlog.Log) error {
	data, err := readRootFile(dnsBackupDir, ksStateFile)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	ep, allowLAN, err := decodeKSState(data)
	if err != nil {
		return err
	}
	pfEnsureMainRuleset(log)
	if err := pfInstall(pfRules("", ep, allowLAN)); err != nil {
		return err
	}
	log.Printf("tunnel", "boot-time kill switch installed")
	return nil
}

// pfEnsureMainRuleset loads the stock /etc/pf.conf when the main ruleset
// does not evaluate com.apple sub-anchors yet. At boot launchd starts our
// daemon and Apple's com.apple.pfctl (which loads /etc/pf.conf) in no
// particular order; if ours runs first the kernel holds no main ruleset,
// pfInstall would refuse ("the block would be ignored") and the device would
// come up unblocked. Loading the file ourselves is exactly what Apple's
// daemon does a moment later; a second load replaces the main ruleset only
// and leaves our anchor's rules alone.
func pfEnsureMainRuleset(log *eventlog.Log) {
	main, err := run("pfctl rules", pfctlPath, "-s", "rules")
	if err != nil || pfMainHasAppleAnchor(main) {
		return
	}
	if _, err := run("pfctl load main", pfctlPath, "-q", "-f", "/etc/pf.conf"); err != nil {
		log.Printf("tunnel", "loading /etc/pf.conf: %v", err)
		return
	}
	log.Printf("tunnel", "main pf ruleset loaded (com.apple.pfctl had not run yet)")
}

// ---- host routes via route(8) and the routing information base ----

type darwinRouteOps struct{}

func (darwinRouteOps) table() ([]rtEntry, error) {
	msgs, err := fetchRIB4()
	if err != nil {
		return defaultFromRouteGet()
	}
	names := map[int]string{}
	ifName := func(idx int) string {
		if n, ok := names[idx]; ok {
			return n
		}
		n := ""
		if ifi, err := net.InterfaceByIndex(idx); err == nil {
			n = ifi.Name
		}
		names[idx] = n
		return n
	}
	t := ribToTable(msgs, ifName, false)
	if !hasDefault(t) { // only scoped defaults (unusual): use those
		t = ribToTable(msgs, ifName, true)
	}
	return t, nil
}

func hasDefault(t []rtEntry) bool {
	for _, e := range t {
		if e.Dst.Bits() == 0 {
			return true
		}
	}
	return false
}

// ribToTable converts RIB messages into rtEntries, skipping our own and
// other tunnels (utun*), loopback, cloned/ARP entries, our tagged host
// routes and (unless withScoped) interface-scoped routes.
func ribToTable(msgs []*route.RouteMessage, ifName func(int) string, withScoped bool) []rtEntry {
	var out []rtEntry
	for _, m := range msgs {
		if m.Flags&unix.RTF_UP == 0 ||
			m.Flags&(unix.RTF_WASCLONED|unix.RTF_LLINFO|ourRouteFlag|unix.RTF_REJECT|unix.RTF_BLACKHOLE) != 0 ||
			(!withScoped && m.Flags&unix.RTF_IFSCOPE != 0) {
			continue
		}
		dst, ok := msgDst4(m)
		if !ok {
			continue
		}
		bits := msgBits4(m, dst)
		if bits < 0 {
			continue
		}
		name := ifName(m.Index)
		if name == "" || strings.HasPrefix(name, "utun") || strings.HasPrefix(name, "lo") {
			continue
		}
		e := rtEntry{Dst: netip.PrefixFrom(dst, bits).Masked(), IfIndex: uint64(m.Index), IfName: name}
		if len(m.Addrs) > unix.RTAX_GATEWAY && m.Flags&unix.RTF_GATEWAY != 0 {
			if g, ok := m.Addrs[unix.RTAX_GATEWAY].(*route.Inet4Addr); ok {
				e.Gateway = netip.AddrFrom4(g.IP)
			}
		}
		out = append(out, e)
	}
	return out
}

func msgDst4(m *route.RouteMessage) (netip.Addr, bool) {
	if len(m.Addrs) <= unix.RTAX_DST {
		return netip.Addr{}, false
	}
	a, ok := m.Addrs[unix.RTAX_DST].(*route.Inet4Addr)
	if !ok {
		return netip.Addr{}, false
	}
	return netip.AddrFrom4(a.IP), true
}

// msgBits4 returns the prefix length, or -1 for a non-contiguous mask.
func msgBits4(m *route.RouteMessage, dst netip.Addr) int {
	if m.Flags&unix.RTF_HOST != 0 {
		return 32
	}
	var mask *route.Inet4Addr
	if len(m.Addrs) > unix.RTAX_NETMASK {
		mask, _ = m.Addrs[unix.RTAX_NETMASK].(*route.Inet4Addr)
	}
	if mask == nil {
		if dst.IsUnspecified() {
			return 0
		}
		return -1
	}
	v := binary.BigEndian.Uint32(mask.IP[:])
	bits := 0
	for v&0x80000000 != 0 {
		bits++
		v <<= 1
	}
	if v != 0 {
		return -1
	}
	return bits
}

func fetchRIB4() ([]*route.RouteMessage, error) {
	b, err := route.FetchRIB(unix.AF_INET, route.RIBTypeRoute, 0)
	if err != nil {
		return nil, err
	}
	msgs, err := route.ParseRIB(route.RIBTypeRoute, b)
	if err != nil {
		return nil, err
	}
	out := make([]*route.RouteMessage, 0, len(msgs))
	for _, m := range msgs {
		if rm, ok := m.(*route.RouteMessage); ok && rm.Err == nil {
			out = append(out, rm)
		}
	}
	return out, nil
}

// defaultFromRouteGet is the §9.3 fallback: `route -n get default`.
func defaultFromRouteGet() ([]rtEntry, error) {
	out, err := run("route get", routePath, "-n", "get", "default")
	if err != nil {
		return nil, err
	}
	gw, name, ok := parseRouteGetDefault(out)
	if !ok || strings.HasPrefix(name, "utun") {
		return nil, errNoPhysicalRoute
	}
	ifi, err := net.InterfaceByName(name)
	if err != nil {
		return nil, errNoPhysicalRoute
	}
	return []rtEntry{{Dst: netip.MustParsePrefix("0.0.0.0/0"), Gateway: gw, IfIndex: uint64(ifi.Index), IfName: name}}, nil
}

func hostRouteArgs(verb string, r hostRoute) []string {
	args := []string{"-q", "-n", verb, "-inet"}
	if verb == "add" {
		args = append(args, "-proto2")
	}
	args = append(args, "-host", r.Dst.String())
	if r.Gateway.IsValid() {
		return append(args, r.Gateway.String())
	}
	return append(args, "-interface", r.IfName)
}

func (darwinRouteOps) add(r hostRoute) error {
	if !r.Gateway.IsValid() && r.IfName == "" {
		return errNoPhysicalRoute
	}
	if _, err := run("route add host", routePath, hostRouteArgs("add", r)...); err == nil {
		return nil
	}
	// A cloned host route for dst may exist ("File exists"): replace it.
	_, _ = run("route delete host", routePath, "-q", "-n", "delete", "-inet", "-host", r.Dst.String())
	_, err := run("route add host", routePath, hostRouteArgs("add", r)...)
	return err
}

func (darwinRouteOps) del(r hostRoute) error {
	_, err := run("route delete host", routePath, hostRouteArgs("delete", r)...)
	return err
}

// routeWatcher kicks fn on routing changes that may move the default route.
type routeWatcher struct {
	f    *os.File
	done chan struct{}
}

func startRouteWatcher(fn func()) (*routeWatcher, error) {
	fd, err := unix.Socket(unix.AF_ROUTE, unix.SOCK_RAW, unix.AF_UNSPEC)
	if err != nil {
		return nil, err
	}
	unix.CloseOnExec(fd)
	if err := unix.SetNonblock(fd, true); err != nil {
		unix.Close(fd)
		return nil, err
	}
	w := &routeWatcher{f: os.NewFile(uintptr(fd), "route"), done: make(chan struct{})}
	go func() {
		defer close(w.done)
		buf := make([]byte, 16<<10)
		for {
			n, err := w.f.Read(buf)
			if err != nil {
				return
			}
			if routeMsgInteresting(buf[:n]) {
				fn()
			}
		}
	}()
	return w, nil
}

func (w *routeWatcher) stop() {
	w.f.Close()
	<-w.done
}

// routeMsgInteresting filters routing socket messages: interface and address
// changes and non-cloned, not-ours route changes.
func routeMsgInteresting(b []byte) bool {
	if len(b) < 4 || b[2] != syscall.RTM_VERSION {
		return false
	}
	switch int(b[3]) {
	case unix.RTM_IFINFO, unix.RTM_NEWADDR, unix.RTM_DELADDR:
		return true
	case unix.RTM_ADD, unix.RTM_DELETE, unix.RTM_CHANGE:
		if len(b) < 12 {
			return false
		}
		flags := int(int32(binary.NativeEndian.Uint32(b[8:12])))
		return flags&(unix.RTF_WASCLONED|unix.RTF_LLINFO|ourRouteFlag) == 0
	}
	return false
}

// ---- DNS via networksetup, with a crash-safe backup ----

func dnsBackupPath() string { return filepath.Join(dnsBackupDir, dnsBackupFile) }

func setDNS(dns []netip.Addr) error {
	out, err := run("networksetup list", networksetupPath, "-listallnetworkservices")
	if err != nil {
		return err
	}
	var b dnsBackup
	for _, svc := range parseNetworkServices(out) {
		o, err := run("networksetup get", networksetupPath, "-getdnsservers", svc)
		if err != nil {
			continue
		}
		if servers, ok := parseDNSServers(o); ok {
			b.Services = append(b.Services, dnsBackupEntry{Name: svc, Servers: servers})
		}
	}
	if len(b.Services) == 0 {
		return nil
	}
	// Record before changing anything (§9.3). Never overwrite an existing
	// backup: it holds the user's real settings (startup restore failed).
	if _, err := os.Lstat(dnsBackupPath()); errors.Is(err, os.ErrNotExist) {
		data, err := encodeDNSBackup(b)
		if err != nil {
			return err
		}
		if err := writeRootFile(dnsBackupDir, dnsBackupFile, data, 0o600); err != nil {
			return fmt.Errorf("tunnel: saving DNS backup: %w", err)
		}
	}
	servers := make([]string, len(dns))
	for i, d := range dns {
		servers[i] = d.String()
	}
	for _, e := range b.Services {
		if _, err := run("networksetup set", networksetupPath, setDNSArgs(e.Name, servers)...); err != nil {
			return err
		}
	}
	flushDNSCache()
	return nil
}

// restoreDNS applies and then removes the backup, if there is one.
func restoreDNS() error {
	data, err := readRootFile(dnsBackupDir, dnsBackupFile)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	b, err := decodeDNSBackup(data)
	if err != nil {
		_ = os.Remove(dnsBackupPath())
		return err
	}
	current := map[string]bool{}
	if out, err := run("networksetup list", networksetupPath, "-listallnetworkservices"); err == nil {
		for _, s := range parseNetworkServices(out) {
			current[s] = true
		}
	} else {
		return err
	}
	var first error
	for _, e := range b.Services {
		if !current[e.Name] {
			continue
		}
		if _, err := run("networksetup set", networksetupPath, setDNSArgs(e.Name, e.Servers)...); err != nil && first == nil {
			first = err
		}
	}
	if first != nil {
		return first
	}
	flushDNSCache()
	return os.Remove(dnsBackupPath())
}

func flushDNSCache() {
	_, _ = run("dscacheutil", dscacheutilPath, "-flushcache")
	_, _ = run("killall", killallPath, "-HUP", "mDNSResponder")
}
