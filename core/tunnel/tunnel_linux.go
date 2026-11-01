//go:build linux && !android

package tunnel

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/tun"

	"github.com/cyberkyd01/private-vpn-pro/core/eventlog"
)

// Linux client tunnel (§9.4): pvp0 + wg-quick style policy routing. The
// WireGuard socket carries fwmark 20566, so its packets (and every gateway
// socket marked the same way, §7.4) use the main table; everything else is
// sent to table 20566 whose routes are the tunnel and — with the kill
// switch — a blackhole default with a worse metric: when pvp0 vanishes the
// kernel drops the tunnel route and the blackhole catches everything that
// has no specific route in main. Rules and table survive the process; a
// systemd unit re-installs them at boot; only Down removes them.
const (
	linuxIfName = "pvp0"
	linuxFwMark = 20566

	resolvConf       = "/etc/resolv.conf"
	resolvConfBackup = "/etc/resolv.conf.private-vpn-pro-backup"
	resolvConfTmp    = "/etc/.resolv.conf.private-vpn-pro-tmp"
	resolvedRunDir   = "/run/systemd/resolve"

	ksStateDir  = "/var/lib/private-vpn-pro"
	ksStateFile = "killswitch.json"
	ksBinDir    = "/var/lib/private-vpn-pro/bin"
	ksBinName   = "private-vpn-pro"
	ksUnitName  = "private-vpn-pro-killswitch.service"
	ksUnitDir   = "/etc/systemd/system"
	ksUnitWants = "/etc/systemd/system/sysinit.target.wants"
	systemdDir  = "/run/systemd/system"
)

// IsElevated reports whether the effective capability set contains
// CAP_NET_ADMIN (root normally has it; `setcap cap_net_admin+ep` grants it).
func IsElevated() bool {
	b, err := os.ReadFile("/proc/self/status")
	return err == nil && hasCapNetAdmin(b)
}

// prepareCmd passes CAP_NET_ADMIN to children through the ambient set when
// we are not root, so `ip` and `resolvectl` work for an in-process tunnel
// granted the capability by setcap (file capabilities are not inherited
// across exec otherwise).
func prepareCmd(cmd *exec.Cmd) {
	if os.Geteuid() != 0 {
		cmd.SysProcAttr = &syscall.SysProcAttr{AmbientCaps: []uintptr{unix.CAP_NET_ADMIN}}
	}
}

type dnsMode int

const (
	dnsNone dnsMode = iota
	dnsResolved
	dnsResolvConf
)

type linuxSession struct {
	tdev     tun.Device // owned until wg is set
	wg       *wgDevice
	ifname   string
	v6       bool
	dns      dnsMode
	ks       bool // the block was installed for this session
	mark     string
	ep       netip.Addr
	dnsAddr  netip.Addr // tunnel resolver exempted from the DNS blackhole
	allowLAN bool
	warnings []string
}

type linuxTunnel struct {
	mu         sync.Mutex
	log        *eventlog.Log
	ip         string
	resolvectl string
	systemctl  string
	sess       *linuxSession
	closed     bool
	blockOn    bool // a kill-switch block (ours or a leftover) is installed
}

// NewNative returns the Linux tunnel. It needs CAP_NET_ADMIN and cleans up
// leftovers of a previous crash (pvp0; and, unless a kill-switch block is
// in place, our rules and the resolv.conf backup).
func NewNative(log *eventlog.Log) (Tunnel, error) {
	if !IsElevated() {
		return nil, ErrNotElevated
	}
	ip := findExe("/usr/sbin/ip", "/sbin/ip", "/usr/bin/ip", "/bin/ip")
	if ip == "" {
		return nil, errors.New("tunnel: the ip command (iproute2) was not found")
	}
	t := &linuxTunnel{
		log:        logOrDefault(log),
		ip:         ip,
		resolvectl: findExe("/usr/bin/resolvectl", "/bin/resolvectl"),
		systemctl:  findExe("/usr/bin/systemctl", "/bin/systemctl"),
	}
	t.cleanupStale()
	return t, nil
}

func (t *linuxTunnel) ipCmd(label string, args ...string) error {
	_, err := run(label, t.ip, args...)
	return err
}

func (t *linuxTunnel) Up(cfg Config) (string, error) {
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

func (t *linuxTunnel) upLocked(cfg Config) (s *linuxSession, err error) {
	if !cfg.KillSwitch {
		// No kill switch wanted: an old block would keep the new gateway
		// out, and the plain policy routing starts from a clean slate.
		if t.blockOn || t.blockLeftover() {
			if err := t.removeBlock(); err != nil {
				return nil, fmt.Errorf("tunnel: a leftover kill-switch block could not be removed: %w", err)
			}
		}
		t.removeRules()
	}
	if linkExists(linuxIfName) {
		_ = t.ipCmd("ip link", "link", "del", "dev", linuxIfName)
	}
	tdev, err := tun.CreateTUN(linuxIfName, cfg.MTU)
	if err != nil {
		return nil, fmt.Errorf("tunnel: create %s: %w", linuxIfName, err)
	}
	s = &linuxSession{tdev: tdev, ifname: linuxIfName, ep: cfg.Peer.Endpoint.Addr(), allowLAN: cfg.AllowLAN}
	if n, err := tdev.Name(); err == nil {
		s.ifname = n
	}
	defer func() {
		if err != nil {
			t.teardown(s, t.blockOn)
		}
	}()
	mark := cfg.FwMark
	if mark == 0 {
		mark = linuxFwMark
	}
	s.mark = strconv.FormatUint(uint64(mark), 10)

	if err = t.ipCmd("ip address", "-4", "address", "add", cfg.Address.String(), "dev", s.ifname); err != nil {
		return s, err
	}
	if err = t.ipCmd("ip link", "link", "set", "dev", s.ifname, "mtu", strconv.Itoa(cfg.MTU), "up"); err != nil {
		return s, err
	}
	// Reverse-path filtering must honour the mark (as wg-quick does).
	_ = os.WriteFile("/proc/sys/net/ipv4/conf/all/src_valid_mark", []byte("1"), 0o644)

	var dns netip.Addr
	if len(cfg.DNS) > 0 {
		dns = cfg.DNS[0]
	}
	s.dnsAddr = dns
	if cfg.KillSwitch {
		// Block first (rules + blackhole; nothing references pvp0), then
		// the tunnel route that beats the blackhole: traffic is never
		// routed to the physical network in between.
		warn, e := t.installBlock("-4", s.mark, s.ep, dns)
		if e != nil {
			if !t.blockOn {
				t.removeRules()
			}
			return s, e
		}
		t.sweepStaleRules(s.ep, dns)
		s.ks, t.blockOn = true, true
		for _, w := range warn {
			s.warnings = addWarning(s.warnings, w)
		}
		if err = t.ipCmd("ip route", linuxTunnelDefaultArgs("-4", s.ifname)...); err != nil {
			return s, err
		}
		if cfg.SinkIPv6 && ipv6Enabled() {
			if _, e := t.installBlock("-6", s.mark, netip.Addr{}, netip.Addr{}); e != nil {
				t.log.Printf("tunnel", "IPv6 block not installed (IPv6 is not blocked): %v", e)
				t.removeRulesFamily("-6")
				s.warnings = addWarning(s.warnings, WarnIPv6NotBlocked)
			} else {
				s.v6 = true
				if e := t.ipCmd("ip route", linuxTunnelDefaultArgs("-6", s.ifname)...); e != nil {
					t.log.Printf("tunnel", "IPv6 tunnel route not installed (IPv6 stays blocked): %v", e)
				}
			}
		}
		if e := t.persistBoot(s.ep, cfg.AllowLAN); e != nil {
			t.log.Printf("tunnel", "kill switch will not survive a reboot: %v", e)
			s.warnings = addWarning(s.warnings, WarnKillSwitchNotPersistent)
		}
		if !cfg.AllowLAN {
			// Policy routing keeps every destination with a specific
			// route in main (on-link LANs) reachable; that cannot be
			// switched off without a packet filter.
			s.warnings = addWarning(s.warnings, WarnLANNotBlocked)
		}
	} else {
		if err = t.policyRouting("-4", s.ifname, s.mark); err != nil {
			return s, err
		}
		// Endpoint exclusion for unmarked sockets (the control plane) before
		// the WireGuard device starts, so nothing bound for the gateway ever loops.
		if err = t.ipCmd("ip rule", linuxEndpointRuleArgs("add", s.ep, linuxPrioEndpoint)...); err != nil {
			return s, err
		}
		if cfg.SinkIPv6 && ipv6Enabled() {
			if e := t.policyRouting("-6", s.ifname, s.mark); e != nil {
				t.log.Printf("tunnel", "IPv6 sink not installed (IPv6 is not blocked): %v", e)
				t.removeRulesFamily("-6")
				s.warnings = addWarning(s.warnings, WarnIPv6NotBlocked)
			} else {
				s.v6 = true
			}
		}
	}
	if len(cfg.DNS) > 0 {
		if s.dns = t.setDNS(s.ifname, cfg.DNS); s.dns == dnsNone {
			s.warnings = addWarning(s.warnings, WarnDNSNotSet)
		}
	}
	wg, err := startDevice(s.tdev, cfg, mark, t.log)
	s.tdev = nil // closed by startDevice on failure, owned by wg otherwise
	if err != nil {
		return s, err
	}
	s.wg = wg
	return s, nil
}

// policyRouting installs the §9.4 rules for one address family (no kill
// switch: table 20566 holds only the tunnel route).
func (t *linuxTunnel) policyRouting(fam, ifname, mark string) error {
	if err := t.ipCmd("ip route", linuxTunnelDefaultArgs(fam, ifname)...); err != nil {
		return err
	}
	if err := t.ipCmd("ip rule", fam, "rule", "add", "not", "fwmark", mark, "table", linuxTable, "priority", linuxPrioMark); err != nil {
		return err
	}
	return t.ipCmd("ip rule", fam, "rule", "add", "table", "main", "suppress_prefixlength", "0", "priority", linuxPrioMain)
}

// installBlock applies linuxBlockArgs with "ensure" semantics (an object
// that is already there is fine: a leftover block is being replaced). A
// mandatory command failing is an error; the optional DNS-confinement
// group is rolled back as a whole and reported as a warning.
func (t *linuxTunnel) installBlock(fam, mark string, ep, dns netip.Addr) (warnings []string, err error) {
	for _, c := range linuxBlockArgs(fam, mark, ep, dns) {
		e := t.ipCmd(c.label, c.args...)
		if e == nil || isExistsErr(e) {
			continue
		}
		if c.warn == "" {
			return nil, e
		}
		t.log.Printf("tunnel", "DNS confinement not installed (%s): %v", fam, e)
		for _, prio := range []string{linuxPrioMarkMain, linuxPrioDNSMain, linuxPrioDNSBlock} {
			t.deleteRulesByPrio(fam, prio)
		}
		return []string{c.warn}, nil
	}
	return nil, nil
}

// sweepStaleRules deletes endpoint/DNS rules of an earlier session that do
// not match the current values (new rules are already in place).
func (t *linuxTunnel) sweepStaleRules(ep, dns netip.Addr) {
	out, err := run("ip rule show", t.ip, "-4", "rule", "show")
	if err != nil {
		return
	}
	rules := parseIPRules(out)
	for _, a := range staleHostRules(rules, 20564, ep) {
		_ = t.ipCmd("ip rule", linuxEndpointRuleArgs("del", a, linuxPrioEndpoint)...)
	}
	for _, a := range staleHostRules(rules, 20562, dns) {
		_ = t.ipCmd("ip rule", linuxDNSRuleArgs("del", a)...)
	}
}

func ipv6Enabled() bool {
	b, err := os.ReadFile("/proc/sys/net/ipv6/conf/all/disable_ipv6")
	return err == nil && len(b) > 0 && b[0] == '0'
}

// setDNS points the system resolver at the gateway. Failure is reported
// (WarnDNSNotSet), not fatal.
func (t *linuxTunnel) setDNS(ifname string, dns []netip.Addr) dnsMode {
	if t.useResolved() {
		args := []string{"dns", ifname}
		for _, d := range dns {
			args = append(args, d.String())
		}
		_, err := run("resolvectl dns", t.resolvectl, args...)
		if err == nil {
			_, err = run("resolvectl domain", t.resolvectl, "domain", ifname, "~.")
		}
		if err == nil {
			return dnsResolved
		}
		t.log.Printf("tunnel", "DNS via systemd-resolved failed, trying resolv.conf: %v", err)
	}
	if err := writeResolvConf(dns); err != nil {
		t.log.Printf("tunnel", "DNS not redirected to the gateway: %v", err)
		return dnsNone
	}
	return dnsResolvConf
}

func (t *linuxTunnel) useResolved() bool {
	if t.resolvectl == "" {
		return false
	}
	if fi, err := os.Stat(resolvedRunDir); err != nil || !fi.IsDir() {
		return false
	}
	target, _ := os.Readlink(resolvConf)
	content, _ := os.ReadFile(resolvConf)
	return resolvConfUsesResolved(target, content)
}

// writeResolvConf backs up /etc/resolv.conf (a symlink is backed up as a
// symlink) unless a backup already exists, then atomically replaces it.
func writeResolvConf(dns []netip.Addr) error {
	if _, err := os.Lstat(resolvConfBackup); errors.Is(err, os.ErrNotExist) {
		fi, err := os.Lstat(resolvConf)
		switch {
		case err != nil && !errors.Is(err, os.ErrNotExist):
			return err
		case err == nil && fi.Mode()&os.ModeSymlink != 0:
			target, err := os.Readlink(resolvConf)
			if err != nil {
				return err
			}
			if err := os.Symlink(target, resolvConfBackup); err != nil {
				return err
			}
		case err == nil:
			data, err := os.ReadFile(resolvConf)
			if err != nil {
				return err
			}
			if err := writeFileAtomic(resolvConfBackup, data, 0o644); err != nil {
				return err
			}
		default: // no resolv.conf: an empty one behaves the same for glibc
			if err := writeFileAtomic(resolvConfBackup, nil, 0o644); err != nil {
				return err
			}
		}
	}
	return writeFileAtomic(resolvConf, resolvConfContent(dns), 0o644)
}

// restoreResolvConf undoes writeResolvConf. No backup = nothing to do.
func restoreResolvConf() error {
	fi, err := os.Lstat(resolvConfBackup)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		target, err := os.Readlink(resolvConfBackup)
		if err != nil {
			return err
		}
		_ = os.Remove(resolvConfTmp)
		if err := os.Symlink(target, resolvConfTmp); err != nil {
			return err
		}
		if err := os.Rename(resolvConfTmp, resolvConf); err != nil {
			return err
		}
		return os.Remove(resolvConfBackup)
	}
	if !fi.Mode().IsRegular() {
		return errors.New("tunnel: unexpected resolv.conf backup type")
	}
	return os.Rename(resolvConfBackup, resolvConf)
}

func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	tmp := path + ".pvp-tmp"
	_ = os.Remove(tmp)
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW, perm)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp, path)
	}
	if err != nil {
		_ = os.Remove(tmp)
	}
	return err
}

func (t *linuxTunnel) removeRules() {
	t.removeRulesFamily("-4")
	t.removeRulesFamily("-6")
}

// removeRulesFamily deletes every rule with our priorities and flushes our
// table (tunnel route and blackhole).
func (t *linuxTunnel) removeRulesFamily(fam string) {
	for _, prio := range linuxAllPrios {
		t.deleteRulesByPrio(fam, prio)
	}
	_ = t.ipCmd("ip route", fam, "route", "flush", "table", linuxTable)
}

// deleteRulesByPrio removes every rule at prio (duplicates included).
func (t *linuxTunnel) deleteRulesByPrio(fam, prio string) {
	for i := 0; i < 64; i++ {
		if t.ipCmd("ip rule", fam, "rule", "del", "priority", prio) != nil {
			return
		}
	}
}

func linkExists(name string) bool {
	_, err := os.Lstat("/sys/class/net/" + name)
	return err == nil
}

// blockLeftover reports whether a kill switch from an earlier session is in
// place (blackhole in our table, or the persisted boot record).
func (t *linuxTunnel) blockLeftover() bool {
	if _, err := os.Lstat(filepath.Join(ksStateDir, ksStateFile)); err == nil {
		return true
	}
	return t.blackholePresent()
}

func (t *linuxTunnel) blackholePresent() bool {
	out, err := run("ip route show", t.ip, "-4", "route", "show", "table", linuxTable)
	return err == nil && routeShowHasBlackhole(out)
}

func (t *linuxTunnel) cleanupStale() {
	t.blockOn = t.blockLeftover()
	if linkExists(linuxIfName) {
		_ = t.ipCmd("ip link", "link", "del", "dev", linuxIfName)
	}
	if t.blockOn {
		t.log.Printf("tunnel", "a kill-switch block from an earlier session is in place; keeping it until Disconnect")
		return
	}
	t.removeRules()
	if err := restoreResolvConf(); err != nil {
		t.log.Printf("tunnel", "restoring resolv.conf backup failed: %v", err)
	}
}

// teardown removes the tunnel. With keepBlock the rules, the blackhole and
// a resolv.conf pointing at the (dead) tunnel resolver stay — Down undoes
// them; the tunnel route disappears with the interface.
func (t *linuxTunnel) teardown(s *linuxSession, keepBlock bool) {
	if s.dns == dnsResolvConf && !keepBlock {
		if err := restoreResolvConf(); err != nil {
			t.log.Printf("tunnel", "restoring resolv.conf failed (retried at next start): %v", err)
		}
	}
	if !keepBlock {
		t.removeRules()
	}
	if s.wg != nil {
		s.wg.close()
	} else if s.tdev != nil {
		s.tdev.Close()
	}
	if linkExists(s.ifname) {
		_ = t.ipCmd("ip link", "link", "del", "dev", s.ifname)
	}
}

func (t *linuxTunnel) downLocked(keepBlock bool) {
	if t.sess == nil {
		return
	}
	t.teardown(t.sess, keepBlock && t.blockOn)
	t.sess = nil
	t.log.Printf("tunnel", "down")
}

// removeBlock lifts the kill switch: rules, table, boot unit, state file
// and the resolv.conf backup (also leftovers of an earlier session).
func (t *linuxTunnel) removeBlock() error {
	t.removeRules()
	var err error
	if t.blackholePresent() {
		err = errors.New("tunnel: the blackhole route is still in place")
	}
	if e := t.removeBoot(); e != nil {
		t.log.Printf("tunnel", "removing the boot-time block: %v", e)
		if err == nil {
			err = e
		}
	}
	if e := restoreResolvConf(); e != nil {
		t.log.Printf("tunnel", "restoring resolv.conf failed (retried at next start): %v", e)
	}
	if err == nil {
		t.blockOn = false
		t.log.Printf("tunnel", "kill switch removed")
	}
	return err
}

func (t *linuxTunnel) SetEndpoint(ep netip.AddrPort) error {
	if err := CheckEndpoint(ep); err != nil {
		return err
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.sess == nil {
		return errNotUp
	}
	s := t.sess
	// New rule first, so packets to the new endpoint never enter the tunnel
	// (or the blackhole), then the old one goes.
	var rerr error
	if err := t.ipCmd("ip rule", linuxEndpointRuleArgs("add", ep.Addr(), linuxPrioEndpoint)...); err != nil && !isExistsErr(err) {
		rerr = err
	}
	if rerr == nil {
		t.sweepStaleRules(ep.Addr(), s.dnsAddr)
		if s.ks {
			if err := t.writeKSState(ep.Addr(), s.allowLAN); err != nil {
				t.log.Printf("tunnel", "kill switch state not updated: %v", err)
			}
		}
		s.ep = ep.Addr()
	}
	if err := s.wg.setEndpoint(ep); err != nil {
		return err
	}
	return rerr
}

func (t *linuxTunnel) Status() (Status, error) {
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

// RouteAdd is a no-op on Linux: marked sockets already use the main table.
func (t *linuxTunnel) RouteAdd(dst netip.Addr) error { return CheckPublicIPv4(dst) }

// RouteDel is a no-op on Linux.
func (t *linuxTunnel) RouteDel(dst netip.Addr) error { return CheckPublicIPv4(dst) }

// EndpointRouteOK is always true on Linux (fwmark, no endpoint route).
func (t *linuxTunnel) EndpointRouteOK() bool { return true }

// Down removes the tunnel and the kill switch (also a leftover one).
func (t *linuxTunnel) Down() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.downLocked(false)
	return t.removeBlock()
}

// Close removes the tunnel but keeps a kill-switch block in place.
func (t *linuxTunnel) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.downLocked(true)
	t.closed = true
	return nil
}

// ---- kill switch: boot persistence (systemd) ----

func (t *linuxTunnel) writeKSState(ep netip.Addr, allowLAN bool) error {
	data, err := encodeKSState(ep, allowLAN)
	if err != nil {
		return err
	}
	return writeRootFile(ksStateDir, ksStateFile, data, 0o600)
}

func systemdPresent() bool {
	fi, err := os.Stat(systemdDir)
	return err == nil && fi.IsDir()
}

// persistBoot records the boot block's inputs, copies the executable to a
// root-owned place and enables a oneshot unit that runs it before the
// network comes up. Needs root (a setcap-only process cannot write /etc).
func (t *linuxTunnel) persistBoot(ep netip.Addr, allowLAN bool) error {
	if !systemdPresent() {
		return errors.New("systemd is not running this system")
	}
	if err := t.writeKSState(ep, allowLAN); err != nil {
		return err
	}
	bin, err := copyRootExe(ksBinDir, ksBinName)
	if err != nil {
		return err
	}
	if err := writeRootFile(ksUnitDir, ksUnitName, []byte(systemdUnit(bin)), 0o644); err != nil {
		return err
	}
	if err := os.MkdirAll(ksUnitWants, 0o755); err != nil {
		return err
	}
	link := filepath.Join(ksUnitWants, ksUnitName)
	target := filepath.Join(ksUnitDir, ksUnitName)
	if cur, err := os.Readlink(link); err != nil || cur != target {
		_ = os.Remove(link)
		if err := os.Symlink(target, link); err != nil {
			return err
		}
	}
	if t.systemctl != "" {
		_, _ = run("systemctl daemon-reload", t.systemctl, "daemon-reload")
	}
	return nil
}

// removeBoot disables the unit and deletes the state file, the unit and the
// binary copy. Missing pieces are fine.
func (t *linuxTunnel) removeBoot() error {
	if t.systemctl != "" {
		_, _ = run("systemctl disable", t.systemctl, "disable", "--now", "--quiet", ksUnitName)
	}
	var first error
	for _, p := range []string{filepath.Join(ksUnitWants, ksUnitName), filepath.Join(ksUnitDir, ksUnitName),
		filepath.Join(ksStateDir, ksStateFile), filepath.Join(ksBinDir, ksBinName)} {
		if err := removeIfExists(p); err != nil && first == nil {
			first = err
		}
	}
	if t.systemctl != "" {
		_, _ = run("systemctl daemon-reload", t.systemctl, "daemon-reload")
	}
	return first
}

// bootBlock is `private-vpn-pro killswitch-boot`: re-install the block recorded
// by the last session (nothing to do when there is no record). No tunnel
// route is added, so everything but the gateway endpoint and on-link
// destinations is dropped until the app reconnects or the user disconnects.
func bootBlock(log *eventlog.Log) error {
	data, err := readRootFile(ksStateDir, ksStateFile)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	ep, _, err := decodeKSState(data)
	if err != nil {
		return err
	}
	ip := findExe("/usr/sbin/ip", "/sbin/ip", "/usr/bin/ip", "/bin/ip")
	if ip == "" {
		return errors.New("tunnel: the ip command (iproute2) was not found")
	}
	t := &linuxTunnel{log: log, ip: ip}
	mark := strconv.Itoa(linuxFwMark)
	_ = os.WriteFile("/proc/sys/net/ipv4/conf/all/src_valid_mark", []byte("1"), 0o644)
	if _, err := t.installBlock("-4", mark, ep, netip.Addr{}); err != nil {
		return err
	}
	if ipv6Enabled() {
		if _, err := t.installBlock("-6", mark, netip.Addr{}, netip.Addr{}); err != nil {
			log.Printf("tunnel", "IPv6 boot block not installed: %v", err)
		}
	}
	log.Printf("tunnel", "boot-time kill switch installed")
	return nil
}
