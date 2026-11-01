package tunnel

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"net/netip"
	"sort"
	"strconv"
	"strings"
)

// Kill switch: pure, OS-independent pieces (unit tested on every OS). The
// OS files apply them.
//
// Boot persistence record. While the kill switch is engaged, macOS and Linux
// keep a tiny root-owned file with what the boot-time block needs: the last
// gateway endpoint (so a reconnect can reach it) and whether LAN stays
// reachable. It holds no keys and no addresses other than the gateway's.

const ksStateVersion = 1

// ksState is the persisted record (killswitch.json).
type ksState struct {
	Version  int    `json:"version"`
	Endpoint string `json:"endpoint"` // IPv4 literal of the gateway endpoint
	AllowLAN bool   `json:"allow_lan"`
}

func encodeKSState(ep netip.Addr, allowLAN bool) ([]byte, error) {
	if !ep.Is4() || ep.Is4In6() {
		return nil, errors.New("kill switch state: endpoint must be IPv4")
	}
	return json.Marshal(ksState{Version: ksStateVersion, Endpoint: ep.String(), AllowLAN: allowLAN})
}

// decodeKSState strictly validates the record; a malformed file is refused
// (the boot block then installs nothing rather than something half right).
func decodeKSState(data []byte) (ep netip.Addr, allowLAN bool, err error) {
	if len(data) > 4096 {
		return netip.Addr{}, false, errors.New("kill switch state: too large")
	}
	var s ksState
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil || dec.More() || s.Version != ksStateVersion {
		return netip.Addr{}, false, errors.New("kill switch state: malformed")
	}
	a, err := netip.ParseAddr(s.Endpoint)
	if err != nil || CheckEndpoint(netip.AddrPortFrom(a, 1)) != nil {
		return netip.Addr{}, false, errors.New("kill switch state: bad endpoint")
	}
	return a, s.AllowLAN, nil
}

// ---- macOS: pf ----

// beaconGroup is the discovery multicast group (ARCHITECTURE §7.1).
const beaconGroup = "239.255.77.77"

// pfAnchor is evaluated by the stock /etc/pf.conf through its
// `anchor "com.apple/*"` line. Sub-anchors run in name order; 100 puts ours
// before Apple's (200.AirDrop, 250.ApplicationFirewall) so our `quick`
// rules decide first.
const pfAnchor = "com.apple/100.PrivateVPNPro"

// LAN ranges kept reachable with AllowLAN (RFC1918, link-local, multicast,
// broadcast). 100.64/10 (CGNAT) is deliberately not LAN.
var (
	lanV4 = []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16"}
	lanV6 = []string{"fe80::/10"}
)

// pfRules renders the anchor ruleset. ifname is the tunnel interface ("" at
// boot: nothing is permitted through a tunnel). Everything uses `quick`
// (first match wins) and `no state`, so flushing the state table never
// affects our decisions and no stale state can outlive a rule change.
func pfRules(ifname string, ep netip.Addr, allowLAN bool) string {
	var b strings.Builder
	w := func(s string) { b.WriteString(s + "\n") }
	w("# Private VPN Pro kill switch — removed by `private-vpn-pro unblock` or Disconnect")
	w("pass quick on lo0 all no state")
	if ifname != "" {
		w("pass quick on " + ifname + " all no state")
	}
	if ep.IsValid() {
		e := ep.Unmap().String()
		w("pass out quick inet from any to " + e + " no state")
		w("pass in quick inet from " + e + " to any no state")
	}
	// DNS goes through the tunnel only (the tunnel resolver is reached via
	// the interface rule above); nothing else may answer name lookups.
	w("block return out quick proto { tcp, udp } from any to any port 53")
	// Gateway discovery beacons (fixed multicast group, §7.1): authenticated,
	// carry no user traffic, and pf cannot permit per process like WFP.
	w("pass in quick inet proto udp from any to " + beaconGroup + " no state")
	w("pass out quick inet proto udp from any to " + beaconGroup + " no state")
	// Keep the physical link alive: DHCP, DHCPv6, neighbour discovery.
	w("pass out quick inet proto udp from any port 68 to any port 67 no state")
	w("pass in quick inet proto udp from any port 67 to any port 68 no state")
	w("pass out quick inet6 proto udp from any port 546 to any port 547 no state")
	w("pass in quick inet6 proto udp from any port 547 to any port 546 no state")
	w("pass quick inet6 proto icmp6 all icmp6-type { routersol, routeradv, neighbrsol, neighbradv, redir } no state")
	if allowLAN {
		v4 := strings.Join(append(append([]string(nil), lanV4...), "224.0.0.0/4", "255.255.255.255/32"), ", ")
		w("pass out quick inet from any to { " + v4 + " } no state")
		w("pass in quick inet from { " + strings.Join(lanV4, ", ") + " } to any no state")
		w("pass out quick inet6 from any to { fe80::/10, ff00::/8 } no state")
		w("pass in quick inet6 from fe80::/10 to any no state")
	}
	w("block drop in quick all")
	w("block return out quick all")
	return b.String()
}

// pfMainHasAppleAnchor reports whether `pfctl -s rules` (the main ruleset)
// evaluates com.apple sub-anchors — without that line our anchor is never
// consulted.
func pfMainHasAppleAnchor(out []byte) bool {
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) >= 2 && f[0] == "anchor" && f[1] == `"com.apple/*"` {
			return true
		}
	}
	return false
}

// pfEnabled parses `pfctl -s info`.
func pfEnabled(out []byte) bool {
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "Status:") {
			return strings.HasPrefix(strings.TrimSpace(strings.TrimPrefix(line, "Status:")), "Enabled")
		}
	}
	return false
}

// pfAnchorHasRules reports whether `pfctl -a <anchor> -s rules` printed any
// rule (a leftover block).
func pfAnchorHasRules(out []byte) bool {
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) > 0 && (f[0] == "block" || f[0] == "pass") {
			return true
		}
	}
	return false
}

// launchdPlist renders the LaunchDaemon that re-installs the block at boot.
// bin is the root-owned copy of the executable (never a user-writable path).
func launchdPlist(label, bin string) string {
	return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>` + label + `</string>
	<key>ProgramArguments</key>
	<array>
		<string>` + xmlEscape(bin) + `</string>
		<string>killswitch-boot</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<false/>
</dict>
</plist>
`
}

func xmlEscape(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;")
	return r.Replace(s)
}

// ---- Linux: policy routing ----

// Rule priorities. 20564–20566 are wg-quick's scheme (§9.4); the lower ones
// are the kill switch's.
const (
	linuxPrioMarkMain  = "20561" // fwmark → main: our own (marked) sockets, dual-role gateway sockets
	linuxPrioDNSMain   = "20562" // to <tunnel resolver> → main (non-default routes only)
	linuxPrioDNSBlock  = "20563" // dport 53 → blackhole: no resolver but the tunnel's
	linuxPrioEndpoint  = "20564" // to <endpoint> → main
	linuxPrioMain      = "20565" // main, suppress_prefixlength 0 (LAN / on-link)
	linuxPrioMark      = "20566" // not fwmark → table 20566 (tunnel or blackhole)
	linuxBlackholeMetr = "20566" // blackhole default metric (the pvp0 default has 0 / 1024)
	linuxTable         = "20566"
)

// linuxAllPrios lists every priority we ever create (Down deletes them all).
var linuxAllPrios = []string{linuxPrioMarkMain, linuxPrioDNSMain, linuxPrioDNSBlock, linuxPrioEndpoint, linuxPrioMain, linuxPrioMark}

// linuxEndpointRuleArgs renders the `ip` arguments that add or delete the
// endpoint-exclusion rule: everything sent to the gateway's address is looked
// up in the main table (via the physical default route) ahead of the
// suppress_prefixlength rule. Only WireGuard's own socket carries the fwmark;
// the control-plane datagrams (RENEW, LEAVE, INFO, re-JOIN) of the main
// process do not, and without this rule they would be routed into the tunnel
// when the gateway is off-LAN, where the gateway drops them (§8.5, D13).
// verb is "add" or "del".
func linuxEndpointRuleArgs(verb string, ep netip.Addr, priority string) []string {
	return []string{"-4", "rule", verb, "to", ep.Unmap().String() + "/32", "table", "main", "priority", priority}
}

// linuxDNSRuleArgs: queries to the tunnel resolver use main's non-default
// routes (the pvp0 subnet) ahead of the DNS blackhole.
func linuxDNSRuleArgs(verb string, dns netip.Addr) []string {
	return []string{"-4", "rule", verb, "to", dns.Unmap().String() + "/32", "table", "main", "suppress_prefixlength", "0", "priority", linuxPrioDNSMain}
}

// ipCmdArgs is one `ip` invocation.
type ipCmdArgs struct {
	label string
	args  []string
	// optional: failure only degrades (warning code) instead of failing Up
	warn string
}

// linuxBlockArgs returns, in order, the commands that install the fail-closed
// block for one family ("-4"/"-6"): the blackhole default in our table and
// the rules. Nothing here references the tunnel interface, so the same set is
// installed at boot. mark is the fwmark decimal. The DNS blackhole needs
// fib-rule port matching (kernel/iproute2 ≥ 4.17): it is best effort and
// reported as WarnDNSNotBlocked.
func linuxBlockArgs(fam, mark string, ep, dns netip.Addr) []ipCmdArgs {
	var out []ipCmdArgs
	add := func(label, warn string, args ...string) {
		out = append(out, ipCmdArgs{label: label, args: args, warn: warn})
	}
	add("ip route", "", fam, "route", "add", "blackhole", "default", "table", linuxTable, "metric", linuxBlackholeMetr)
	// Order matters only for readability: rules are matched by priority.
	add("ip rule", "", fam, "rule", "add", "not", "fwmark", mark, "table", linuxTable, "priority", linuxPrioMark)
	add("ip rule", "", fam, "rule", "add", "table", "main", "suppress_prefixlength", "0", "priority", linuxPrioMain)
	if fam == "-4" && ep.IsValid() {
		add("ip rule", "", linuxEndpointRuleArgs("add", ep, linuxPrioEndpoint)...)
	}
	// DNS confinement (best effort).
	add("ip rule", WarnDNSNotBlocked, fam, "rule", "add", "fwmark", mark, "table", "main", "priority", linuxPrioMarkMain)
	if fam == "-4" && dns.IsValid() {
		add("ip rule", WarnDNSNotBlocked, linuxDNSRuleArgs("add", dns)...)
	}
	add("ip rule", WarnDNSNotBlocked, fam, "rule", "add", "ipproto", "udp", "dport", "53", "blackhole", "priority", linuxPrioDNSBlock)
	add("ip rule", WarnDNSNotBlocked, fam, "rule", "add", "ipproto", "tcp", "dport", "53", "blackhole", "priority", linuxPrioDNSBlock)
	return out
}

// linuxTunnelDefaultArgs routes everything that reaches our table into the
// tunnel (beats the blackhole by metric).
func linuxTunnelDefaultArgs(fam, ifname string) []string {
	return []string{fam, "route", "add", "default", "dev", ifname, "table", linuxTable}
}

// ipRule is one parsed line of `ip rule show`.
type ipRule struct {
	Prio int
	To   string // destination without prefix length ("" = all)
}

// parseIPRules parses `ip [-4|-6] rule show` output, e.g.
// "20564:\tfrom all to 192.168.1.10 lookup main".
func parseIPRules(out []byte) []ipRule {
	var rules []ipRule
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		p, rest, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		prio, err := strconv.Atoi(strings.TrimSpace(p))
		if err != nil {
			continue
		}
		r := ipRule{Prio: prio}
		f := strings.Fields(rest)
		for i := 0; i+1 < len(f); i++ {
			if f[i] == "to" {
				r.To, _, _ = strings.Cut(f[i+1], "/")
				break
			}
		}
		rules = append(rules, r)
	}
	return rules
}

// staleHostRules lists the destinations of rules at prio other than keep
// (sorted, deduplicated): leftovers of an earlier session to delete.
func staleHostRules(rules []ipRule, prio int, keep netip.Addr) []netip.Addr {
	seen := map[netip.Addr]bool{}
	var out []netip.Addr
	for _, r := range rules {
		if r.Prio != prio || r.To == "" {
			continue
		}
		a, err := netip.ParseAddr(r.To)
		if err != nil || a == keep || seen[a] {
			continue
		}
		seen[a] = true
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Less(out[j]) })
	return out
}

// routeShowHasBlackhole parses `ip route show table 20566` for our
// blackhole default (a leftover block).
func routeShowHasBlackhole(out []byte) bool {
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) >= 2 && f[0] == "blackhole" && f[1] == "default" {
			return true
		}
	}
	return false
}

// isExistsErr reports whether a command failed only because the object was
// already there (ip: "RTNETLINK answers: File exists"; route: "File exists").
func isExistsErr(err error) bool {
	var ce *cmdError
	return errors.As(err, &ce) && strings.Contains(ce.detail, "File exists")
}

// isMissingErr reports a delete of something that is not there.
func isMissingErr(err error) bool {
	var ce *cmdError
	if !errors.As(err, &ce) {
		return false
	}
	return strings.Contains(ce.detail, "No such file or directory") || strings.Contains(ce.detail, "No such process") ||
		strings.Contains(ce.detail, "not in table") || strings.Contains(ce.detail, "Cannot find device")
}

// systemdUnit renders the oneshot unit that re-installs the block at boot,
// before the network comes up. bin is the root-owned copy of the executable.
func systemdUnit(bin string) string {
	return `[Unit]
Description=Private VPN Pro kill switch (blocks traffic until the VPN reconnects or the user disconnects)
Documentation=man:private-vpn-pro
DefaultDependencies=no
After=local-fs.target
Before=network-pre.target shutdown.target
Wants=network-pre.target
Conflicts=shutdown.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=` + systemdQuote(bin) + ` killswitch-boot

[Install]
WantedBy=sysinit.target
`
}

// systemdQuote quotes a path for ExecStart= (systemd's own quoting rules:
// double quotes with backslash escapes).
func systemdQuote(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`)
	return `"` + r.Replace(s) + `"`
}
