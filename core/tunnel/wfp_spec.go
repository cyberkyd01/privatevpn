package tunnel

import (
	"encoding/binary"
	"net/netip"
)

// Windows Filtering Platform plan (pure; wfp_windows.go applies it).
//
// Two filter sets are built from the same code:
//
//   - kill switch (Config.KillSwitch): persistent objects in a non-dynamic
//     session with deterministic keys, so they survive the helper, the app,
//     BFE restarts and reboots, and any later elevated process can delete
//     them by key (Down, `private-vpn-pro unblock`);
//   - DNS-only leak protection (no kill switch): the same DNS filters in a
//     dynamic session that dies with the helper.
//
// Within our sublayer the highest weight wins; a Block is final, a Permit
// can still be overridden by a Block in a lower-weight sublayer (Windows
// Firewall keeps its say over inbound traffic).

// wfpGUID has the layout of windows.GUID (convertible on Windows).
type wfpGUID struct {
	Data1 uint32
	Data2 uint16
	Data3 uint16
	Data4 [8]byte
}

// Fixed identities. Changing them would orphan objects of older builds.
var (
	wfpProviderKey = wfpGUID{0x7A0E5C11, 0x2B4D, 0x4E8F, [8]byte{0x9C, 0x1A, 0x50, 0x56, 0x50, 0x50, 0x56, 0x01}}
	wfpSublayerKey = wfpGUID{0x7A0E5C11, 0x2B4D, 0x4E8F, [8]byte{0x9C, 0x1A, 0x50, 0x56, 0x50, 0x50, 0x56, 0x02}}
	wfpFilterBase  = wfpGUID{0x7A0E5C11, 0x2B4D, 0x4E8F, [8]byte{0x9C, 0x1A, 0x50, 0x56, 0x50, 0x50, 0x00, 0x00}}
)

// wfpMaxFilters bounds the deterministic key range: Down deletes keys
// 0..wfpMaxFilters-1 without knowing how many were installed.
const wfpMaxFilters = 64

// wfpFilterKey returns the persistent key of filter number i.
func wfpFilterKey(i int) wfpGUID {
	g := wfpFilterBase
	g.Data4[6] = byte(i >> 8)
	g.Data4[7] = byte(i)
	return g
}

type wfpLayer uint8

const (
	wfpConnectV4 wfpLayer = iota
	wfpRecvV4
	wfpConnectV6
	wfpRecvV6
)

var wfpAllLayers = []wfpLayer{wfpConnectV4, wfpRecvV4, wfpConnectV6, wfpRecvV6}

type wfpField uint8

const (
	wfpFieldRemoteAddr wfpField = iota
	wfpFieldLocalAddr
	wfpFieldProtocol
	wfpFieldLocalPort
	wfpFieldRemotePort
	wfpFieldLocalInterface
	wfpFieldAppID
	wfpFieldFlags
	wfpFieldICMPType // = local port
	wfpFieldICMPCode // = remote port
)

type wfpKind uint8

const (
	wfpU8 wfpKind = iota
	wfpU16
	wfpU32   // also an exact IPv4 address (host order)
	wfpU64   // interface LUID
	wfpV4Net // IPv4 address + mask
	wfpV6Net // IPv6 address + prefix length
	wfpV6Addr
	wfpAppID
	wfpFlagsAllSet // FLAGS field with FWP_MATCH_FLAGS_ALL_SET
)

// wfpCond is one filter condition. Repeating a field ORs its conditions.
type wfpCond struct {
	Field  wfpField
	Kind   wfpKind
	Num    uint64
	Prefix netip.Prefix
}

// wfpFilter is one filter; its index in the plan is its persistent key.
type wfpFilter struct {
	Name   string
	Layer  wfpLayer
	Permit bool
	Weight uint8
	Conds  []wfpCond
}

// wfpSpec is what the filter set depends on.
type wfpSpec struct {
	KillSwitch bool
	TunnelLUID uint64 // 0 = no tunnel interface (boot block)
	Endpoint   netip.Addr
	DNS        []netip.Addr
	AllowLAN   bool
}

// Weights (higher wins within the sublayer).
const (
	wfpWeightApp       = 15 // private-vpn-pro.exe: gateway role, control plane, WireGuard socket
	wfpWeightDNSPermit = 14 // DNS to the tunnel resolver
	wfpWeightDNSBlock  = 13 // DNS anywhere else (above LAN and tunnel permits)
	wfpWeightPermit    = 12 // tunnel, loopback, endpoint, DHCP, NDP
	wfpWeightLAN       = 11
	wfpWeightBlock     = 0
)

const (
	ipprotoICMPv6 = 58
	ipprotoTCP    = 6
	ipprotoUDP    = 17
)

func condU8(f wfpField, v uint8) wfpCond   { return wfpCond{Field: f, Kind: wfpU8, Num: uint64(v)} }
func condU16(f wfpField, v uint16) wfpCond { return wfpCond{Field: f, Kind: wfpU16, Num: uint64(v)} }
func condV4(f wfpField, p netip.Prefix) wfpCond {
	if p.Bits() == 32 {
		b := p.Addr().As4()
		return wfpCond{Field: f, Kind: wfpU32, Num: uint64(binary.BigEndian.Uint32(b[:]))}
	}
	return wfpCond{Field: f, Kind: wfpV4Net, Prefix: p.Masked()}
}
func condV6(f wfpField, p netip.Prefix) wfpCond {
	if p.Bits() == 128 {
		return wfpCond{Field: f, Kind: wfpV6Addr, Prefix: p}
	}
	return wfpCond{Field: f, Kind: wfpV6Net, Prefix: p.Masked()}
}

var (
	dnsConds = []wfpCond{
		condU16(wfpFieldRemotePort, 53),
		condU8(wfpFieldProtocol, ipprotoUDP),
		condU8(wfpFieldProtocol, ipprotoTCP),
	}
	pfxLinkLocalV6 = netip.MustParsePrefix("fe80::/10")
	pfxMulticastV6 = netip.MustParsePrefix("ff00::/8")
	pfxMulticastV4 = netip.MustParsePrefix("224.0.0.0/4")
	pfxBroadcastV4 = netip.MustParsePrefix("255.255.255.255/32")
	dhcpV6Servers  = netip.MustParsePrefix("ff02::1:2/128")
	dhcpV6Site     = netip.MustParsePrefix("ff05::1:3/128")
	ndpRouters     = netip.MustParsePrefix("ff02::2/128")
)

// buildWFPFilters returns the ordered filter plan for s. The order is
// deterministic (index = persistent key) and bounded by wfpMaxFilters.
func buildWFPFilters(s wfpSpec) []wfpFilter {
	var fs []wfpFilter
	add := func(name string, layer wfpLayer, permit bool, weight uint8, conds ...wfpCond) {
		fs = append(fs, wfpFilter{Name: name, Layer: layer, Permit: permit, Weight: weight, Conds: conds})
	}
	app := wfpCond{Field: wfpFieldAppID, Kind: wfpAppID}

	if !s.KillSwitch {
		// DNS-only: block port 53 except to the tunnel resolver and from
		// our own executable (dual-role forwarder upstream, §7.4).
		for _, l := range wfpAllLayers {
			add("Private VPN Pro: block DNS", l, false, wfpWeightDNSBlock, dnsConds...)
		}
		if c := dnsPermitConds(s.DNS); c != nil {
			add("Private VPN Pro: permit tunnel DNS", wfpConnectV4, true, wfpWeightDNSPermit, c...)
			add("Private VPN Pro: permit tunnel DNS", wfpRecvV4, true, wfpWeightDNSPermit, c...)
		}
		for _, l := range wfpAllLayers {
			add("Private VPN Pro: permit own DNS", l, true, wfpWeightDNSPermit, append(append([]wfpCond(nil), dnsConds...), app)...)
		}
		return fs
	}

	// Our own executable: control plane, WireGuard socket, gateway role.
	for _, l := range wfpAllLayers {
		add("Private VPN Pro: permit private-vpn-pro.exe", l, true, wfpWeightApp, app)
	}
	// DNS: only the tunnel resolver.
	if c := dnsPermitConds(s.DNS); c != nil {
		add("Private VPN Pro: permit tunnel DNS", wfpConnectV4, true, wfpWeightDNSPermit, c...)
		add("Private VPN Pro: permit tunnel DNS", wfpRecvV4, true, wfpWeightDNSPermit, c...)
	}
	for _, l := range wfpAllLayers {
		add("Private VPN Pro: block DNS", l, false, wfpWeightDNSBlock, dnsConds...)
	}
	// The tunnel interface itself.
	if s.TunnelLUID != 0 {
		for _, l := range wfpAllLayers {
			add("Private VPN Pro: permit tunnel interface", l, true, wfpWeightPermit, wfpCond{Field: wfpFieldLocalInterface, Kind: wfpU64, Num: s.TunnelLUID})
		}
	}
	// Loopback.
	for _, l := range wfpAllLayers {
		add("Private VPN Pro: permit loopback", l, true, wfpWeightPermit, wfpCond{Field: wfpFieldFlags, Kind: wfpFlagsAllSet, Num: 1})
	}
	// Everything to/from the gateway endpoint (WireGuard and control share
	// the address; ports are not restricted).
	if s.Endpoint.IsValid() && s.Endpoint.Is4() {
		ep := condV4(wfpFieldRemoteAddr, netip.PrefixFrom(s.Endpoint.Unmap(), 32))
		add("Private VPN Pro: permit gateway endpoint", wfpConnectV4, true, wfpWeightPermit, ep)
		add("Private VPN Pro: permit gateway endpoint", wfpRecvV4, true, wfpWeightPermit, ep)
	}
	// DHCPv4 (any server address: renewals are unicast).
	dhcp4 := []wfpCond{condU8(wfpFieldProtocol, ipprotoUDP), condU16(wfpFieldLocalPort, 68), condU16(wfpFieldRemotePort, 67)}
	add("Private VPN Pro: permit DHCP request", wfpConnectV4, true, wfpWeightPermit, dhcp4...)
	add("Private VPN Pro: permit DHCP reply", wfpRecvV4, true, wfpWeightPermit, dhcp4...)
	// DHCPv6 (as wireguard-windows).
	add("Private VPN Pro: permit DHCPv6 request", wfpConnectV6, true, wfpWeightPermit,
		condU8(wfpFieldProtocol, ipprotoUDP),
		condV6(wfpFieldRemoteAddr, dhcpV6Servers), condV6(wfpFieldRemoteAddr, dhcpV6Site),
		condU16(wfpFieldRemotePort, 547),
		condV6(wfpFieldLocalAddr, pfxLinkLocalV6), condU16(wfpFieldLocalPort, 546))
	add("Private VPN Pro: permit DHCPv6 reply", wfpRecvV6, true, wfpWeightPermit,
		condU8(wfpFieldProtocol, ipprotoUDP),
		condV6(wfpFieldRemoteAddr, pfxLinkLocalV6), condU16(wfpFieldRemotePort, 547),
		condV6(wfpFieldLocalAddr, pfxLinkLocalV6), condU16(wfpFieldLocalPort, 546))
	// Neighbour discovery (ICMPv6 133–137).
	icmp6 := func(typ uint16) []wfpCond {
		return []wfpCond{condU8(wfpFieldProtocol, ipprotoICMPv6), condU16(wfpFieldICMPType, typ), condU16(wfpFieldICMPCode, 0)}
	}
	add("Private VPN Pro: permit NDP 133", wfpConnectV6, true, wfpWeightPermit, append(icmp6(133), condV6(wfpFieldRemoteAddr, ndpRouters))...)
	add("Private VPN Pro: permit NDP 134", wfpRecvV6, true, wfpWeightPermit, append(icmp6(134), condV6(wfpFieldRemoteAddr, pfxLinkLocalV6))...)
	add("Private VPN Pro: permit NDP 135", wfpConnectV6, true, wfpWeightPermit, icmp6(135)...)
	add("Private VPN Pro: permit NDP 135", wfpRecvV6, true, wfpWeightPermit, icmp6(135)...)
	add("Private VPN Pro: permit NDP 136", wfpConnectV6, true, wfpWeightPermit, icmp6(136)...)
	add("Private VPN Pro: permit NDP 136", wfpRecvV6, true, wfpWeightPermit, icmp6(136)...)
	add("Private VPN Pro: permit NDP 137", wfpRecvV6, true, wfpWeightPermit, append(icmp6(137), condV6(wfpFieldRemoteAddr, pfxLinkLocalV6))...)
	// LAN.
	if s.AllowLAN {
		var out4, in4 []wfpCond
		for _, p := range lanV4 {
			out4 = append(out4, condV4(wfpFieldRemoteAddr, netip.MustParsePrefix(p)))
			in4 = append(in4, condV4(wfpFieldRemoteAddr, netip.MustParsePrefix(p)))
		}
		out4 = append(out4, condV4(wfpFieldRemoteAddr, pfxMulticastV4), condV4(wfpFieldRemoteAddr, pfxBroadcastV4))
		add("Private VPN Pro: permit LAN", wfpConnectV4, true, wfpWeightLAN, out4...)
		add("Private VPN Pro: permit LAN", wfpRecvV4, true, wfpWeightLAN, in4...)
		add("Private VPN Pro: permit LAN", wfpConnectV6, true, wfpWeightLAN, condV6(wfpFieldRemoteAddr, pfxLinkLocalV6), condV6(wfpFieldRemoteAddr, pfxMulticastV6))
		add("Private VPN Pro: permit LAN", wfpRecvV6, true, wfpWeightLAN, condV6(wfpFieldRemoteAddr, pfxLinkLocalV6))
	}
	// Everything else.
	for _, l := range wfpAllLayers {
		add("Private VPN Pro: block all", l, false, wfpWeightBlock)
	}
	return fs
}

// dnsPermitConds permits DNS (UDP/TCP 53) to the IPv4 resolvers, or nil.
func dnsPermitConds(dns []netip.Addr) []wfpCond {
	conds := append([]wfpCond(nil), dnsConds...)
	n := 0
	for _, a := range dns {
		if a.Is4() {
			conds = append(conds, condV4(wfpFieldRemoteAddr, netip.PrefixFrom(a.Unmap(), 32)))
			n++
		}
	}
	if n == 0 {
		return nil
	}
	return conds
}
