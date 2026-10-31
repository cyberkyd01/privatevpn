package sysinfo

import (
	"net"
	"net/netip"
	"strings"
)

// maxLANIPs caps LANIPv4s (§10.5 lan_ips ≤ 8).
const maxLANIPs = 8

// ourTunnelPrefixes are name prefixes of PrivateVPN's own tunnel interfaces
// (Linux "pvn0", macOS "utunN"). On Windows the Wintun adapter is named
// "PrivateVPN" (see isOurTunnel).
var ourTunnelPrefixes = []string{"pvn", "utun"}

// isOurTunnel reports whether name is one of our tunnel interfaces.
func isOurTunnel(name string) bool {
	if strings.EqualFold(name, "PrivateVPN") {
		return true
	}
	lower := strings.ToLower(name)
	for _, p := range ourTunnelPrefixes {
		if strings.HasPrefix(lower, p) {
			return true
		}
	}
	return false
}

// isVirtualName reports whether name matches a well-known virtual interface
// prefix for this OS (virtualPrefixes, defined per OS).
func isVirtualName(name string) bool {
	lower := strings.ToLower(name)
	for _, p := range virtualPrefixes {
		if strings.HasPrefix(lower, p) {
			return true
		}
	}
	return false
}

// LANIPv4s returns up to 8 IPv4 addresses of the device's physical
// interfaces: up, not loopback, not point-to-point, not link-local, and not
// one of our own tunnel interfaces or a well-known virtual interface.
func LANIPv4s() []netip.Addr {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil
	}
	return collectLANIPv4s(ifs, interfaceAddrs, virtualIfaces())
}

// interfaceAddrs is the production address source for an interface.
func interfaceAddrs(ifi net.Interface) ([]net.Addr, error) { return ifi.Addrs() }

// collectLANIPv4s is the testable core of LANIPv4s. virtual holds interface
// indexes the OS reports as virtual (Windows only; nil elsewhere).
func collectLANIPv4s(ifs []net.Interface, addrsOf func(net.Interface) ([]net.Addr, error), virtual map[int]bool) []netip.Addr {
	var out []netip.Addr
	seen := map[netip.Addr]bool{}
	for _, ifi := range ifs {
		if ifi.Flags&net.FlagUp == 0 || ifi.Flags&(net.FlagLoopback|net.FlagPointToPoint) != 0 {
			continue
		}
		if isOurTunnel(ifi.Name) || isVirtualName(ifi.Name) || virtual[ifi.Index] {
			continue
		}
		addrs, err := addrsOf(ifi)
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ip, ok := addrOf(a)
			if !ok || !ip.Is4() || ip.IsLoopback() || ip.IsLinkLocalUnicast() ||
				ip.IsUnspecified() || ip.IsMulticast() || seen[ip] {
				continue
			}
			seen[ip] = true
			out = append(out, ip)
			if len(out) == maxLANIPs {
				return out
			}
		}
	}
	return out
}

// HostAddrs returns every address (IPv4 and IPv6) on every interface of the
// device, whatever its state, without duplicates. The gateway adds these to
// its always-deny destination list (§8.5).
func HostAddrs() []netip.Addr {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil
	}
	return collectHostAddrs(ifs, interfaceAddrs)
}

func collectHostAddrs(ifs []net.Interface, addrsOf func(net.Interface) ([]net.Addr, error)) []netip.Addr {
	var out []netip.Addr
	seen := map[netip.Addr]bool{}
	for _, ifi := range ifs {
		addrs, err := addrsOf(ifi)
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ip, ok := addrOf(a)
			if !ok || seen[ip] {
				continue
			}
			seen[ip] = true
			out = append(out, ip)
		}
	}
	return out
}

// addrOf extracts the (unmapped, zone-less) IP from a net.Addr.
func addrOf(a net.Addr) (netip.Addr, bool) {
	var ip net.IP
	switch v := a.(type) {
	case *net.IPNet:
		ip = v.IP
	case *net.IPAddr:
		ip = v.IP
	default:
		return netip.Addr{}, false
	}
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return netip.Addr{}, false
	}
	return addr.Unmap(), true
}
