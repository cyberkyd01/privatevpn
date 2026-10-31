//go:build windows

package sysinfo

import (
	"fmt"
	"net/netip"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

const (
	osName      = "windows"
	deviceLabel = "PC"
)

// On Windows virtual adapters are identified by interface type and
// description (virtualIfaces / isVirtualAdapter), not by name.
var virtualPrefixes []string

// virtualDescriptions are adapter-description substrings of host-only VM
// adapters (their IfType is plain Ethernet). Hyper-V's vEthernet is not
// listed: with an external switch it carries the host's real LAN address.
var virtualDescriptions = []string{"vmware virtual ethernet", "virtualbox host-only"}

// osVersion uses RtlGetVersion (not subject to the manifest version lie).
func osVersion() string {
	v := windows.RtlGetVersion()
	return fmt.Sprintf("%d.%d.%d", v.MajorVersion, v.MinorVersion, v.BuildNumber)
}

// uptime uses GetTickCount64.
func uptime() time.Duration { return windows.DurationSinceBoot() }

// systemTZName: Windows has no IANA zone name; the caller falls back to the
// GeoIP provider's zone (§10.5).
func systemTZName() string { return "" }

func isVirtualAdapter(a *winipcfg.IPAdapterAddresses) bool {
	switch a.IfType {
	case winipcfg.IfTypeSoftwareLoopback, winipcfg.IfTypeTunnel, winipcfg.IfTypePropVirtual:
		return true
	}
	if isOurTunnel(a.FriendlyName()) {
		return true
	}
	desc := strings.ToLower(a.Description())
	for _, d := range virtualDescriptions {
		if strings.Contains(desc, d) {
			return true
		}
	}
	return false
}

// virtualIfaces returns the indexes (IPv4 and IPv6) of virtual adapters.
func virtualIfaces() map[int]bool {
	aas, err := winipcfg.GetAdaptersAddresses(windows.AF_UNSPEC,
		winipcfg.GAAFlagSkipUnicast|winipcfg.GAAFlagSkipAnycast|winipcfg.GAAFlagSkipMulticast|winipcfg.GAAFlagSkipDNSServer)
	if err != nil {
		return nil
	}
	m := map[int]bool{}
	for _, a := range aas {
		if isVirtualAdapter(a) {
			if a.IfIndex != 0 {
				m[int(a.IfIndex)] = true
			}
			if a.IPv6IfIndex != 0 {
				m[int(a.IPv6IfIndex)] = true
			}
		}
	}
	return m
}

// systemResolvers returns the DNS servers of up, physical adapters.
func systemResolvers() []netip.AddrPort {
	aas, err := winipcfg.GetAdaptersAddresses(windows.AF_UNSPEC,
		winipcfg.GAAFlagSkipUnicast|winipcfg.GAAFlagSkipAnycast|winipcfg.GAAFlagSkipMulticast)
	if err != nil {
		return nil
	}
	var out []netip.AddrPort
	for _, a := range aas {
		if a.OperStatus != winipcfg.IfOperStatusUp || isVirtualAdapter(a) {
			continue
		}
		for dns := a.FirstDNSServerAddress; dns != nil; dns = dns.Next {
			ip, ok := netip.AddrFromSlice(dns.Address.IP())
			if !ok {
				continue
			}
			ip = ip.Unmap()
			if isWindowsPlaceholderDNS(ip) {
				continue
			}
			out = append(out, netip.AddrPortFrom(ip.WithZone(""), 53))
		}
	}
	return out
}

// isWindowsPlaceholderDNS reports the deprecated site-local resolvers
// fec0:0:0:ffff::1..3 that Windows lists on adapters without IPv6 DNS.
func isWindowsPlaceholderDNS(ip netip.Addr) bool {
	for i := byte(1); i <= 3; i++ {
		if ip == netip.AddrFrom16([16]byte{0xfe, 0xc0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, i}) {
			return true
		}
	}
	return false
}
