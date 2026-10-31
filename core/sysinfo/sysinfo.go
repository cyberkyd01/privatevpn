// Package sysinfo reports facts about this device for the gateway details
// panel (ARCHITECTURE §10.1, §10.5) and for the gateway's host-address deny
// list (§8.5): OS name and version, uptime, LAN and host addresses, time
// zone, system resolvers, and a network-change Watcher (§10.3).
//
// Everything here describes this device only. Nothing is logged.
//
// Per-OS code lives in build-tagged files (windows, darwin,
// linux && !android, android). On Android the Kotlin side supplies the values
// Go cannot obtain itself through SetMobileInfo.
package sysinfo

import (
	"crypto/rand"
	"encoding/hex"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"
)

// Field caps (ARCHITECTURE §10.5).
const (
	maxOSVersion = 32
	maxModel     = 32
	maxTZName    = 64
	maxAbbrev    = 8
	maxResolvers = 16
)

// mobile holds values supplied by the Android app (SetMobileInfo).
var mobile struct {
	sync.RWMutex
	osVersion string
	model     string
	tz        string
	dns       []netip.AddrPort
}

// OSName returns "windows", "macos", "linux" or "android".
func OSName() string { return osName }

var (
	osVersionOnce   sync.Once
	osVersionCached string
)

// OSVersion returns the OS version (≤ 32 characters), e.g. "10.0.22631",
// "15.6", "24.04". The system value is computed once and cached; a value
// supplied through SetMobileInfo takes precedence.
func OSVersion() string {
	mobile.RLock()
	v := mobile.osVersion
	mobile.RUnlock()
	if v != "" {
		return v
	}
	osVersionOnce.Do(func() { osVersionCached = clean(osVersion(), maxOSVersion) })
	return osVersionCached
}

// Hostname returns the device's host name, or "" if unknown. When the
// Android app supplied a device model through SetMobileInfo, that is
// returned instead (Android host names are always "localhost").
func Hostname() string {
	mobile.RLock()
	m := mobile.model
	mobile.RUnlock()
	if m != "" {
		return m
	}
	h, err := os.Hostname()
	if err != nil {
		return ""
	}
	return clean(h, 255)
}

// DefaultDeviceName returns a non-identifying default device name of the
// form "<label>-<4 hex>" ("PC-1A2B", "Mac-1A2B", "Linux-1A2B",
// "Phone-1A2B"). The suffix is random on every call; the caller persists the
// chosen name.
func DefaultDeviceName() string {
	var b [2]byte
	_, _ = rand.Read(b[:]) // crypto/rand.Read never fails (Go ≥ 1.24)
	return deviceLabel + "-" + strings.ToUpper(hex.EncodeToString(b[:]))
}

// Uptime returns the time since the device booted.
func Uptime() time.Duration {
	d := uptime()
	if d < 0 {
		return 0
	}
	return d
}

// TimeZone returns the IANA zone name (or "" when the OS cannot provide one,
// e.g. on Windows — the caller then falls back to the GeoIP provider's zone),
// and the current UTC offset in seconds and zone abbreviation (≤ 8 chars)
// from time.Now().Zone().
//
// On Android the zone supplied through SetMobileInfo is used, and the offset
// and abbreviation are computed in that zone (Go's time.Local is UTC there).
func TimeZone() (name string, offsetSec int, abbrev string) {
	now := time.Now()
	mobile.RLock()
	name = mobile.tz
	mobile.RUnlock()
	if name != "" {
		if loc, err := time.LoadLocation(name); err == nil {
			abbrev, offsetSec = now.In(loc).Zone()
			return name, offsetSec, clean(abbrev, maxAbbrev)
		}
	} else {
		name = systemTZName()
	}
	abbrev, offsetSec = now.Zone()
	return name, offsetSec, clean(abbrev, maxAbbrev)
}

// Resolvers returns the system DNS servers (port 53 unless stated
// otherwise), loopback resolvers included, at most 16, without duplicates.
// Servers supplied through SetMobileInfo take precedence.
func Resolvers() []netip.AddrPort {
	mobile.RLock()
	dns := mobile.dns
	mobile.RUnlock()
	if len(dns) > 0 {
		return append([]netip.AddrPort(nil), dns...)
	}
	return dedupeAddrPorts(systemResolvers(), maxResolvers)
}

// SetMobileInfo is called by the Android app with values Go cannot obtain
// itself: the Android version (Build.VERSION.RELEASE), the device model
// (Build.MODEL, returned by Hostname), the IANA zone
// (TimeZone.getDefault().id) and the current DNS servers (LinkProperties).
// Non-empty values override the system values on every OS; empty values
// clear the override. Invalid entries are ignored.
func SetMobileInfo(osVersion, model, tz string, dns []string) {
	var servers []netip.AddrPort
	for _, s := range dns {
		if ap, ok := parseServer(s); ok {
			servers = append(servers, ap)
		}
	}
	servers = dedupeAddrPorts(servers, maxResolvers)
	tz = strings.TrimSpace(tz)
	if !validTZName(tz) {
		tz = ""
	}
	mobile.Lock()
	mobile.osVersion = clean(osVersion, maxOSVersion)
	mobile.model = clean(model, maxModel)
	mobile.tz = tz
	mobile.dns = servers
	mobile.Unlock()
}

// parseServer accepts "1.2.3.4", "2001:db8::1", "[2001:db8::1]:5353" or
// "1.2.3.4:5353".
func parseServer(s string) (netip.AddrPort, bool) {
	s = strings.TrimSpace(s)
	if a, err := netip.ParseAddr(s); err == nil {
		return netip.AddrPortFrom(a.Unmap(), 53), true
	}
	if ap, err := netip.ParseAddrPort(s); err == nil && ap.Port() != 0 {
		return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()), true
	}
	return netip.AddrPort{}, false
}

func dedupeAddrPorts(in []netip.AddrPort, max int) []netip.AddrPort {
	var out []netip.AddrPort
	seen := make(map[netip.AddrPort]bool, len(in))
	for _, ap := range in {
		if !ap.IsValid() || seen[ap] {
			continue
		}
		seen[ap] = true
		out = append(out, ap)
		if len(out) == max {
			break
		}
	}
	return out
}

// validTZName reports whether s matches ^[A-Za-z0-9_+\-/]{1,64}$ (§10.5).
func validTZName(s string) bool {
	if len(s) == 0 || len(s) > maxTZName {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case c == '_', c == '+', c == '-', c == '/':
		default:
			return false
		}
	}
	return true
}

// clean trims s, removes C0/C1 control and bidi control characters, and
// truncates it to max runes (the last one being "…" when truncated). It
// mirrors geo.Sanitize; it is duplicated to keep sysinfo dependency-free.
func clean(s string, max int) string {
	if max <= 0 {
		return ""
	}
	s = strings.ToValidUTF8(s, "")
	s = strings.Map(func(r rune) rune {
		if isStripped(r) {
			return -1
		}
		return r
	}, s)
	s = strings.TrimSpace(s)
	if utf8.RuneCountInString(s) <= max {
		return s
	}
	n := 0
	for i := range s {
		if n == max-1 {
			s = s[:i]
			break
		}
		n++
	}
	return strings.TrimRightFunc(s, unicode.IsSpace) + "…"
}

func isStripped(r rune) bool {
	switch {
	case r < 0x20, r == 0x7f, r >= 0x80 && r <= 0x9f: // C0, DEL, C1
		return true
	case r >= 0x202a && r <= 0x202e, r >= 0x2066 && r <= 0x2069: // bidi embeddings/isolates
		return true
	case r == 0x200e, r == 0x200f, r == 0x061c: // LRM, RLM, ALM
		return true
	}
	return false
}
