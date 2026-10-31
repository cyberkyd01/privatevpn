package sysinfo

import (
	"bufio"
	"io"
	"net/netip"
	"os"
	"strings"
)

// maxConfigFile caps how much of a system configuration file is read.
const maxConfigFile = 64 << 10

// parseResolvConf extracts "nameserver <addr>" entries from a resolv.conf
// (port 53; comments starting with '#' or ';' ignored; invalid addresses
// skipped). Loopback resolvers are kept.
func parseResolvConf(r io.Reader) []netip.AddrPort {
	var out []netip.AddrPort
	sc := bufio.NewScanner(io.LimitReader(r, maxConfigFile))
	for sc.Scan() {
		line := sc.Text()
		if i := strings.IndexAny(line, "#;"); i >= 0 {
			line = line[:i]
		}
		f := strings.Fields(line)
		if len(f) < 2 || f[0] != "nameserver" {
			continue
		}
		a, err := netip.ParseAddr(f[1])
		if err != nil {
			continue
		}
		out = append(out, netip.AddrPortFrom(a.Unmap(), 53))
	}
	return dedupeAddrPorts(out, maxResolvers)
}

// readResolvConf parses the resolv.conf at path; a missing file yields nil.
func readResolvConf(path string) []netip.AddrPort {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	return parseResolvConf(f)
}

// parseOSRelease returns VERSION_ID from an os-release file, unquoted.
func parseOSRelease(r io.Reader) string {
	sc := bufio.NewScanner(io.LimitReader(r, maxConfigFile))
	for sc.Scan() {
		k, v, ok := strings.Cut(strings.TrimSpace(sc.Text()), "=")
		if !ok || k != "VERSION_ID" {
			continue
		}
		v = strings.TrimSpace(v)
		if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
			v = v[1 : len(v)-1]
		}
		return clean(v, maxOSVersion)
	}
	return ""
}

// zoneFromPath extracts an IANA zone name from a path such as
// "/usr/share/zoneinfo/Europe/Berlin" or (macOS)
// "/var/db/timezone/zoneinfo/Europe/London": the part after the last
// "zoneinfo/", minus a leading "posix/" or "right/". It returns "" when the
// path holds no valid zone name.
func zoneFromPath(p string) string {
	const marker = "zoneinfo/"
	i := strings.LastIndex(p, marker)
	if i < 0 {
		return ""
	}
	name := p[i+len(marker):]
	for _, pre := range []string{"posix/", "right/"} {
		name = strings.TrimPrefix(name, pre)
	}
	if !validTZName(name) || strings.Contains(name, "..") || strings.HasPrefix(name, "/") {
		return ""
	}
	return name
}

// zoneFromTZEnv interprets a $TZ value: "" means UTC (Go's rule), a leading
// ':' is dropped, a path is reduced with zoneFromPath, and anything else
// must itself be a valid zone name (POSIX rule strings such as
// "EST5EDT,M3.2.0,M11.1.0" yield "").
func zoneFromTZEnv(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return "UTC"
	}
	v = strings.TrimPrefix(v, ":")
	if strings.HasPrefix(v, "/") {
		return zoneFromPath(v)
	}
	if !validTZName(v) || strings.Contains(v, "..") {
		return ""
	}
	return v
}
