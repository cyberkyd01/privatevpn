//go:build !windows

package sysinfo

import (
	"bufio"
	"io"
	"net/netip"
	"os"
	"strings"
)

// Indirections for tests.
var (
	lookupEnv     = os.LookupEnv
	localtimePath = "/etc/localtime"
	timezoneFile  = "/etc/timezone" // Debian/Ubuntu fallback
	resolvConf    = "/etc/resolv.conf"
)

// systemTZName returns $TZ if set, else the zone named by the
// /etc/localtime symlink target, else /etc/timezone, else "".
func systemTZName() string {
	if v, ok := lookupEnv("TZ"); ok {
		return zoneFromTZEnv(v)
	}
	if target, err := os.Readlink(localtimePath); err == nil {
		if name := zoneFromPath(target); name != "" {
			return name
		}
	}
	if f, err := os.Open(timezoneFile); err == nil {
		defer f.Close()
		sc := bufio.NewScanner(io.LimitReader(f, 256))
		if sc.Scan() {
			if name := strings.TrimSpace(sc.Text()); validTZName(name) && !strings.Contains(name, "..") {
				return name
			}
		}
	}
	return ""
}

// systemResolvers reads /etc/resolv.conf (absent on Android, where the app
// supplies resolvers through SetMobileInfo).
func systemResolvers() []netip.AddrPort { return readResolvConf(resolvConf) }

// virtualIfaces is only meaningful on Windows.
func virtualIfaces() map[int]bool { return nil }
