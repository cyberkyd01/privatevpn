//go:build !windows

package sysinfo

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

// withTZFiles points systemTZName at a temporary /etc/localtime and
// /etc/timezone, with $TZ either unset (tz == nil) or set.
func withTZFiles(t *testing.T, linkTarget, timezone string, tz *string) {
	t.Helper()
	dir := t.TempDir()
	oldLink, oldFile, oldEnv := localtimePath, timezoneFile, lookupEnv
	t.Cleanup(func() { localtimePath, timezoneFile, lookupEnv = oldLink, oldFile, oldEnv })
	localtimePath = filepath.Join(dir, "localtime")
	timezoneFile = filepath.Join(dir, "timezone")
	if linkTarget != "" {
		if err := os.Symlink(linkTarget, localtimePath); err != nil {
			t.Fatal(err)
		}
	}
	if timezone != "" {
		if err := os.WriteFile(timezoneFile, []byte(timezone), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	lookupEnv = func(k string) (string, bool) {
		if k == "TZ" && tz != nil {
			return *tz, true
		}
		return "", false
	}
}

func TestSystemTZName(t *testing.T) {
	str := func(s string) *string { return &s }
	cases := []struct {
		name, link, file string
		tz               *string
		want             string
	}{
		{"symlink", "/usr/share/zoneinfo/Europe/Berlin", "", nil, "Europe/Berlin"},
		{"relative symlink", "../usr/share/zoneinfo/America/New_York", "", nil, "America/New_York"},
		{"macOS symlink", "/var/db/timezone/zoneinfo/Europe/London", "", nil, "Europe/London"},
		{"TZ wins", "/usr/share/zoneinfo/Europe/Berlin", "", str(":Asia/Tokyo"), "Asia/Tokyo"},
		{"TZ empty is UTC", "/usr/share/zoneinfo/Europe/Berlin", "", str(""), "UTC"},
		{"TZ posix rule", "/usr/share/zoneinfo/Europe/Berlin", "", str("EST5EDT,M3.2.0,M11.1.0"), ""},
		{"bad symlink, /etc/timezone", "/opt/custom/tzfile", "Pacific/Auckland\n", nil, "Pacific/Auckland"},
		{"no link, /etc/timezone", "", "Europe/Rome", nil, "Europe/Rome"},
		{"hostile /etc/timezone", "", "../../etc/shadow", nil, ""},
		{"nothing", "", "", nil, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			withTZFiles(t, c.link, c.file, c.tz)
			if got := systemTZName(); got != c.want {
				t.Errorf("systemTZName() = %q, want %q", got, c.want)
			}
		})
	}
}

func TestSystemResolversFixture(t *testing.T) {
	old := resolvConf
	t.Cleanup(func() { resolvConf = old })
	resolvConf = filepath.Join(t.TempDir(), "resolv.conf")
	if err := os.WriteFile(resolvConf, []byte(resolvConfFixture), 0o600); err != nil {
		t.Fatal(err)
	}
	got := Resolvers()
	if len(got) != 6 || got[0] != netip.MustParseAddrPort("192.168.1.1:53") || got[4] != netip.MustParseAddrPort("127.0.0.53:53") {
		t.Errorf("Resolvers() = %v", got)
	}
}
