//go:build darwin

package sysinfo

import (
	"context"
	"os/exec"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const (
	osName      = "macos"
	deviceLabel = "Mac"
)

// virtualPrefixes: VM/sharing bridges, VMware/VirtualBox host-only, 6to4,
// fake ethernet, IPsec.
var virtualPrefixes = []string{"bridge", "vmenet", "vmnet", "vboxnet", "feth", "gif", "stf", "ipsec"}

// swVers is the absolute path of sw_vers (never resolved through $PATH).
const swVers = "/usr/bin/sw_vers"

// osVersion runs `/usr/bin/sw_vers -productVersion` (no shell, empty
// environment, 3 s timeout), falling back to sysctl kern.osproductversion.
// OSVersion caches the result.
func osVersion() string {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, swVers, "-productVersion")
	cmd.Env = []string{}
	if out, err := cmd.Output(); err == nil {
		if v := strings.TrimSpace(string(out)); v != "" {
			return v
		}
	}
	if v, err := unix.Sysctl("kern.osproductversion"); err == nil {
		return v
	}
	return ""
}

// uptime is the time since kern.boottime.
func uptime() time.Duration {
	tv, err := unix.SysctlTimeval("kern.boottime")
	if err != nil {
		return 0
	}
	sec, nsec := tv.Unix()
	return time.Since(time.Unix(sec, nsec))
}
