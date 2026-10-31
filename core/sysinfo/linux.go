//go:build linux

package sysinfo

import (
	"time"

	"golang.org/x/sys/unix"
)

// Shared by Linux and Android (GOOS=android implies the linux tag).

// virtualPrefixes: containers, bridges, VM host-only, other VPNs/overlays.
var virtualPrefixes = []string{
	"docker", "veth", "br-", "virbr", "vmnet", "vboxnet", "lxc", "lxd", "cni",
	"flannel", "cali", "podman", "kube", "tun", "tap", "wg", "tailscale", "zt",
	"dummy", "ip6tnl", "sit", "gre",
}

// uptime uses sysinfo(2).
func uptime() time.Duration {
	var si unix.Sysinfo_t
	if err := unix.Sysinfo(&si); err != nil {
		return 0
	}
	return time.Duration(int64(si.Uptime)) * time.Second
}

// unameRelease returns the kernel release (uname -r).
func unameRelease() string {
	var u unix.Utsname
	if err := unix.Uname(&u); err != nil {
		return ""
	}
	return unix.ByteSliceToString(u.Release[:])
}
