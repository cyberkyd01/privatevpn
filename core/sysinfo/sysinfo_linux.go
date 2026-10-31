//go:build linux && !android

package sysinfo

import "os"

const (
	osName      = "linux"
	deviceLabel = "Linux"
)

var osReleasePaths = []string{"/etc/os-release", "/usr/lib/os-release"}

// osVersion returns os-release VERSION_ID, else the kernel release.
func osVersion() string {
	for _, p := range osReleasePaths {
		f, err := os.Open(p)
		if err != nil {
			continue
		}
		v := parseOSRelease(f)
		f.Close()
		if v != "" {
			return v
		}
	}
	return unameRelease()
}
