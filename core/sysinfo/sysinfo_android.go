//go:build android

package sysinfo

const (
	osName      = "android"
	deviceLabel = "Phone"
)

// osVersion is the fallback when the app has not called SetMobileInfo: the
// kernel release (Go cannot read Build.VERSION.RELEASE).
func osVersion() string { return unameRelease() }
