//go:build !windows && !android

package firewall

// Supported reports whether this OS uses the inbound rule.
func Supported() bool { return false }

// Add is Windows-only.
func Add(exe string) error { return ErrUnsupported }

// Remove is Windows-only.
func Remove() error { return ErrUnsupported }

// Check is Windows-only.
func Check(exe string) (bool, error) { return false, ErrUnsupported }

// AddElevated is Windows-only.
func AddElevated(exe string) error { return ErrUnsupported }
