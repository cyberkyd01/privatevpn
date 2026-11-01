package state

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
)

// DefaultDir returns the per-OS data directory (ARCHITECTURE §12.2).
// Android passes its own directory instead.
func DefaultDir() (string, error) {
	switch runtime.GOOS {
	case "windows":
		if d := os.Getenv("LOCALAPPDATA"); d != "" {
			return filepath.Join(d, "Private VPN Pro"), nil
		}
		return "", errors.New("state: LOCALAPPDATA not set")
	case "darwin":
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		return filepath.Join(home, "Library", "Application Support", "Private VPN Pro"), nil
	default:
		if d := os.Getenv("XDG_CONFIG_HOME"); filepath.IsAbs(d) {
			return filepath.Join(d, "private-vpn-pro"), nil
		}
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		return filepath.Join(home, ".config", "private-vpn-pro"), nil
	}
}

// ensureDir creates dir with 0700 and tightens it if it already exists.
func ensureDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if runtime.GOOS != "windows" {
		return os.Chmod(dir, 0o700)
	}
	return nil
}

// writeAtomic writes data to path via a temp file, fsync and rename, 0600.
func writeAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".state-*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp) // no-op after a successful rename
	if runtime.GOOS != "windows" {
		if err := f.Chmod(0o600); err != nil {
			f.Close()
			return err
		}
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	if d, err := os.Open(dir); err == nil {
		d.Sync() // best effort: persist the rename
		d.Close()
	}
	return nil
}
