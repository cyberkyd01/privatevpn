//go:build !windows && !darwin && !android

package autostart

import (
	"os"
	"path/filepath"
)

func desktopPath() (string, error) {
	if d := os.Getenv("XDG_CONFIG_HOME"); filepath.IsAbs(d) {
		return filepath.Join(d, "autostart", "private-vpn-pro.desktop"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "autostart", "private-vpn-pro.desktop"), nil
}

func set(exe string, on bool) error {
	p, err := desktopPath()
	if err != nil {
		return err
	}
	if !on {
		return removeIfExists(p)
	}
	entry, err := desktopEntry(exe)
	if err != nil {
		return err
	}
	return writeFileAtomic(p, entry)
}

func enabled() (bool, error) {
	p, err := desktopPath()
	if err != nil {
		return false, err
	}
	_, err = os.Stat(p)
	if os.IsNotExist(err) {
		return false, nil
	}
	return err == nil, err
}
