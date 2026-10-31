//go:build darwin

package autostart

import (
	"os"
	"path/filepath"
)

func plistPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, "Library", "LaunchAgents", "app.privatevpn.plist"), nil
}

func set(exe string, on bool) error {
	p, err := plistPath()
	if err != nil {
		return err
	}
	if !on {
		return removeIfExists(p)
	}
	// launchd picks the agent up at the next login; nothing is loaded now
	// (the app is already running).
	return writeFileAtomic(p, launchAgentPlist(exe))
}

func enabled() (bool, error) {
	p, err := plistPath()
	if err != nil {
		return false, err
	}
	_, err = os.Stat(p)
	if os.IsNotExist(err) {
		return false, nil
	}
	return err == nil, err
}
