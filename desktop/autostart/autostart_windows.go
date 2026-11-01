//go:build windows

package autostart

import (
	"errors"
	"strings"

	"golang.org/x/sys/windows/registry"
)

const (
	runKey    = `Software\Microsoft\Windows\CurrentVersion\Run`
	valueName = "Private VPN Pro"
)

// runValue is the HKCU Run command line: "<exe>" --autostart.
func runValue(exe string) string { return `"` + exe + `" ` + Flag }

func set(exe string, on bool) error {
	k, _, err := registry.CreateKey(registry.CURRENT_USER, runKey, registry.SET_VALUE|registry.QUERY_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	if !on {
		if err := k.DeleteValue(valueName); err != nil && !errors.Is(err, registry.ErrNotExist) {
			return err
		}
		return nil
	}
	if strings.ContainsAny(exe, "\"\x00") {
		return errors.New("autostart: unusable executable path")
	}
	return k.SetStringValue(valueName, runValue(exe))
}

func enabled() (bool, error) {
	k, err := registry.OpenKey(registry.CURRENT_USER, runKey, registry.QUERY_VALUE)
	if err != nil {
		if errors.Is(err, registry.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	defer k.Close()
	_, _, err = k.GetStringValue(valueName)
	if errors.Is(err, registry.ErrNotExist) {
		return false, nil
	}
	return err == nil, err
}
