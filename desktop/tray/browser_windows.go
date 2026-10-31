//go:build windows

package tray

import (
	"errors"
	"strings"

	"golang.org/x/sys/windows"
)

// OpenBrowser opens a local http://127.0.0.1 URL with ShellExecute "open"
// from this unprivileged process, so the browser runs unprivileged too.
func OpenBrowser(u string) error {
	if !strings.HasPrefix(u, "http://127.0.0.1:") {
		return errors.New("refusing to open a non-local URL")
	}
	verb, err := windows.UTF16PtrFromString("open")
	if err != nil {
		return err
	}
	file, err := windows.UTF16PtrFromString(u)
	if err != nil {
		return err
	}
	return windows.ShellExecute(0, verb, file, nil, nil, windows.SW_SHOWNORMAL)
}
