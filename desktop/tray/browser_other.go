//go:build !windows && !darwin && !android

package tray

import (
	"errors"
	"os/exec"
	"strings"
)

// OpenBrowser opens a local http://127.0.0.1 URL with xdg-open (resolved to
// an absolute path; no shell).
func OpenBrowser(u string) error {
	if !strings.HasPrefix(u, "http://127.0.0.1:") {
		return errors.New("refusing to open a non-local URL")
	}
	p, err := exec.LookPath("xdg-open")
	if err != nil {
		return err
	}
	cmd := exec.Command(p, u)
	if err := cmd.Start(); err != nil {
		return err
	}
	go cmd.Wait() // xdg-open may stay alive while the browser starts
	return nil
}
