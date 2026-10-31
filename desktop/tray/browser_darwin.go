//go:build darwin

package tray

import (
	"errors"
	"os/exec"
	"strings"
)

// OpenBrowser opens a local http://127.0.0.1 URL with /usr/bin/open.
func OpenBrowser(u string) error {
	if !strings.HasPrefix(u, "http://127.0.0.1:") {
		return errors.New("refusing to open a non-local URL")
	}
	return exec.Command("/usr/bin/open", u).Run()
}
