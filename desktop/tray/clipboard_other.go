//go:build !windows && !darwin && !android

package tray

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"time"
)

// ErrNoClipboard means no clipboard tool (wl-copy, xclip, xsel) was found.
var ErrNoClipboard = errors.New("no clipboard tool found (install wl-clipboard or xclip)")

// clipboardCommand picks wl-copy on Wayland, else xclip or xsel. Paths are
// resolved with exec.LookPath to absolute paths; nothing runs via a shell.
func clipboardCommand() (path string, args []string, err error) {
	type cand struct {
		name string
		args []string
		need string // environment variable that must be set
	}
	cands := []cand{
		{"wl-copy", nil, "WAYLAND_DISPLAY"},
		{"xclip", []string{"-selection", "clipboard", "-in"}, "DISPLAY"},
		{"xsel", []string{"--clipboard", "--input"}, "DISPLAY"},
	}
	for _, c := range cands {
		if os.Getenv(c.need) == "" {
			continue
		}
		if p, err := exec.LookPath(c.name); err == nil {
			return p, c.args, nil
		}
	}
	return "", nil, ErrNoClipboard
}

// CopyToClipboard puts text on the desktop clipboard.
func CopyToClipboard(text string) error {
	path, args, err := clipboardCommand()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Stdin = strings.NewReader(text)
	return cmd.Run()
}
