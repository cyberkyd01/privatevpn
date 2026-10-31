//go:build darwin

package tray

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"time"
)

// CopyToClipboard puts text on the macOS pasteboard via /usr/bin/pbcopy
// (absolute path, no shell).
func CopyToClipboard(text string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/bin/pbcopy")
	cmd.Stdin = strings.NewReader(text)
	cmd.Env = append(os.Environ(), "LANG=en_US.UTF-8") // pbcopy decodes stdin per locale
	return cmd.Run()
}
