//go:build !windows && !darwin && !android

package main

import (
	"context"
	"os/exec"
	"time"
)

// showMessage uses notify-send when it is installed (absolute path, no
// shell); otherwise the stderr line printed by the caller is all there is.
func showMessage(text string) {
	p, err := exec.LookPath("notify-send")
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	exec.CommandContext(ctx, p, "--app-name=Private VPN Pro", "Private VPN Pro", text).Run()
}
