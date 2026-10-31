//go:build darwin

package main

import (
	"context"
	"os/exec"
	"time"
)

// showMessage posts a notification. The text is passed as an argument to
// the script (never spliced into it), so it cannot inject AppleScript.
func showMessage(text string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	exec.CommandContext(ctx, "/usr/bin/osascript",
		"-e", "on run argv",
		"-e", `display notification (item 1 of argv) with title "PrivateVPN"`,
		"-e", "end run",
		"--", text).Run()
}

// trayAvailable: the macOS menu bar always exists.
func trayAvailable() bool { return true }
