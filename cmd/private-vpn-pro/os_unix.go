//go:build !windows && !android

package main

import (
	"os"
	"os/signal"
	"syscall"
)

// runningAsRoot: the tray, web UI and engine must run as the user (D4).
func runningAsRoot() bool { return os.Geteuid() == 0 }

// refreshSignal delivers SIGUSR1 ("print a new sign-in link", --no-tray).
func refreshSignal() <-chan os.Signal {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGUSR1)
	return ch
}
