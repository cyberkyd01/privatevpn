//go:build !windows && !darwin && !linux

package main

// trayAvailable: assume a tray on other Unix desktops.
func trayAvailable() bool { return true }
