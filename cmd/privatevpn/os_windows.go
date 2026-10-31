//go:build windows

package main

import (
	"os"

	"golang.org/x/sys/windows"
)

// runningAsRoot is a Unix notion; on Windows the app is asInvoker.
func runningAsRoot() bool { return false }

// refreshSignal: no SIGUSR1 on Windows (Enter still prints a new link).
func refreshSignal() <-chan os.Signal { return nil }

const (
	mbIconInformation = 0x00000040
	mbSetForeground   = 0x00010000
)

// showMessage shows a message box (the GUI build has no console).
func showMessage(text string) {
	t, err := windows.UTF16PtrFromString(text)
	if err != nil {
		return
	}
	c, _ := windows.UTF16PtrFromString("PrivateVPN")
	windows.MessageBox(0, t, c, windows.MB_OK|mbIconInformation|mbSetForeground)
}

// trayAvailable: Windows always has a notification area.
func trayAvailable() bool { return true }
