//go:build linux && !android

package main

import "github.com/godbus/dbus/v5"

// trayAvailable reports whether a StatusNotifierItem host (the tray
// fyne.io/systray talks to) is on the session bus (§13.7). Without one the
// icon would never appear.
func trayAvailable() bool {
	conn, err := dbus.ConnectSessionBus()
	if err != nil {
		return false
	}
	defer conn.Close()
	var has bool
	err = conn.BusObject().Call("org.freedesktop.DBus.NameHasOwner", 0, "org.kde.StatusNotifierWatcher").Store(&has)
	return err == nil && has
}
