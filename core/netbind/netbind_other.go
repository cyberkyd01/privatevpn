//go:build android || !(linux || windows || darwin)

package netbind

import "syscall"

// control is a no-op: on Android the app is excluded from its own VpnService
// (§7.4), so every socket already bypasses the tunnel.
func control(string, string, syscall.RawConn) error { return nil }

func defaultInterfaces(string) (uint32, uint32, error) { return 0, 0, nil }
