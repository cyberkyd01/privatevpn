package beacon

import (
	"net"
	"syscall"

	"golang.org/x/sys/windows"
)

// On Windows SO_REUSEADDR lets another process hijack the port, so it is not
// set; a single instance is enforced by the state lock instead.
func reuseControl(network, address string, c syscall.RawConn) error { return nil }

func enableBroadcast(conn *net.UDPConn) {
	if rc, err := conn.SyscallConn(); err == nil {
		rc.Control(func(fd uintptr) {
			windows.SetsockoptInt(windows.Handle(fd), windows.SOL_SOCKET, windows.SO_BROADCAST, 1)
		})
	}
}
