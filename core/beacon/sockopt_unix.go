//go:build !windows

package beacon

import (
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

func reuseControl(network, address string, c syscall.RawConn) error {
	return c.Control(func(fd uintptr) {
		unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
		unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
	})
}

func enableBroadcast(conn *net.UDPConn) {
	if rc, err := conn.SyscallConn(); err == nil {
		rc.Control(func(fd uintptr) {
			unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_BROADCAST, 1)
		})
	}
}
