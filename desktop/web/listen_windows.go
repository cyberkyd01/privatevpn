//go:build windows

package web

import (
	"context"
	"net"
	"strconv"
	"syscall"

	"golang.org/x/sys/windows"
)

// soExclusiveAddrUse is SO_EXCLUSIVEADDRUSE (= ~SO_REUSEADDR).
const soExclusiveAddrUse = ^int(windows.SO_REUSEADDR)

// listenLoopback binds 127.0.0.1:port over IPv4 only, with
// SO_EXCLUSIVEADDRUSE so no other process can bind the same address/port
// while we hold it.
func listenLoopback(port int) (net.Listener, error) {
	lc := net.ListenConfig{Control: func(network, address string, c syscall.RawConn) error {
		var serr error
		err := c.Control(func(fd uintptr) {
			serr = windows.SetsockoptInt(windows.Handle(fd), windows.SOL_SOCKET, soExclusiveAddrUse, 1)
		})
		if err != nil {
			return err
		}
		return serr
	}}
	return lc.Listen(context.Background(), "tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
}
