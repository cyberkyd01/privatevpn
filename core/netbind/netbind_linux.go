//go:build linux && !android

package netbind

import (
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

var (
	canMarkOnce sync.Once
	canMarkOK   bool
)

// canMark probes SO_MARK on a throwaway socket once; capabilities are fixed
// for the life of the process.
func canMark() bool {
	canMarkOnce.Do(func() {
		fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			return
		}
		defer unix.Close(fd)
		canMarkOK = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_MARK, FwMark) == nil
	})
	return canMarkOK
}

// control marks every socket; the main routing table then decides, so no
// destination classification is needed. Setting SO_MARK needs CAP_NET_ADMIN;
// without it the socket fails rather than silently using the tunnel.
func control(_, _ string, c syscall.RawConn) error {
	var opErr error
	err := c.Control(func(fd uintptr) {
		opErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, FwMark)
	})
	if err != nil {
		return err
	}
	return opErr
}

// defaultInterfaces is not needed on Linux (marks, not interface binding).
func defaultInterfaces(string) (uint32, uint32, error) { return 0, 0, nil }
