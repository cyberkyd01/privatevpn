//go:build linux && !android

package helper

import "golang.org/x/sys/unix"

// sockPeerUID reads SO_PEERCRED: the peer's uid as of connect/listen.
func sockPeerUID(fd int) (int, error) {
	cred, err := unix.GetsockoptUcred(fd, unix.SOL_SOCKET, unix.SO_PEERCRED)
	if err != nil {
		return -1, err
	}
	return int(cred.Uid), nil
}
