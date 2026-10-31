//go:build darwin

package helper

import "golang.org/x/sys/unix"

// sockPeerUID reads LOCAL_PEERCRED (what getpeereid(3) uses): the peer's
// effective uid.
func sockPeerUID(fd int) (int, error) {
	cred, err := unix.GetsockoptXucred(fd, unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	if err != nil {
		return -1, err
	}
	return int(cred.Uid), nil
}
