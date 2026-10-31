//go:build android

package mobile

import "golang.org/x/sys/unix"

// silenceStdio points fd 1 and 2 at /dev/null. gomobile's runtime pipes the
// process's stdout/stderr into logcat (tag "GoLog"); nothing from the core
// may reach a system log (§12.1) — not a panic message, not stray output of
// a dependency. The in-memory eventlog remains the only log.
func silenceStdio() {
	fd, err := unix.Open("/dev/null", unix.O_WRONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return
	}
	_ = unix.Dup3(fd, 1, 0)
	_ = unix.Dup3(fd, 2, 0)
	_ = unix.Close(fd)
}
