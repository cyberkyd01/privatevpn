//go:build !windows

package state

import (
	"errors"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// ErrAlreadyRunning means another instance holds the lock.
var ErrAlreadyRunning = errors.New("Private VPN Pro is already running")

// Lock is a held single-instance lock.
type Lock struct{ f *os.File }

// AcquireLock takes an exclusive, non-blocking lock on <dir>/.lock.
func AcquireLock(dir string) (*Lock, error) {
	if err := ensureDir(dir); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(dir, ".lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, ErrAlreadyRunning
		}
		return nil, err
	}
	return &Lock{f: f}, nil
}

// Release drops the lock.
func (l *Lock) Release() {
	if l != nil && l.f != nil {
		unix.Flock(int(l.f.Fd()), unix.LOCK_UN)
		l.f.Close()
	}
}
