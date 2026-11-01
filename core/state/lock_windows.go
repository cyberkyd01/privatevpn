package state

import (
	"errors"
	"path/filepath"

	"golang.org/x/sys/windows"
)

// ErrAlreadyRunning means another instance holds the lock.
var ErrAlreadyRunning = errors.New("Private VPN Pro is already running")

// Lock is a held single-instance lock.
type Lock struct{ h windows.Handle }

// AcquireLock opens <dir>\.lock with no sharing; a second open fails.
func AcquireLock(dir string) (*Lock, error) {
	if err := ensureDir(dir); err != nil {
		return nil, err
	}
	p, err := windows.UTF16PtrFromString(filepath.Join(dir, ".lock"))
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateFile(p, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil,
		windows.OPEN_ALWAYS, windows.FILE_ATTRIBUTE_HIDDEN|windows.FILE_FLAG_DELETE_ON_CLOSE, 0)
	if err != nil {
		if errors.Is(err, windows.ERROR_SHARING_VIOLATION) {
			return nil, ErrAlreadyRunning
		}
		return nil, err
	}
	return &Lock{h: h}, nil
}

// Release drops the lock.
func (l *Lock) Release() {
	if l != nil && l.h != 0 {
		windows.CloseHandle(l.h)
		l.h = 0
	}
}
