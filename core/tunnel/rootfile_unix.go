//go:build darwin || (linux && !android)

package tunnel

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

// Root-owned state files (macOS DNS backup, kill-switch boot record, the
// executable copy the boot daemon runs). The helper runs as root and must
// never write through a path someone else controls: directories are created
// 0700 and verified to be real root-owned directories, files are written
// O_EXCL|O_NOFOLLOW to a temporary name and renamed into place.

// checkRootDir creates dir (0700) and verifies it is a root-owned real
// directory that nobody else can write.
func checkRootDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !fi.IsDir() || fi.Mode()&os.ModeSymlink != 0 || !ok || st.Uid != 0 || fi.Mode().Perm()&0o022 != 0 {
		return errors.New("tunnel: state directory is not a root-owned directory")
	}
	return nil
}

// writeRootFile atomically writes dir/name (never through a symlink).
func writeRootFile(dir, name string, data []byte, perm os.FileMode) error {
	if err := checkRootDir(dir); err != nil {
		return err
	}
	path := filepath.Join(dir, name)
	tmp := path + ".tmp"
	_ = os.Remove(tmp)
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW, perm)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp, path)
	}
	if err != nil {
		_ = os.Remove(tmp)
	}
	return err
}

func readRootFile(dir, name string) ([]byte, error) {
	if _, err := os.Lstat(dir); err != nil {
		return nil, err
	}
	if err := checkRootDir(dir); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(dir, name), os.O_RDONLY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, 64<<10+1))
}

// copyRootExe copies this executable into dir/name (root-owned, 0700 dir)
// unless an identical copy is already there, and returns the copy's path.
// The boot daemon/unit runs this copy, never the user's — possibly
// user-writable — installation.
func copyRootExe(dir, name string) (string, error) {
	src, err := os.Executable()
	if err != nil {
		return "", err
	}
	if err := checkRootDir(dir); err != nil {
		return "", err
	}
	dst := filepath.Join(dir, name)
	if err := copyFile(src, dst, 0o755); err != nil {
		return "", err
	}
	return dst, nil
}
