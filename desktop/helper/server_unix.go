//go:build (darwin || linux) && !android

package helper

import (
	"errors"
	"flag"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// sanitizeEnv drops the caller's environment: the helper runs as root and,
// for example, wireguard-go's darwin CreateTUN writes the file named by
// WG_TUN_NAME_FILE. Child commands get an explicit environment anyway.
func sanitizeEnv() {
	os.Clearenv()
	_ = os.Setenv("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
}

type helperOpts struct {
	socket string
	uid    int
}

func parseArgs(args []string) (helperOpts, error) {
	fs := flag.NewFlagSet("tunnel-helper", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	socket := fs.String("socket", "", "")
	uid := fs.String("uid", "", "")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		return helperOpts{}, errors.New("usage")
	}
	n, err := strconv.ParseUint(*uid, 10, 31)
	if err != nil {
		return helperOpts{}, errors.New("bad --uid")
	}
	// Under pkexec the invoking user is known: --uid must be that user, so
	// nobody can have root serve a socket for a different account.
	if p := os.Getenv("PKEXEC_UID"); p != "" && p != strconv.FormatUint(n, 10) {
		return helperOpts{}, errors.New("--uid does not match PKEXEC_UID")
	}
	o := helperOpts{socket: *socket, uid: int(n)}
	if err := validSocketPath(o.socket); err != nil {
		return helperOpts{}, err
	}
	return o, nil
}

// maxSocketPath is sun_path minus the terminating NUL (macOS 104, Linux 108).
const maxSocketPath = 103

// validSocketPath accepts only <abs clean dir>/helper-<16 hex>.sock.
func validSocketPath(p string) error {
	if !filepath.IsAbs(p) || filepath.Clean(p) != p || len(p) > maxSocketPath || strings.ContainsAny(p, "\x00\n") {
		return errors.New("bad --socket")
	}
	base := filepath.Base(p)
	if !strings.HasPrefix(base, "helper-") || !strings.HasSuffix(base, ".sock") ||
		!isHex16(strings.TrimSuffix(strings.TrimPrefix(base, "helper-"), ".sock")) {
		return errors.New("bad --socket")
	}
	return nil
}

// checkSocketDir verifies that dir is a real directory owned by uid that
// nobody else can enter: the socket we create as root is only reachable by
// the requesting user, and root never writes through a path someone else
// controls.
func checkSocketDir(dir string, uid int) error {
	fi, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || !fi.IsDir() || fi.Mode()&os.ModeSymlink != 0 || int(st.Uid) != uid || fi.Mode().Perm()&0o077 != 0 {
		return errors.New("socket directory must be a 0700 directory owned by the user")
	}
	return nil
}

// acceptOne listens on the socket (created 0600 via umask, then lchown'ed
// to uid), accepts exactly one connection, stops listening, and verifies the
// peer's uid.
func acceptOne(o helperOpts, timeout time.Duration) (net.Conn, error) {
	if err := checkSocketDir(filepath.Dir(o.socket), o.uid); err != nil {
		return nil, err
	}
	// The path must not exist yet (bind would follow a dangling symlink on
	// macOS and create the socket wherever it points), and afterwards it
	// must be the socket we created, not a symlink.
	if _, err := os.Lstat(o.socket); err == nil {
		return nil, errors.New("socket path already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	old := syscall.Umask(0o177)
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: o.socket, Net: "unix"})
	syscall.Umask(old)
	if err != nil {
		return nil, err
	}
	l.SetUnlinkOnClose(true)
	defer l.Close() // stop listening after the first connection
	if fi, err := os.Lstat(o.socket); err != nil || fi.Mode()&os.ModeType != os.ModeSocket {
		return nil, errors.New("socket path is not the socket we created")
	}
	if err := os.Lchown(o.socket, o.uid, -1); err != nil {
		return nil, err
	}
	if err := l.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}
	c, err := l.AcceptUnix()
	if err != nil {
		return nil, err
	}
	uid, err := peerUID(c)
	if err != nil || uid != o.uid {
		c.Close()
		return nil, errors.New("peer is not the requesting user")
	}
	return c, nil
}

// peerUID returns the uid of the process on the other end of c.
func peerUID(c *net.UnixConn) (int, error) {
	rc, err := c.SyscallConn()
	if err != nil {
		return -1, err
	}
	uid := -1
	var serr error
	if err := rc.Control(func(fd uintptr) { uid, serr = sockPeerUID(int(fd)) }); err != nil {
		return -1, err
	}
	return uid, serr
}
