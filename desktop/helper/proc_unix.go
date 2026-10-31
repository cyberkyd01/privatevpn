//go:build (darwin || linux) && !android

package helper

import (
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// execProcess is a started launcher (osascript / pkexec) we wait for.
type execProcess struct {
	cmd  *exec.Cmd
	done chan struct{}
	once sync.Once
	err  error // valid after done
}

func startProcess(cmd *exec.Cmd) (*execProcess, error) {
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	p := &execProcess{cmd: cmd, done: make(chan struct{})}
	go func() {
		p.err = cmd.Wait()
		close(p.done)
	}()
	return p, nil
}

func (p *execProcess) Done() <-chan struct{} { return p.done }

func (p *execProcess) Kill() {
	select {
	case <-p.done:
	default:
		_ = p.cmd.Process.Kill()
	}
}

// exitCode is the exit status once done, or -1.
func (p *execProcess) exitCode() int {
	var ee *exec.ExitError
	if errors.As(p.err, &ee) {
		return ee.ExitCode()
	}
	if p.err == nil {
		return 0
	}
	return -1
}

// launcherEnvDrop lists environment prefixes that must not reach the
// launcher (osascript, pkexec) and through it the root helper: dynamic
// loader injection (DYLD_*, LD_*), Go runtime knobs that the helper cannot
// undo after start-up (GOTRACEBACK=crash would core-dump the session key,
// GODEBUG), wireguard-go steering (WG_*) and cgo. pkexec scrubs its
// environment itself; osascript's administrator shell may not.
var launcherEnvDrop = []string{"DYLD_", "LD_", "GO", "WG_", "CGO_", "PKEXEC_"}

// launcherEnv returns the current environment minus launcherEnvDrop.
func launcherEnv() []string {
	return filterEnv(os.Environ(), launcherEnvDrop)
}

func filterEnv(env, dropPrefixes []string) []string {
	out := make([]string, 0, len(env))
next:
	for _, kv := range env {
		key, _, _ := strings.Cut(kv, "=")
		for _, p := range dropPrefixes {
			if strings.HasPrefix(key, p) {
				continue next
			}
		}
		out = append(out, kv)
	}
	return out
}

// ensureSocketDir creates dir 0700 and verifies it is a real directory owned
// by us that nobody else can enter (relevant under /tmp).
func ensureSocketDir(dir string) error {
	if err := os.Mkdir(dir, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	return checkSocketDir(dir, os.Getuid())
}

// socketPath picks <dir>/helper-<16 hex>.sock in the first usable directory.
func socketPath(dirs ...string) (string, error) {
	name, err := randomHex()
	if err != nil {
		return "", err
	}
	for _, d := range dirs {
		if d == "" || !filepath.IsAbs(d) {
			continue
		}
		p := filepath.Join(d, "helper-"+name+".sock")
		if validSocketPath(p) != nil {
			continue
		}
		if ensureSocketDir(d) == nil {
			return p, nil
		}
	}
	return "", errors.New("helper: no usable directory for the helper socket")
}

func uidDir(base string) string {
	return filepath.Join(base, "privatevpn-"+strconv.Itoa(os.Getuid()))
}

// dialUnix connects to path once the helper listens, until connectTimeout,
// ctx cancellation, or the launcher exiting. It verifies the server is root.
func dialUnix(ctx context.Context, path string, p *execProcess) (net.Conn, error) {
	deadline := time.NewTimer(connectTimeout)
	defer deadline.Stop()
	tick := time.NewTicker(150 * time.Millisecond)
	defer tick.Stop()
	for {
		if c, err := net.DialTimeout("unix", path, time.Second); err == nil {
			uc := c.(*net.UnixConn)
			if uid, err := peerUID(uc); err != nil || uid != 0 {
				c.Close()
				return nil, errors.New("helper: socket is not served by root")
			}
			return c, nil
		} else if !errors.Is(err, syscall.ENOENT) && !errors.Is(err, syscall.ECONNREFUSED) {
			return nil, err
		}
		select {
		case <-ctx.Done():
			return nil, errClientClosed
		case <-p.Done():
			return nil, errLauncherExited
		case <-deadline.C:
			return nil, errors.New("helper: timed out waiting for the privileged helper")
		case <-tick.C:
		}
	}
}

var errLauncherExited = errors.New("helper: exited before connecting")
