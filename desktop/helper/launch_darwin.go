//go:build darwin

package helper

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/cyberkyd01/private-vpn-pro/core/eventlog"
	"github.com/cyberkyd01/private-vpn-pro/core/tunnel"
)

const osascriptPath = "/usr/bin/osascript"

func newPlatform(exe, version string, log *eventlog.Log) tunnel.Tunnel {
	return newClient(version, log, func(ctx context.Context) (io.ReadWriteCloser, process, error) {
		return launchDarwin(ctx, exe)
	})
}

// limitedBuffer keeps the first max bytes written to it.
type limitedBuffer struct {
	b   bytes.Buffer
	max int
}

func (l *limitedBuffer) Write(p []byte) (int, error) {
	if room := l.max - l.b.Len(); room > 0 {
		if len(p) > room {
			l.b.Write(p[:room])
		} else {
			l.b.Write(p)
		}
	}
	return len(p), nil
}

// launchDarwin runs the helper as root through osascript's administrator
// prompt (§9.3) and connects to its socket.
func launchDarwin(ctx context.Context, exe string) (io.ReadWriteCloser, process, error) {
	if !filepath.IsAbs(exe) {
		return nil, nil, errors.New("helper: executable path must be absolute")
	}
	path, err := socketPath(uidDir(os.TempDir()), uidDir("/tmp"))
	if err != nil {
		return nil, nil, err
	}
	script, err := appleScriptHelperCommand(exe, path, os.Getuid())
	if err != nil {
		return nil, nil, err
	}
	cmd := exec.Command(osascriptPath, "-e", script)
	// The administrator shell may inherit this environment: keep loader and
	// Go runtime variables away from the root helper.
	cmd.Env = launcherEnv()
	// osascript's stderr carries "User canceled. (-128)"; it is inspected
	// for that marker only and never logged.
	stderr := &limitedBuffer{max: 4096}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = nil, nil, stderr
	p, err := startProcess(cmd)
	if err != nil {
		return nil, nil, err
	}
	conn, err := dialUnix(ctx, path, p)
	if err == nil {
		return conn, p, nil
	}
	p.Kill() // dismisses a pending prompt; a running root helper times out on its own
	select {
	case <-p.Done():
	case <-time.After(2 * time.Second):
	}
	if errors.Is(err, errLauncherExited) {
		if bytes.Contains(stderr.b.Bytes(), []byte("(-128)")) || p.exitCode() == exitNotElevated {
			return nil, nil, tunnel.ErrNotElevated
		}
		return nil, nil, errors.New("helper: the administrator prompt failed or the helper exited")
	}
	return nil, nil, err
}
