//go:build linux && !android

package helper

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"

	"github.com/cyberkyd01/privatevpn/core/eventlog"
	"github.com/cyberkyd01/privatevpn/core/tunnel"
)

const pkexecPath = "/usr/bin/pkexec"

// newPlatform runs the tunnel in-process when we already hold CAP_NET_ADMIN
// (root, or `setcap cap_net_admin+ep`), else through a pkexec'd helper.
func newPlatform(exe, version string, log *eventlog.Log) tunnel.Tunnel {
	if tunnel.IsElevated() {
		if t, err := tunnel.NewNative(log); err == nil {
			if log != nil {
				log.Printf("helper", "CAP_NET_ADMIN present: client tunnel runs in-process")
			}
			return t
		}
	}
	return newClient(version, log, func(ctx context.Context) (io.ReadWriteCloser, process, error) {
		return launchLinux(ctx, exe)
	})
}

func launchLinux(ctx context.Context, exe string) (io.ReadWriteCloser, process, error) {
	if !filepath.IsAbs(exe) {
		return nil, nil, errors.New("helper: executable path must be absolute")
	}
	if _, err := os.Stat(pkexecPath); err != nil {
		return nil, nil, fmt.Errorf("helper: pkexec not found; install polkit, or grant the capability once with `sudo setcap cap_net_admin+ep %s` and restart PrivateVPN", exe)
	}
	var dirs []string
	if x := os.Getenv("XDG_RUNTIME_DIR"); filepath.IsAbs(x) {
		dirs = append(dirs, filepath.Join(x, "privatevpn"))
	}
	dirs = append(dirs, uidDir(os.TempDir()))
	path, err := socketPath(dirs...)
	if err != nil {
		return nil, nil, err
	}
	cmd := exec.Command(pkexecPath, exe, "tunnel-helper", "--socket", path, "--uid", strconv.Itoa(os.Getuid()))
	cmd.Env = launcherEnv() // pkexec scrubs too; belt and braces
	cmd.Stdin, cmd.Stdout, cmd.Stderr = nil, nil, nil
	p, err := startProcess(cmd)
	if err != nil {
		return nil, nil, err
	}
	conn, err := dialUnix(ctx, path, p)
	if err == nil {
		return conn, p, nil
	}
	p.Kill()
	select {
	case <-p.Done():
	case <-time.After(2 * time.Second):
	}
	if errors.Is(err, errLauncherExited) {
		switch code := p.exitCode(); code {
		case 126, 127, exitNotElevated: // dismissed, not authorised / no agent, helper not root
			return nil, nil, tunnel.ErrNotElevated
		default:
			return nil, nil, fmt.Errorf("helper: exited before connecting (code %d)", code)
		}
	}
	return nil, nil, err
}
