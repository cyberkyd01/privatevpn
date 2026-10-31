//go:build windows

package helper

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"

	"github.com/cyberkyd01/privatevpn/core/eventlog"
	"github.com/cyberkyd01/privatevpn/core/tunnel"
)

func newPlatform(exe, version string, log *eventlog.Log) tunnel.Tunnel {
	return newClient(version, log, func(ctx context.Context) (io.ReadWriteCloser, process, error) {
		return launchWindows(ctx, exe)
	})
}

// ShellExecuteExW is not in x/sys/windows. Unlike ShellExecute it returns
// the process handle, which lets us verify that the pipe server is the
// process we launched and notice when it exits.
var (
	modshell32          = windows.NewLazySystemDLL("shell32.dll")
	procShellExecuteExW = modshell32.NewProc("ShellExecuteExW")
)

// SHELLEXECUTEINFOW (shellapi.h).
type shellExecuteInfo struct {
	cbSize         uint32
	fMask          uint32
	hwnd           windows.Handle
	lpVerb         *uint16
	lpFile         *uint16
	lpParameters   *uint16
	lpDirectory    *uint16
	nShow          int32
	hInstApp       windows.Handle
	lpIDList       uintptr
	lpClass        *uint16
	hkeyClass      windows.Handle
	dwHotKey       uint32
	hIconOrMonitor windows.Handle
	hProcess       windows.Handle
}

const (
	seeMaskNoCloseProcess = 0x00000040
	seeMaskNoAsync        = 0x00000100
)

// Compile-time size check: 112 bytes on 64-bit, 60 on 32-bit.
var _ = [1]struct{}{}[unsafe.Sizeof(shellExecuteInfo{})-(60+52*(unsafe.Sizeof(uintptr(0))/8))]

// shellExecuteRunas starts exe elevated (UAC prompt) and returns its
// process handle. A cancelled prompt maps to tunnel.ErrNotElevated.
func shellExecuteRunas(exe, params string) (windows.Handle, error) {
	verb, err := windows.UTF16PtrFromString("runas")
	if err != nil {
		return 0, err
	}
	file, err := windows.UTF16PtrFromString(exe)
	if err != nil {
		return 0, err
	}
	args, err := windows.UTF16PtrFromString(params)
	if err != nil {
		return 0, err
	}
	// The helper starts in System32 rather than in this process's cwd
	// (wintun.dll is loaded from the application directory only).
	var dir *uint16
	if sys, err := windows.GetSystemDirectory(); err == nil {
		dir, _ = windows.UTF16PtrFromString(sys)
	}
	info := shellExecuteInfo{
		fMask:        seeMaskNoCloseProcess | seeMaskNoAsync,
		lpVerb:       verb,
		lpFile:       file,
		lpParameters: args,
		lpDirectory:  dir,
		nShow:        windows.SW_HIDE,
	}
	info.cbSize = uint32(unsafe.Sizeof(info))
	if err := procShellExecuteExW.Find(); err != nil {
		return 0, err
	}
	r1, _, e1 := syscall.SyscallN(procShellExecuteExW.Addr(), uintptr(unsafe.Pointer(&info)))
	runtime.KeepAlive(&info)
	if r1 == 0 {
		if errors.Is(e1, windows.ERROR_CANCELLED) {
			return 0, tunnel.ErrNotElevated
		}
		return 0, fmt.Errorf("helper: elevation failed: %w", e1)
	}
	if info.hProcess == 0 {
		return 0, errors.New("helper: elevation returned no process")
	}
	return info.hProcess, nil
}

type winProcess struct {
	mu     sync.Mutex
	h      windows.Handle
	done   chan struct{}
	code   uint32
	closed bool
}

func newWinProcess(h windows.Handle) *winProcess {
	p := &winProcess{h: h, done: make(chan struct{})}
	go func() {
		_, _ = windows.WaitForSingleObject(h, windows.INFINITE)
		p.mu.Lock()
		_ = windows.GetExitCodeProcess(h, &p.code)
		windows.CloseHandle(h)
		p.closed = true
		p.mu.Unlock()
		close(p.done)
	}()
	return p
}

func (p *winProcess) Done() <-chan struct{} { return p.done }

// Kill is best effort: a handle to an elevated process may lack
// PROCESS_TERMINATE; the helper then exits on its own accept timeout.
func (p *winProcess) Kill() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.closed {
		_ = windows.TerminateProcess(p.h, 1)
	}
}

func currentUserSID() (string, error) {
	tu, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return "", err
	}
	return tu.User.Sid.String(), nil
}

func launchWindows(ctx context.Context, exe string) (io.ReadWriteCloser, process, error) {
	if !filepath.IsAbs(exe) {
		return nil, nil, errors.New("helper: executable path must be absolute")
	}
	hexName, err := randomHex()
	if err != nil {
		return nil, nil, err
	}
	name := "privatevpn-helper-" + hexName
	sid, err := currentUserSID()
	if err != nil || !validSID(sid) {
		return nil, nil, errors.New("helper: cannot determine the user SID")
	}
	h, err := shellExecuteRunas(exe, "tunnel-helper --pipe "+name+" --sid "+sid)
	if err != nil {
		return nil, nil, err
	}
	pid, err := windows.GetProcessId(h)
	if err != nil {
		windows.CloseHandle(h)
		return nil, nil, fmt.Errorf("helper: process id: %w", err)
	}
	p := newWinProcess(h)
	conn, err := dialPipe(ctx, pipePrefix+name, p)
	if err != nil {
		p.Kill()
		if errors.Is(err, errLauncherExited) {
			p.mu.Lock()
			code := p.code
			p.mu.Unlock()
			if code == exitNotElevated {
				return nil, nil, tunnel.ErrNotElevated
			}
			return nil, nil, fmt.Errorf("helper: exited before connecting (code %d)", code)
		}
		return nil, nil, err
	}
	// Defeat pipe squatting: the server must be the process we started.
	if err := checkPipeServer(conn, pid); err != nil {
		conn.Close()
		p.Kill()
		return nil, nil, err
	}
	return conn, p, nil
}

var errLauncherExited = errors.New("helper: exited before connecting")

func dialPipe(ctx context.Context, path string, p *winProcess) (net.Conn, error) {
	deadline := time.NewTimer(connectTimeout)
	defer deadline.Stop()
	tick := time.NewTicker(150 * time.Millisecond)
	defer tick.Stop()
	for {
		d := 500 * time.Millisecond
		c, err := winio.DialPipe(path, &d)
		if err == nil {
			return c, nil
		}
		if !errors.Is(err, windows.ERROR_FILE_NOT_FOUND) && !errors.Is(err, winio.ErrTimeout) {
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

func checkPipeServer(c net.Conn, pid uint32) error {
	f, ok := c.(interface{ Fd() uintptr })
	if !ok {
		return errors.New("helper: cannot verify the pipe server")
	}
	var server uint32
	if err := windows.GetNamedPipeServerProcessId(windows.Handle(f.Fd()), &server); err != nil {
		return fmt.Errorf("helper: cannot verify the pipe server: %w", err)
	}
	if server != pid {
		return errors.New("helper: the pipe is served by another process")
	}
	return nil
}
