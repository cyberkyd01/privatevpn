//go:build windows

package firewall

import (
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Supported reports whether this OS uses the inbound rule.
func Supported() bool { return true }

func netsh(args ...string) ([]byte, int, error) {
	sys, err := windows.GetSystemDirectory()
	if err != nil {
		return nil, -1, err
	}
	cmd := exec.Command(filepath.Join(sys, "netsh.exe"), args...)
	cmd.Dir = sys // never the caller's cwd: netsh loads helper DLLs by name
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NO_WINDOW}
	out, err := cmd.CombinedOutput()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return out, ee.ExitCode(), nil
		}
		return out, -1, err
	}
	return out, 0, nil
}

// Check reports whether both Private VPN Pro rules exist for exe. It does not
// need elevation.
func Check(exe string) (bool, error) {
	for _, name := range ruleNames {
		out, code, err := netsh(showArgs(name)...)
		if err != nil {
			return false, err
		}
		if code != 0 || !ruleCoversProgram(out, exe) { // "No rules match the specified criteria."
			return false, nil
		}
	}
	return true, nil
}

// Add creates the rules for exe; it must run elevated ("<exe> firewall add").
// Stale rules with our names (e.g. for a moved executable) are replaced, so
// exactly one rule of each name exists afterwards.
func Add(exe string) error {
	if !validExe(exe) {
		return errors.New("firewall: invalid program path")
	}
	if ok, err := Check(exe); err == nil && ok {
		return nil
	}
	for _, name := range ruleNames {
		netsh(deleteArgs(name)...) // no rule → non-zero exit, ignored
	}
	for _, args := range addArgs(exe) {
		out, code, err := netsh(args...)
		if err != nil {
			return err
		}
		if code != 0 {
			return fmt.Errorf("firewall: netsh failed (exit %d): %s", code, trim(out))
		}
	}
	return nil
}

// Remove deletes every Private VPN Pro rule; it must run elevated.
func Remove() error {
	for _, name := range ruleNames {
		netsh(deleteArgs(name)...) // a missing rule exits non-zero; verified below
	}
	for _, name := range ruleNames {
		if _, code, err := netsh(showArgs(name)...); err == nil && code == 0 {
			return fmt.Errorf("firewall: could not delete rule %q", name)
		}
	}
	return nil
}

func trim(b []byte) string {
	if len(b) > 300 {
		b = b[:300]
	}
	return string(b)
}

var (
	shell32              = windows.NewLazySystemDLL("shell32.dll")
	procShellExecuteExW  = shell32.NewProc("ShellExecuteExW")
	errElevationNoHandle = errors.New("firewall: the elevated process could not be tracked")
)

// shellExecuteInfo is SHELLEXECUTEINFOW (natural alignment matches C on
// amd64, arm64 and 386).
type shellExecuteInfo struct {
	cbSize       uint32
	fMask        uint32
	hwnd         uintptr
	lpVerb       *uint16
	lpFile       *uint16
	lpParameters *uint16
	lpDirectory  *uint16
	nShow        int32
	hInstApp     uintptr
	lpIDList     uintptr
	lpClass      *uint16
	hkeyClass    uintptr
	dwHotKey     uint32
	hIcon        uintptr
	hProcess     windows.Handle
}

const (
	seeMaskNoCloseProcess = 0x00000040
	seeMaskNoAsync        = 0x00000100
)

// AddElevated runs "<exe> firewall add" with ShellExecute "runas" (the UAC
// prompt) and waits for it. ErrCancelled if the user declines.
func AddElevated(exe string) error {
	if !validExe(exe) {
		return errors.New("firewall: invalid program path")
	}
	verb, _ := windows.UTF16PtrFromString("runas")
	file, err := windows.UTF16PtrFromString(exe)
	if err != nil {
		return err
	}
	params, _ := windows.UTF16PtrFromString("firewall add")
	// Start the elevated process in System32, not in this process's cwd.
	var dir *uint16
	if sys, err := windows.GetSystemDirectory(); err == nil {
		dir, _ = windows.UTF16PtrFromString(sys)
	}
	info := shellExecuteInfo{
		fMask:        seeMaskNoCloseProcess | seeMaskNoAsync,
		lpVerb:       verb,
		lpFile:       file,
		lpParameters: params,
		lpDirectory:  dir,
		nShow:        windows.SW_HIDE,
	}
	info.cbSize = uint32(unsafe.Sizeof(info))
	r, _, callErr := procShellExecuteExW.Call(uintptr(unsafe.Pointer(&info)))
	runtime.KeepAlive(verb)
	runtime.KeepAlive(file)
	runtime.KeepAlive(params)
	runtime.KeepAlive(dir)
	if r == 0 {
		if errors.Is(callErr, windows.ERROR_CANCELLED) {
			return ErrCancelled
		}
		return fmt.Errorf("firewall: elevation failed: %w", callErr)
	}
	if info.hProcess == 0 {
		return errElevationNoHandle
	}
	defer windows.CloseHandle(info.hProcess)
	ev, err := windows.WaitForSingleObject(info.hProcess, 2*60*1000)
	if err != nil {
		return err
	}
	if ev != windows.WAIT_OBJECT_0 {
		return errors.New("firewall: timed out waiting for the elevated process")
	}
	var code uint32
	if err := windows.GetExitCodeProcess(info.hProcess, &code); err != nil {
		return err
	}
	if code != 0 {
		return fmt.Errorf("firewall: adding the rule failed (exit %d)", code)
	}
	return nil
}
