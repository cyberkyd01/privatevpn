//go:build windows

package tray

import (
	"errors"
	"runtime"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	user32                      = windows.NewLazySystemDLL("user32.dll")
	kernel32                    = windows.NewLazySystemDLL("kernel32.dll")
	procOpenClipboard           = user32.NewProc("OpenClipboard")
	procCloseClipboard          = user32.NewProc("CloseClipboard")
	procEmptyClipboard          = user32.NewProc("EmptyClipboard")
	procSetClipboardData        = user32.NewProc("SetClipboardData")
	procRegisterClipboardFormat = user32.NewProc("RegisterClipboardFormatW")
	procGlobalAlloc             = kernel32.NewProc("GlobalAlloc")
	procGlobalLock              = kernel32.NewProc("GlobalLock")
	procGlobalUnlock            = kernel32.NewProc("GlobalUnlock")
	procGlobalFree              = kernel32.NewProc("GlobalFree")
	procRtlMoveMemory           = kernel32.NewProc("RtlMoveMemory")
)

const (
	cfUnicodeText = 13
	gmemMoveable  = 0x0002
)

// CopyToClipboard puts text on the Windows clipboard (CF_UNICODETEXT) and
// marks it so that Windows keeps it out of clipboard history and cloud
// clipboard sync (it is a network key).
func CopyToClipboard(text string) error {
	u16, err := windows.UTF16FromString(text)
	if err != nil {
		return err
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	opened := false
	for i := 0; i < 10; i++ {
		if r, _, _ := procOpenClipboard.Call(0); r != 0 {
			opened = true
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if !opened {
		return errors.New("clipboard is busy")
	}
	defer procCloseClipboard.Call()
	if r, _, e := procEmptyClipboard.Call(); r == 0 {
		return e
	}
	if err := setClipboard(cfUnicodeText, unsafe.Pointer(&u16[0]), uintptr(len(u16)*2)); err != nil {
		return err
	}
	zero := uint32(0)
	for _, f := range []string{"ExcludeClipboardContentFromMonitorProcessing", "CanIncludeInClipboardHistory", "CanUploadToCloudClipboard"} {
		name, _ := windows.UTF16PtrFromString(f)
		format, _, _ := procRegisterClipboardFormat.Call(uintptr(unsafe.Pointer(name)))
		if format != 0 {
			setClipboard(format, unsafe.Pointer(&zero), 4) // best effort
		}
	}
	return nil
}

// setClipboard copies n bytes at src into a movable global block and hands
// it to the clipboard (which then owns it).
func setClipboard(format uintptr, src unsafe.Pointer, n uintptr) error {
	h, _, e := procGlobalAlloc.Call(gmemMoveable, n)
	if h == 0 {
		return e
	}
	p, _, e := procGlobalLock.Call(h)
	if p == 0 {
		procGlobalFree.Call(h)
		return e
	}
	procRtlMoveMemory.Call(p, uintptr(src), n)
	runtime.KeepAlive(src)
	procGlobalUnlock.Call(h)
	if r, _, e := procSetClipboardData.Call(format, h); r == 0 {
		procGlobalFree.Call(h)
		return e
	}
	return nil
}
