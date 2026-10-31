//go:build !android

// Package autostart registers PrivateVPN to start at login with the
// --autostart flag (ARCHITECTURE §13.6), always for the current user and
// without privileges:
//
//   - Windows: HKCU\Software\Microsoft\Windows\CurrentVersion\Run\PrivateVPN
//   - macOS:   ~/Library/LaunchAgents/app.privatevpn.plist (RunAtLoad)
//   - Linux:   $XDG_CONFIG_HOME/autostart/privatevpn.desktop
//
// Autostart restores gateway mode if it was on; it never connects a client
// tunnel (that would ask for elevation at logon) — that rule lives in the
// engine, which receives Options.Autostart.
package autostart

import (
	"encoding/xml"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// Flag is the command-line flag the registered entry passes.
const Flag = "--autostart"

// ErrNotInstalled is returned when the running binary is a temporary build
// (go run) that would vanish; registering it would leave a dead entry.
var ErrNotInstalled = errors.New("autostart: run an installed copy of PrivateVPN to enable start at login")

// executable returns the absolute path of the running binary.
func executable() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	if p, err := filepath.EvalSymlinks(exe); err == nil {
		exe = p
	}
	if strings.Contains(exe, "go-build") {
		return "", ErrNotInstalled
	}
	return exe, nil
}

// Set registers (on=true) or removes (on=false) the login item for the
// running binary.
func Set(on bool) error {
	if !on {
		return set("", false)
	}
	exe, err := executable()
	if err != nil {
		return err
	}
	return set(exe, true)
}

// Enabled reports whether a login item exists.
func Enabled() (bool, error) { return enabled() }

// launchAgentPlist is the macOS LaunchAgent for exe.
func launchAgentPlist(exe string) string {
	var esc strings.Builder
	xml.EscapeText(&esc, []byte(exe))
	return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>app.privatevpn</string>
	<key>ProgramArguments</key>
	<array>
		<string>` + esc.String() + `</string>
		<string>` + Flag + `</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>LimitLoadToSessionType</key>
	<string>Aqua</string>
	<key>ProcessType</key>
	<string>Interactive</string>
</dict>
</plist>
`
}

// desktopExecArg quotes one argument for a .desktop Exec= key: the
// argument is double-quoted, `"`, "`", "$" and "\" are backslash-escaped
// (quoting rule), and every backslash is then doubled (string escaping
// rule), so a literal backslash becomes four. "%" becomes "%%".
func desktopExecArg(s string) (string, error) {
	if s == "" || strings.ContainsAny(s, "\x00\r\n") {
		return "", errors.New("autostart: unusable executable path")
	}
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"', '`', '$':
			b.WriteString(`\\`)
			b.WriteRune(r)
		case '\\':
			b.WriteString(`\\\\`)
		case '%':
			b.WriteString("%%")
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String(), nil
}

// desktopEntry is the XDG autostart entry for exe.
func desktopEntry(exe string) (string, error) {
	arg, err := desktopExecArg(exe)
	if err != nil {
		return "", err
	}
	return "[Desktop Entry]\n" +
		"Type=Application\n" +
		"Name=PrivateVPN\n" +
		"Comment=Private VPN gateways for your own devices\n" +
		"Exec=" + arg + " " + Flag + "\n" +
		"Icon=privatevpn\n" +
		"Terminal=false\n" +
		"Categories=Network;\n" +
		"X-GNOME-Autostart-enabled=true\n", nil
}

// writeFileAtomic writes data via a temp file + rename (0644: the entry
// holds no secrets and the desktop must be able to read it).
func writeFileAtomic(path, data string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".privatevpn-*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if _, err := f.WriteString(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Chmod(0o644); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func removeIfExists(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
