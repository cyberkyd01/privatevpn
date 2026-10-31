//go:build !android

package autostart

import (
	"encoding/xml"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestLaunchAgentPlist(t *testing.T) {
	p := launchAgentPlist("/Applications/Private & <VPN>.app/Contents/MacOS/privatevpn")
	if !strings.Contains(p, "<string>/Applications/Private &amp; &lt;VPN&gt;.app/Contents/MacOS/privatevpn</string>") {
		t.Errorf("path not escaped:\n%s", p)
	}
	for _, want := range []string{"<string>app.privatevpn</string>", "<string>--autostart</string>", "<key>RunAtLoad</key>\n\t<true/>"} {
		if !strings.Contains(p, want) {
			t.Errorf("plist lacks %q", want)
		}
	}
	// Well-formed XML.
	d := xml.NewDecoder(strings.NewReader(p))
	d.Strict = true
	for {
		if _, err := d.Token(); err != nil {
			if err.Error() != "EOF" {
				t.Fatalf("plist is not well-formed: %v", err)
			}
			break
		}
	}
}

func TestDesktopEntry(t *testing.T) {
	e, err := desktopEntry("/opt/Private VPN/privatevpn")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(e, "Exec=\"/opt/Private VPN/privatevpn\" --autostart\n") {
		t.Errorf("entry:\n%s", e)
	}
	if !strings.HasPrefix(e, "[Desktop Entry]\nType=Application\n") {
		t.Error("header")
	}
	cases := map[string]string{
		`/a/b`:    `"/a/b"`,
		`/a"b`:    `"/a\\"b"`,
		"/a`b$c":  "\"/a\\\\`b\\\\$c\"",
		`/a\b`:    `"/a\\\\b"`,
		`/100%/x`: `"/100%%/x"`,
	}
	for in, want := range cases {
		got, err := desktopExecArg(in)
		if err != nil || got != want {
			t.Errorf("desktopExecArg(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "/a\nb", "/a\x00b"} {
		if _, err := desktopExecArg(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestSetAndRemoveInTempHome(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("registry; not touched by tests")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, "cfg"))
	exe := "/opt/privatevpn/privatevpn"
	if err := set(exe, true); err != nil {
		t.Fatal(err)
	}
	on, err := enabled()
	if err != nil || !on {
		t.Fatalf("enabled = %v, %v", on, err)
	}
	var path string
	if runtime.GOOS == "darwin" {
		path = filepath.Join(home, "Library", "LaunchAgents", "app.privatevpn.plist")
	} else {
		path = filepath.Join(home, "cfg", "autostart", "privatevpn.desktop")
	}
	b, err := os.ReadFile(path)
	if err != nil || !strings.Contains(string(b), exe) || !strings.Contains(string(b), Flag) {
		t.Fatalf("entry %s: %v\n%s", path, err, b)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o644 {
		t.Errorf("mode %v", fi.Mode())
	}
	if err := set("", false); err != nil {
		t.Fatal(err)
	}
	if on, _ := enabled(); on {
		t.Error("still enabled after removal")
	}
	if err := set("", false); err != nil {
		t.Errorf("removing twice: %v", err)
	}
}

func TestGoRunBinaryRefused(t *testing.T) {
	// Test binaries are built in a go-build temp dir, like `go run`.
	exe, _ := os.Executable()
	if !strings.Contains(exe, "go-build") {
		t.Skip("test binary not in a go-build dir")
	}
	if _, err := executable(); err != ErrNotInstalled {
		t.Errorf("executable() = %v, want ErrNotInstalled", err)
	}
}
