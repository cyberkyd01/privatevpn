//go:build !android

package main

import (
	"io"
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/cyberkyd01/private-vpn-pro/core/tunnel"
)

// capture runs f with stdout and stderr redirected.
func capture(t *testing.T, f func() int) (int, string, string) {
	t.Helper()
	oldOut, oldErr := os.Stdout, os.Stderr
	ro, wo, _ := os.Pipe()
	re, we, _ := os.Pipe()
	os.Stdout, os.Stderr = wo, we
	code := f()
	wo.Close()
	we.Close()
	os.Stdout, os.Stderr = oldOut, oldErr
	out, _ := io.ReadAll(ro)
	errOut, _ := io.ReadAll(re)
	return code, string(out), string(errOut)
}

func TestVersionAndHelp(t *testing.T) {
	old := version
	version = "v1.4.2"
	defer func() { version = old }()
	code, out, _ := capture(t, func() int { return run([]string{"version"}) })
	if code != 0 || strings.TrimSpace(out) != "v1.4.2" {
		t.Errorf("version: %d %q", code, out)
	}
	code, out, _ = capture(t, func() int { return run([]string{"--help"}) })
	if code != 0 || !strings.Contains(out, "--no-tray") || !strings.Contains(out, "firewall add|remove") || !strings.Contains(out, "private-vpn-pro unblock") {
		t.Errorf("help: %d %q", code, out)
	}
}

// The recovery commands change system state: they refuse to run without
// administrator rights and never touch anything unelevated.
func TestKillSwitchCommandsNeedElevation(t *testing.T) {
	if tunnel.IsElevated() {
		t.Skip("running elevated")
	}
	code, out, errOut := capture(t, func() int { return run([]string{"unblock"}) })
	if code != 3 || out != "" || !strings.Contains(errOut, "administrator") {
		t.Errorf("unblock unelevated: %d %q %q", code, out, errOut)
	}
	code, _, errOut = capture(t, func() int { return run([]string{"killswitch-boot"}) })
	if code != 3 || !strings.Contains(errOut, "root") {
		t.Errorf("killswitch-boot unelevated: %d %q", code, errOut)
	}
	for _, args := range [][]string{{"unblock", "extra"}, {"killswitch-boot", "--x"}} {
		if code, _, _ := capture(t, func() int { return run(args) }); code != 2 {
			t.Errorf("%v: %d", args, code)
		}
	}
}

func TestBadArgs(t *testing.T) {
	for _, args := range [][]string{{"--bogus"}, {"extra-arg"}, {"--no-tray", "x"}} {
		code, _, errOut := capture(t, func() int { return run(args) })
		if code != 2 || !strings.Contains(errOut, "Usage") {
			t.Errorf("%v: %d", args, code)
		}
	}
}

func TestPkexecOnlyAllowsHelper(t *testing.T) {
	t.Setenv("PKEXEC_UID", "1000")
	for _, args := range [][]string{nil, {"--no-tray"}, {"version"}, {"firewall", "add"}, {"--autostart"}, {"unblock"}, {"killswitch-boot"}} {
		code, out, errOut := capture(t, func() int { return run(args) })
		if code != 2 || out != "" || !strings.Contains(errOut, "pkexec") {
			t.Errorf("%v under pkexec: %d %q %q", args, code, out, errOut)
		}
	}
}

func TestFirewallSubcommand(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("would run netsh")
	}
	code, _, errOut := capture(t, func() int { return run([]string{"firewall", "add"}) })
	if code != 2 || !strings.Contains(errOut, "only needed on Windows") {
		t.Errorf("firewall on %s: %d %q", runtime.GOOS, code, errOut)
	}
}

func TestAppVersion(t *testing.T) {
	old := version
	defer func() { version = old }()
	for in, want := range map[string]string{
		"v1.2.3": "1.2.3", "1.2.3": "1.2.3", "v10.20.30-rc1": "10.20.30",
		"dev": "0.0.0", "": "0.0.0", "v1.2": "0.0.0", "abc-dirty": "0.0.0",
	} {
		version = in
		if got := appVersion(); got != want {
			t.Errorf("appVersion(%q) = %q, want %q", in, got, want)
		}
	}
}
