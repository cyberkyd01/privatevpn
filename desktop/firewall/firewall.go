//go:build !android

// Package firewall manages the Windows Defender Firewall inbound rule that
// lets gateway mode receive UDP (ARCHITECTURE §13.6):
//
//	netsh advfirewall firewall add rule name="Private VPN Pro" dir=in action=allow
//	      program="<exe path>" protocol=UDP profile=private,domain enable=yes
//	netsh advfirewall firewall add rule name="Private VPN Pro (public, local subnet)"
//	      … profile=public remoteip=localsubnet …
//
// Both rules are program-scoped and UDP only. Windows classifies most home
// Wi-Fi networks as Public, so the second rule admits LAN peers on Public
// networks; from beyond the local subnet a Public network stays closed.
// Adding it needs administrator rights: the unprivileged app calls
// AddElevated, which runs "<exe> firewall add" through ShellExecute "runas";
// that elevated process calls Add. netsh is always executed by absolute path
// with an argument slice, never through a shell. Other OSes need no rule
// (every function returns ErrUnsupported there).
package firewall

import (
	"errors"
	"strings"
)

// Rule display names.
const (
	RuleName       = "Private VPN Pro"
	RuleNamePublic = "Private VPN Pro (public, local subnet)"
)

var ruleNames = []string{RuleName, RuleNamePublic}

var (
	// ErrUnsupported is returned on operating systems other than Windows.
	ErrUnsupported = errors.New("firewall: the inbound rule is only used on Windows")
	// ErrCancelled means the administrator prompt was declined.
	ErrCancelled = errors.New("firewall: the administrator prompt was cancelled")
)

func addArgs(exe string) [][]string {
	base := func(name string) []string {
		return []string{"advfirewall", "firewall", "add", "rule",
			"name=" + name, "dir=in", "action=allow", "program=" + exe, "protocol=UDP"}
	}
	return [][]string{
		append(base(RuleName), "profile=private,domain", "enable=yes"),
		append(base(RuleNamePublic), "profile=public", "remoteip=localsubnet", "enable=yes"),
	}
}

func deleteArgs(name string) []string {
	return []string{"advfirewall", "firewall", "delete", "rule", "name=" + name}
}

func showArgs(name string) []string {
	return []string{"advfirewall", "firewall", "show", "rule", "name=" + name, "verbose"}
}

// ruleCoversProgram reports whether netsh's verbose listing of our rule(s)
// names exe. Labels in that output are localised but paths are not; for a
// non-ASCII path (printed in the OEM code page) the presence of a rule with
// our name is accepted.
func ruleCoversProgram(out []byte, exe string) bool {
	for i := 0; i < len(exe); i++ {
		if exe[i] >= 0x80 {
			return true
		}
	}
	return strings.Contains(strings.ToLower(string(out)), strings.ToLower(exe))
}

// validExe rejects paths netsh cannot take as a single program= value.
func validExe(exe string) bool {
	return exe != "" && !strings.ContainsAny(exe, "\"\r\n\x00")
}
