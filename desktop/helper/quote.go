//go:build !android

package helper

import (
	"errors"
	"path/filepath"
	"strconv"
	"strings"
)

var errUnsafePath = errors.New("helper: the application path contains characters that cannot be passed to the macOS administrator prompt safely (allowed: letters, digits, space and / _ . -); move Private VPN Pro to /Applications")

// safeShellPath allows only absolute paths over [A-Za-z0-9/_.\- ]: no quote,
// backslash, $, `, ;, newline or anything else with meaning to sh or to an
// AppleScript string literal.
func safeShellPath(p string) bool {
	if p == "" || len(p) > 1024 || !filepath.IsAbs(p) {
		return false
	}
	for _, c := range p {
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case c == '/', c == '_', c == '.', c == '-', c == ' ':
		default:
			return false
		}
	}
	return true
}

// shQuote single-quotes a string already accepted by safeShellPath (it
// cannot contain a single quote, so no escaping is needed).
func shQuote(s string) string { return "'" + s + "'" }

// appleScriptHelperCommand builds the osascript -e argument that runs the
// helper as root (§9.3). The sh command line is single-quoted per argument;
// it contains no '"' or '\', so it is also a valid AppleScript string
// literal without escaping. Anything else is refused.
func appleScriptHelperCommand(exe, socket string, uid int) (string, error) {
	if !safeShellPath(exe) || !safeShellPath(socket) || uid < 0 {
		return "", errUnsafePath
	}
	sh := shQuote(exe) + " tunnel-helper --socket " + shQuote(socket) + " --uid " + strconv.Itoa(uid)
	return `do shell script "` + sh + `" with administrator privileges`, nil
}

// validPipeName accepts only private-vpn-pro-helper-<16 hex> (Windows).
func validPipeName(name string) bool {
	return strings.HasPrefix(name, "private-vpn-pro-helper-") && isHex16(strings.TrimPrefix(name, "private-vpn-pro-helper-"))
}

// sidSyntaxOK admits only "S-1-<digits and dashes>", so the value cannot
// inject ACEs into the pipe's SDDL string.
func sidSyntaxOK(s string) bool {
	if len(s) < 5 || len(s) > 184 || !strings.HasPrefix(s, "S-1-") || strings.Contains(s, "--") || strings.HasSuffix(s, "-") {
		return false
	}
	for _, c := range s[4:] {
		if !(c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

// pipeSDDL grants SYSTEM, Administrators and the launching user only (§13.5).
func pipeSDDL(sid string) string {
	return "D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;" + sid + ")"
}
