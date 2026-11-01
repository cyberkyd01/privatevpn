//go:build !android

package helper

import (
	"bufio"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestReadLine(t *testing.T) {
	r := bufio.NewReaderSize(strings.NewReader("{\"a\":1}\n{\"b\":2}\r\n"+strings.Repeat("x", 100)+"\npartial"), 16)
	for _, want := range []string{`{"a":1}`, `{"b":2}`, strings.Repeat("x", 100)} {
		got, err := readLine(r, 100)
		if err != nil || string(got) != want {
			t.Fatalf("got %q %v, want %q", got, err, want)
		}
	}
	if _, err := readLine(r, 100); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("partial line: %v", err)
	}
	if _, err := readLine(bufio.NewReader(strings.NewReader("")), 100); !errors.Is(err, io.EOF) {
		t.Errorf("empty: %v", err)
	}
	long := bufio.NewReaderSize(strings.NewReader(strings.Repeat("y", 101)+"\n"), 16)
	if _, err := readLine(long, 100); !errors.Is(err, errLineTooLong) {
		t.Errorf("101 bytes: %v", err)
	}
	huge := bufio.NewReaderSize(strings.NewReader(strings.Repeat("z", 1<<20)), 4096)
	if _, err := readLine(huge, MaxLine); !errors.Is(err, errLineTooLong) {
		t.Errorf("1 MiB without newline: %v", err)
	}
}

func TestParseHostDst(t *testing.T) {
	for _, ok := range []string{"203.0.113.9", "203.0.113.9/32"} {
		if a, err := parseHostDst(ok); err != nil || a.String() != "203.0.113.9" {
			t.Errorf("%s: %v %v", ok, a, err)
		}
	}
	for _, bad := range []string{"203.0.113.0/24", "203.0.113.9/31", "::1", "2001:db8::1/128", "::ffff:1.2.3.4", "host.example", "", "1.2.3.4/32/1"} {
		if _, err := parseHostDst(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestSmallValidators(t *testing.T) {
	if !validVersion("1.0.0") || !validVersion("v1.2.3-rc1+abc") || validVersion("") || validVersion("1.0 0") || validVersion(strings.Repeat("1", 65)) {
		t.Error("validVersion")
	}
	h, err := randomHex()
	if err != nil || !isHex16(h) {
		t.Errorf("randomHex = %q %v", h, err)
	}
	if h2, _ := randomHex(); h2 == h {
		t.Error("randomHex repeats")
	}
	if isHex16("0123456789ABCDEF") || isHex16("0123456789abcde") {
		t.Error("isHex16")
	}
	if !validPipeName("private-vpn-pro-helper-0123456789abcdef") || validPipeName("private-vpn-pro-helper-../../x") || validPipeName("other-0123456789abcdef") {
		t.Error("validPipeName")
	}
	for _, ok := range []string{"S-1-5-21-3623811015-3361044348-30300820-1013", "S-1-12-1-1234-5678-9012-3456"} {
		if !sidSyntaxOK(ok) {
			t.Errorf("SID %s rejected", ok)
		}
	}
	for _, bad := range []string{"", "S-1-", "S-1-5-21)(A;;GA;;;WD", "S-1-5--1", "S-1-5-", "s-1-5-18", "S-1-5-18 "} {
		if sidSyntaxOK(bad) {
			t.Errorf("SID %q accepted", bad)
		}
	}
	if got := pipeSDDL("S-1-5-21-1-2-3-1001"); got != "D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;S-1-5-21-1-2-3-1001)" {
		t.Errorf("SDDL = %s", got)
	}
}

func TestAppleScriptCommand(t *testing.T) {
	got, err := appleScriptHelperCommand("/Applications/Private VPN Pro.app/Contents/MacOS/private-vpn-pro",
		"/var/folders/zz/abc_123/T/private-vpn-pro-501/helper-0123456789abcdef.sock", 501)
	want := `do shell script "'/Applications/Private VPN Pro.app/Contents/MacOS/private-vpn-pro' tunnel-helper --socket '/var/folders/zz/abc_123/T/private-vpn-pro-501/helper-0123456789abcdef.sock' --uid 501" with administrator privileges`
	if err != nil || got != want {
		t.Fatalf("got  %s\nwant %s\n(%v)", got, want, err)
	}
	if got, err := appleScriptHelperCommand("/Users/a b/My Apps/private-vpn-pro", "/tmp/private-vpn-pro-501/helper-0123456789abcdef.sock", 501); err != nil ||
		!strings.Contains(got, `"'/Users/a b/My Apps/private-vpn-pro' tunnel-helper`) {
		t.Errorf("spaces: %s %v", got, err)
	}
	for _, exe := range []string{
		"relative/private-vpn-pro", "/a'b/private-vpn-pro", `/a"b/private-vpn-pro`, `/a\b/private-vpn-pro`, "/a$(id)/private-vpn-pro",
		"/a`id`/private-vpn-pro", "/a;b/private-vpn-pro", "/a\nb/private-vpn-pro", "/a&b", "/a|b", "/é/private-vpn-pro", "/a*b", "",
	} {
		if _, err := appleScriptHelperCommand(exe, "/tmp/private-vpn-pro-501/helper-0123456789abcdef.sock", 501); err == nil {
			t.Errorf("exe %q accepted", exe)
		}
	}
	if _, err := appleScriptHelperCommand("/Applications/p", "/tmp/x'y/helper-0123456789abcdef.sock", 501); err == nil {
		t.Error("socket path with quote accepted")
	}
	if _, err := appleScriptHelperCommand("/Applications/p", "/tmp/s.sock", -1); err == nil {
		t.Error("negative uid accepted")
	}
}
