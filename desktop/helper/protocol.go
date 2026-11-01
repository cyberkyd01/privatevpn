//go:build !android

// Package helper is the privileged tunnel helper (ARCHITECTURE §13.5): the
// elevated `private-vpn-pro tunnel-helper` process (Run) and the unprivileged
// main process's proxy to it (Client, returned by New).
//
// Transport: newline-delimited JSON, one object per line, at most 64 KiB per
// line, over a named pipe (Windows) or a Unix socket (macOS, Linux).
package helper

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"strings"
)

// MaxLine is the protocol's line limit, excluding the newline.
const MaxLine = 64 << 10

// Ops (§13.5). "down" removes the tunnel and the kill-switch block (also a
// block left by an earlier crashed session; it works with nothing up).
// "exit" and a closed connection only remove the tunnel: a block stays.
const (
	opHello       = "hello"
	opUp          = "up"
	opStatus      = "status"
	opSetEndpoint = "set_endpoint"
	opRouteAdd    = "route_add"
	opRouteDel    = "route_del"
	opDown        = "down"
	opExit        = "exit"
)

// Error codes in responses.
const (
	codeBadRequest      = "bad_request"
	codeHelloRequired   = "hello_required"
	codeVersionMismatch = "version_mismatch"
	codeNotElevated     = "not_elevated"
	codeFailed          = "failed"
)

// Event kinds of unsolicited lines. "log" (helper event-log lines) is an
// extension of §13.5 so helper diagnostics reach the main process's log.
const (
	evTunnel = "tunnel"
	evLog    = "log"
)

// request is a client → helper line.
type request struct {
	ID       uint64          `json:"id"`
	Op       string          `json:"op"`
	Version  string          `json:"version,omitempty"`
	Config   json.RawMessage `json:"config,omitempty"`
	Endpoint string          `json:"endpoint,omitempty"`
	Dst      string          `json:"dst,omitempty"`
}

// response is a helper → client reply to the request with the same id.
type response struct {
	ID              uint64  `json:"id"`
	OK              bool    `json:"ok"`
	Error           string  `json:"error,omitempty"`
	Code            string  `json:"code,omitempty"`
	Version         string  `json:"version,omitempty"`
	Elevated        *bool   `json:"elevated,omitempty"`
	IfName          string  `json:"ifname,omitempty"`
	HandshakeAgeSec *int64  `json:"handshake_age_sec,omitempty"`
	Rx              *uint64 `json:"rx,omitempty"`
	Tx              *uint64 `json:"tx,omitempty"`
	EndpointOK      *bool   `json:"endpoint_ok,omitempty"`
	// status: tunnel.Status.Warnings codes and whether the OS-level block
	// (kill switch) is installed.
	Warnings         []string `json:"warnings,omitempty"`
	KillSwitchActive *bool    `json:"kill_switch_active,omitempty"`
}

// event is an unsolicited helper → client line.
type event struct {
	Ev      string `json:"ev"`
	State   string `json:"state,omitempty"`
	Message string `json:"message,omitempty"`
}

// inbound is what the client decodes: a response or an event.
type inbound struct {
	response
	Ev      string `json:"ev"`
	State   string `json:"state"`
	Message string `json:"message"`
}

var errLineTooLong = errors.New("helper: protocol line too long")

// readLine reads one '\n'-terminated line of at most max bytes (newline and
// an optional preceding '\r' excluded). The returned slice is a fresh copy.
func readLine(r *bufio.Reader, max int) ([]byte, error) {
	var line []byte
	for {
		frag, err := r.ReadSlice('\n')
		if len(line)+len(frag) > max+2 {
			clear(line)
			return nil, errLineTooLong
		}
		line = append(line, frag...)
		switch {
		case err == nil:
			line = line[:len(line)-1]
			if n := len(line); n > 0 && line[n-1] == '\r' {
				line = line[:n-1]
			}
			if len(line) > max {
				clear(line)
				return nil, errLineTooLong
			}
			return line, nil
		case errors.Is(err, bufio.ErrBufferFull):
			continue
		case errors.Is(err, io.EOF) && len(line) > 0:
			clear(line)
			return nil, io.ErrUnexpectedEOF
		default:
			clear(line)
			return nil, err
		}
	}
}

// marshalLine encodes v as one protocol line.
func marshalLine(v any) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	if len(b) > MaxLine {
		return nil, errLineTooLong
	}
	return append(b, '\n'), nil
}

// validVersion bounds the version string exchanged in hello.
func validVersion(v string) bool {
	if v == "" || len(v) > 64 {
		return false
	}
	for _, r := range v {
		if r <= 0x20 || r >= 0x7f {
			return false
		}
	}
	return true
}

// parseHostDst parses a route_add/route_del destination: "a.b.c.d" or
// "a.b.c.d/32". Anything else is rejected.
func parseHostDst(s string) (netip.Addr, error) {
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil || p.Bits() != 32 || !p.Addr().Is4() {
			return netip.Addr{}, errors.New("dst must be a single IPv4 host (/32)")
		}
		return p.Addr(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil || !a.Is4() {
		return netip.Addr{}, errors.New("dst must be a single IPv4 host (/32)")
	}
	return a, nil
}

// randomHex returns 16 lowercase hex characters from crypto/rand.
func randomHex() (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

func isHex16(s string) bool {
	if len(s) != 16 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
