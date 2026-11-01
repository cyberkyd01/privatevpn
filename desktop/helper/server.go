//go:build !android

package helper

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/cyberkyd01/private-vpn-pro/core/eventlog"
	"github.com/cyberkyd01/private-vpn-pro/core/tunnel"
)

// Version is this binary's version, compared with the caller's in hello.
// cmd/private-vpn-pro sets it before calling Run (or links it with
// -X github.com/cyberkyd01/private-vpn-pro/desktop/helper.Version=…).
var Version = "dev"

// Exit codes of Run (126/127 are left to pkexec).
const (
	exitOK          = 0
	exitUsage       = 2
	exitNotElevated = 3
	exitSetup       = 4
	exitNoClient    = 5
	exitPanic       = 6
)

// acceptTimeout bounds how long the helper waits for its caller; the caller
// itself gives up after 60 s.
const acceptTimeout = 75 * time.Second

// Run is the `private-vpn-pro tunnel-helper` entry point. args are the arguments
// after the subcommand (a leading "tunnel-helper" is tolerated):
//
//	Windows:     --pipe private-vpn-pro-helper-<16 hex> --sid <user SID>
//	macOS/Linux: --socket <dir>/helper-<16 hex>.sock --uid <n>
//
// It refuses to run unelevated, cleans up tunnel leftovers of a previous
// crash, accepts exactly one connection, serves it, and removes the tunnel
// and exits when the connection closes or the client sends exit. A
// kill-switch block is deliberately kept on that path (tunnel.Tunnel.Close):
// only the explicit "down" op lifts it.
func Run(args []string) (code int) {
	if len(args) > 0 && args[0] == "tunnel-helper" {
		args = args[1:]
	}
	opts, err := parseArgs(args)
	if err != nil {
		return exitUsage
	}
	if !tunnel.IsElevated() {
		return exitNotElevated
	}
	debug.SetTraceback("none") // no goroutine dumps with session data (§12.1)
	sanitizeEnv()
	log := eventlog.New(256)
	log.Printf("helper", "started (version %s)", Version)
	// NewNative also removes leftovers of a previous crash (§13.5).
	t, err := tunnel.NewNative(log)
	if err != nil {
		if errors.Is(err, tunnel.ErrNotElevated) {
			return exitNotElevated
		}
		return exitSetup
	}
	defer t.Close() // keeps a kill-switch block; "down" is the only way out
	conn, err := acceptOne(opts, acceptTimeout)
	if err != nil {
		return exitNoClient
	}
	defer conn.Close()
	defer func() {
		if r := recover(); r != nil {
			code = exitPanic
		}
	}()
	_ = serve(conn, t, Version, log)
	return exitOK
}

type server struct {
	t       tunnel.Tunnel
	version string
	log     *eventlog.Log

	wmu sync.Mutex
	w   io.Writer

	hello bool
}

func (s *server) send(v any) error {
	b, err := marshalLine(v)
	if err != nil {
		return err
	}
	s.wmu.Lock()
	defer s.wmu.Unlock()
	if d, ok := s.w.(interface{ SetWriteDeadline(time.Time) error }); ok {
		_ = d.SetWriteDeadline(time.Now().Add(10 * time.Second))
	}
	_, err = s.w.Write(b)
	return err
}

// serve runs the protocol on conn until it closes, the client sends exit,
// or a protocol violation (oversized line, version mismatch). The caller
// tears the tunnel down afterwards.
func serve(conn io.ReadWriteCloser, t tunnel.Tunnel, version string, log *eventlog.Log) error {
	s := &server{t: t, version: version, log: log, w: conn}

	// Forward event-log lines (already §12.1-clean) as "log" events. The
	// subscriber must not block: drop lines if the client is slow.
	logs := make(chan string, 256)
	stop := make(chan struct{})
	go func() {
		// Not waited for on return: it may be blocked writing to a peer
		// that stopped reading; closing conn (the caller does) ends it.
		for {
			select {
			case line := <-logs:
				if s.send(event{Ev: evLog, Message: line}) != nil {
					return
				}
			case <-stop:
				return
			}
		}
	}()
	for _, l := range log.Lines() {
		select {
		case logs <- l:
		default:
		}
	}
	cancelSub := log.Subscribe(func(line string) {
		select {
		case logs <- line:
		default:
		}
	})
	if n, ok := t.(tunnel.Notifier); ok {
		n.SetNotify(func(ev tunnel.Event) {
			_ = s.send(event{Ev: evTunnel, State: ev.State, Message: ev.Message})
		})
	}
	defer func() {
		if n, ok := t.(tunnel.Notifier); ok {
			n.SetNotify(nil)
		}
		cancelSub()
		close(stop)
	}()

	r := bufio.NewReaderSize(conn, 4096)
	for {
		line, err := readLine(r, MaxLine)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		resp, exit := s.handleLine(line)
		clear(line) // may hold the session private key
		if err := s.send(resp); err != nil {
			return err
		}
		if exit {
			return nil
		}
	}
}

func (s *server) handleLine(line []byte) (response, bool) {
	var req request
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil || dec.More() {
		return fail(response{}, codeBadRequest, "malformed request"), false
	}
	defer clear(req.Config)
	return s.handle(&req)
}

func fail(r response, code, msg string) response {
	r.OK, r.Code, r.Error = false, code, msg
	return r
}

// failErr reports a tunnel error, redacted once more as defence in depth.
func failErr(r response, err error) response {
	if errors.Is(err, tunnel.ErrNotElevated) {
		return fail(r, codeNotElevated, err.Error())
	}
	return fail(r, codeFailed, tunnel.Redact(err.Error()))
}

// fieldsOnly checks that req carries exactly the fields op allows.
func fieldsOnly(req *request, version, config, endpoint, dst bool) bool {
	return (req.Version != "") == version && (len(req.Config) > 0) == config &&
		(req.Endpoint != "") == endpoint && (req.Dst != "") == dst
}

func (s *server) handle(req *request) (response, bool) {
	resp := response{ID: req.ID}
	if !s.hello && req.Op != opHello {
		return fail(resp, codeHelloRequired, "hello required"), false
	}
	switch req.Op {
	case opHello:
		if !fieldsOnly(req, true, false, false, false) || !validVersion(req.Version) {
			return fail(resp, codeBadRequest, "bad hello"), false
		}
		if req.Version != s.version {
			s.log.Printf("helper", "version mismatch (helper %s); exiting", s.version)
			resp = fail(resp, codeVersionMismatch, "helper version "+s.version+" differs from the app")
			resp.Version = s.version
			return resp, true
		}
		s.hello = true
		elevated := true
		resp.OK, resp.Version, resp.Elevated = true, s.version, &elevated
		return resp, false

	case opUp:
		if !fieldsOnly(req, false, true, false, false) {
			return fail(resp, codeBadRequest, "bad up"), false
		}
		cfg := new(tunnel.Config)
		defer wipe(cfg)
		err := json.Unmarshal(req.Config, cfg) // errors name fields, never values
		if err == nil {
			err = cfg.Validate()
		}
		if err != nil {
			return fail(resp, codeBadRequest, "config: "+tunnel.Redact(err.Error())), false
		}
		ifname, err := s.t.Up(*cfg)
		if err != nil {
			return failErr(resp, err), false
		}
		resp.OK, resp.IfName = true, ifname
		return resp, false

	case opStatus:
		if !fieldsOnly(req, false, false, false, false) {
			return fail(resp, codeBadRequest, "bad status"), false
		}
		st, err := s.t.Status()
		if err != nil {
			return failErr(resp, err), false
		}
		epOK := true
		if r, ok := s.t.(tunnel.EndpointRouteReporter); ok {
			epOK = r.EndpointRouteOK()
		}
		ks := st.KillSwitchActive
		resp.OK, resp.IfName = true, st.IfName
		resp.HandshakeAgeSec, resp.Rx, resp.Tx, resp.EndpointOK = &st.HandshakeAgeSec, &st.RxBytes, &st.TxBytes, &epOK
		resp.Warnings, resp.KillSwitchActive = append([]string(nil), st.Warnings...), &ks
		return resp, false

	case opSetEndpoint:
		if !fieldsOnly(req, false, false, true, false) {
			return fail(resp, codeBadRequest, "bad set_endpoint"), false
		}
		ep, err := netip.ParseAddrPort(req.Endpoint)
		if err == nil {
			err = tunnel.CheckEndpoint(ep)
		}
		if err != nil {
			return fail(resp, codeBadRequest, "endpoint must be IPv4 address:port"), false
		}
		if err := s.t.SetEndpoint(ep); err != nil {
			return failErr(resp, err), false
		}
		resp.OK = true
		return resp, false

	case opRouteAdd, opRouteDel:
		if !fieldsOnly(req, false, false, false, true) {
			return fail(resp, codeBadRequest, "bad "+req.Op), false
		}
		dst, err := parseHostDst(req.Dst)
		if err == nil {
			err = tunnel.CheckPublicIPv4(dst)
		}
		if err != nil {
			return fail(resp, codeBadRequest, err.Error()), false
		}
		if req.Op == opRouteAdd {
			err = s.t.RouteAdd(dst)
		} else {
			err = s.t.RouteDel(dst)
		}
		if err != nil {
			return failErr(resp, err), false
		}
		resp.OK = true
		return resp, false

	case opDown:
		if !fieldsOnly(req, false, false, false, false) {
			return fail(resp, codeBadRequest, "bad down"), false
		}
		if err := s.t.Down(); err != nil {
			return failErr(resp, err), false
		}
		resp.OK = true
		return resp, false

	case opExit:
		resp.OK = true
		return resp, true
	}
	return fail(resp, codeBadRequest, "unknown op "+strings.Map(printable, truncate(req.Op, 32))), false
}

// wipe zeroes a decoded config (best effort: it holds the session key).
func wipe(c *tunnel.Config) { *c = tunnel.Config{} }

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func printable(r rune) rune {
	if r < 0x20 || r >= 0x7f {
		return '?'
	}
	return r
}
