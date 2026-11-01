//go:build !android

// Package web is the desktop app's loopback HTTP server: the embedded web UI
// (ui/) and the /api/v1 local API, implementing the security rules of
// ARCHITECTURE §13.4 and the route table of §14.1.
//
// Every request goes through ServeHTTP, which in order: sets the security
// headers, enforces the exact Host, and then either serves a static file or
// authenticates the API request (session cookie; for non-GET also Origin,
// Sec-Fetch-Site and the CSRF header; JSON bodies capped at 64 KiB).
package web

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cyberkyd01/private-vpn-pro/core/api"
)

// Fixed parameters (ARCHITECTURE §13.4).
const (
	DefaultPort   = 47771
	fallbackFirst = 47772
	fallbackLast  = 47780

	tokenTTL       = 60 * time.Second
	maxTokens      = 8
	maxSessions    = 4
	sessionIdle    = 12 * time.Hour
	maxBody        = 64 << 10
	sessionRate    = 5 // requests per second on /api/v1/session
	heartbeatEvery = 20 * time.Second

	cookieName = "pvp_s"
	csrfHeader = "X-PVP-CSRF"
)

// csp is the Content-Security-Policy, verbatim from §13.4.
const csp = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; " +
	"connect-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'; object-src 'none'"

// Backend is the engine as seen by the web server (core/engine.Engine
// satisfies it). Tests use a fake.
type Backend interface {
	Call(method string, args []byte) ([]byte, *api.Error)
	Subscribe(fn func(event []byte)) (cancel func())
}

// Options configure New.
type Options struct {
	// Port is the preferred port (settings ui.port); 0 means DefaultPort.
	// When it is busy, 47772–47780 are tried in order.
	Port int

	// ports overrides the candidate list (tests; 0 = any free port).
	ports []int
}

// Server is the loopback web server. Create with New, then Start.
type Server struct {
	b    Backend
	opts Options
	mux  *http.ServeMux

	// Set once by setPort before serving; read-only afterwards.
	port   int
	host   string // "127.0.0.1:<port>"
	origin string // "http://127.0.0.1:<port>"

	now       func() time.Time
	heartbeat time.Duration

	auth authState

	srv       *http.Server
	done      chan struct{}
	closeOnce sync.Once
}

// New returns an unstarted server.
func New(b Backend, opts Options) *Server {
	s := &Server{
		b:         b,
		opts:      opts,
		now:       time.Now,
		heartbeat: heartbeatEvery,
		done:      make(chan struct{}),
	}
	s.auth.init()
	s.mux = s.routes()
	return s
}

// candidates returns the ports to try, preferred first.
func (s *Server) candidates() []int {
	if s.opts.ports != nil {
		return s.opts.ports
	}
	pref := s.opts.Port
	if pref < 1024 || pref > 65535 {
		pref = DefaultPort
	}
	out := []int{pref}
	for p := fallbackFirst; p <= fallbackLast; p++ {
		if p != pref {
			out = append(out, p)
		}
	}
	return out
}

// Start binds 127.0.0.1 (never a name, never IPv6, never 0.0.0.0) on the
// first free candidate port and serves in the background.
func (s *Server) Start() error {
	var ln net.Listener
	var lastErr error
	for _, p := range s.candidates() {
		l, err := listenLoopback(p)
		if err == nil {
			ln = l
			break
		}
		lastErr = err
	}
	if ln == nil {
		return fmt.Errorf("web: no free port in 47771–47780: %w", lastErr)
	}
	s.setPort(ln.Addr().(*net.TCPAddr).Port)
	s.srv = &http.Server{
		Handler:           s,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
		// net/http must not print anything (no logs, §12).
		ErrorLog: log.New(io.Discard, "", 0),
	}
	go s.srv.Serve(ln)
	return nil
}

func (s *Server) setPort(p int) {
	s.port = p
	s.host = "127.0.0.1:" + strconv.Itoa(p)
	s.origin = "http://" + s.host
}

// Port returns the bound port (0 before Start).
func (s *Server) Port() int { return s.port }

// MintLoginURL creates a single-use, 60-second login token and returns
// http://127.0.0.1:<port>/#t=<token>. The token travels in the fragment so
// it is never sent to the server in a request line or Referer.
func (s *Server) MintLoginURL() string {
	tok := s.auth.mint(s.now())
	return s.origin + "/#t=" + tok
}

// Close stops the server: SSE streams end, in-flight requests get a short
// grace period (a pre-connected browser socket would otherwise hold
// Shutdown for 5 s), then every connection is closed.
func (s *Server) Close() error {
	s.closeOnce.Do(func() { close(s.done) })
	if s.srv == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	err := s.srv.Shutdown(ctx)
	if errors.Is(err, context.DeadlineExceeded) {
		err = s.srv.Close()
	}
	return err
}

// ServeHTTP is the single entry point; see the package comment.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("Content-Security-Policy", csp)
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Cross-Origin-Opener-Policy", "same-origin")
	h.Set("Cross-Origin-Resource-Policy", "same-origin")
	// no-store everywhere: /api/* per §13.4, and "/" because it serves
	// index.html or login.html depending on the session.
	h.Set("Cache-Control", "no-store")

	// Exact Host match defeats DNS rebinding (T7); "localhost" is refused too.
	if s.host == "" || r.Host != s.host {
		w.WriteHeader(http.StatusMisdirectedRequest)
		return
	}
	if r.URL.Path == "/api" || strings.HasPrefix(r.URL.Path, "/api/") {
		s.serveAPI(w, r)
		return
	}
	s.serveStatic(w, r)
}

// --- request checks ---------------------------------------------------------

func isSafeMethod(m string) bool { return m == http.MethodGet || m == http.MethodHead }

// fetchSiteOK: Sec-Fetch-Site, if present, must be same-origin or none.
func fetchSiteOK(r *http.Request) bool {
	v := r.Header.Values("Sec-Fetch-Site")
	switch len(v) {
	case 0:
		return true
	case 1:
		return v[0] == "same-origin" || v[0] == "none"
	}
	return false
}

// originOK: exactly one Origin header equal to http://127.0.0.1:<port>.
func (s *Server) originOK(r *http.Request) bool {
	v := r.Header.Values("Origin")
	return len(v) == 1 && v[0] == s.origin
}

// readBody enforces the JSON content type and the 64 KiB cap. It returns
// nil for an empty body. On failure the response has been written.
func readBody(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	if r.ContentLength > maxBody {
		writeErr(w, http.StatusRequestEntityTooLarge, "too_large", "request body exceeds 64 KiB")
		return nil, false
	}
	if r.ContentLength == 0 {
		return nil, true
	}
	if !isJSONContentType(r.Header.Get("Content-Type")) {
		writeErr(w, http.StatusUnsupportedMediaType, "bad_content_type", "Content-Type must be application/json")
		return nil, false
	}
	b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			writeErr(w, http.StatusRequestEntityTooLarge, "too_large", "request body exceeds 64 KiB")
		} else {
			writeErr(w, http.StatusBadRequest, api.CodeBadRequest, "could not read request body")
		}
		return nil, false
	}
	if len(b) == 0 {
		return nil, true
	}
	return b, true
}

func isJSONContentType(ct string) bool {
	mt, _, ok := strings.Cut(ct, ";")
	if !ok {
		mt = ct
	}
	return strings.EqualFold(strings.TrimSpace(mt), "application/json")
}

// --- responses --------------------------------------------------------------

func writeJSON(w http.ResponseWriter, status int, body []byte) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	w.Write(body)
}

func writeErr(w http.ResponseWriter, status int, code, msg string) {
	writeAPIErr(w, &api.Error{Code: code, Message: msg, HTTP: status})
}

func writeAPIErr(w http.ResponseWriter, e *api.Error) {
	status := e.HTTP
	if status < 400 || status > 599 {
		status = http.StatusBadRequest
	}
	writeJSON(w, status, e.JSON())
}
