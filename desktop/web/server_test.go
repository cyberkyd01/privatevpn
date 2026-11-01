//go:build !android

package web

import (
	"bufio"
	"bytes"
	"encoding/json"
	"image/png"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cyberkyd01/private-vpn-pro/core/api"
)

// ---------------------------------------------------------------------------
// fakes and helpers

type call struct {
	method string
	args   map[string]any
}

type fakeBackend struct {
	mu      sync.Mutex
	calls   []call
	results map[string][]byte
	errs    map[string]*api.Error
	subs    map[int]func([]byte)
	nextSub int
}

func newFake() *fakeBackend {
	return &fakeBackend{results: map[string][]byte{}, errs: map[string]*api.Error{}, subs: map[int]func([]byte){}}
}

func (f *fakeBackend) Call(method string, args []byte) ([]byte, *api.Error) {
	var m map[string]any
	if err := json.Unmarshal(args, &m); err != nil {
		panic("backend got invalid args JSON: " + string(args))
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, call{method, m})
	if e := f.errs[method]; e != nil {
		return nil, e
	}
	if r, ok := f.results[method]; ok {
		return r, nil
	}
	return []byte(`{"ok":true}`), nil
}

func (f *fakeBackend) Subscribe(fn func([]byte)) func() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nextSub++
	id := f.nextSub
	f.subs[id] = fn
	return func() {
		f.mu.Lock()
		delete(f.subs, id)
		f.mu.Unlock()
	}
}

func (f *fakeBackend) emit(ev string) {
	f.mu.Lock()
	fns := make([]func([]byte), 0, len(f.subs))
	for _, fn := range f.subs {
		fns = append(fns, fn)
	}
	f.mu.Unlock()
	for _, fn := range fns {
		fn([]byte(ev))
	}
}

func (f *fakeBackend) subCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.subs)
}

func (f *fakeBackend) lastCall(t *testing.T) call {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.calls) == 0 {
		t.Fatal("backend was not called")
	}
	return f.calls[len(f.calls)-1]
}

func (f *fakeBackend) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

const testHost = "127.0.0.1:47771"
const testOrigin = "http://" + testHost

func newTestServer(t *testing.T) (*Server, *fakeBackend, *clock) {
	t.Helper()
	b := newFake()
	s := New(b, Options{})
	s.setPort(47771)
	clk := &clock{t: time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC)}
	s.now = clk.now
	return s, b, clk
}

type reqOpt func(*http.Request)

func withHeader(k, v string) reqOpt { return func(r *http.Request) { r.Header.Set(k, v) } }
func withHost(h string) reqOpt      { return func(r *http.Request) { r.Host = h } }
func withCookie(v string) reqOpt {
	return func(r *http.Request) { r.AddCookie(&http.Cookie{Name: cookieName, Value: v}) }
}

// do sends a request through ServeHTTP. A non-empty body gets
// Content-Type: application/json unless an option overrides it.
func do(s *Server, method, path, body string, opts ...reqOpt) *httptest.ResponseRecorder {
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	r := httptest.NewRequest(method, "http://"+testHost+path, rd)
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	for _, o := range opts {
		o(r)
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	return w
}

func tokenOf(t *testing.T, loginURL string) string {
	t.Helper()
	pfx := testOrigin + "/#t="
	if !strings.HasPrefix(loginURL, pfx) {
		t.Fatalf("login URL %q does not start with %q", loginURL, pfx)
	}
	return strings.TrimPrefix(loginURL, pfx)
}

func exchange(s *Server, tok string, opts ...reqOpt) *httptest.ResponseRecorder {
	b, _ := json.Marshal(map[string]string{"token": tok})
	opts = append([]reqOpt{withHeader("Origin", testOrigin)}, opts...)
	return do(s, "POST", "/api/v1/session", string(b), opts...)
}

// login performs the full token → session exchange; returns cookie, csrf.
func login(t *testing.T, s *Server) (string, string) {
	t.Helper()
	w := exchange(s, tokenOf(t, s.MintLoginURL()))
	if w.Code != 200 {
		t.Fatalf("session exchange: %d %s", w.Code, w.Body)
	}
	var cookie string
	for _, c := range w.Result().Cookies() {
		if c.Name == cookieName {
			cookie = c.Value
		}
	}
	var body struct{ CSRF string }
	json.Unmarshal(w.Body.Bytes(), &body)
	if cookie == "" || body.CSRF == "" {
		t.Fatalf("no cookie/csrf: %v %s", w.Header(), w.Body)
	}
	return cookie, body.CSRF
}

// authed returns options for a fully valid same-origin non-GET request.
func authed(cookie, csrf string) []reqOpt {
	return []reqOpt{withCookie(cookie), withHeader("Origin", testOrigin), withHeader(csrfHeader, csrf), withHeader("Sec-Fetch-Site", "same-origin")}
}

func checkSecurityHeaders(t *testing.T, name string, h http.Header) {
	t.Helper()
	want := map[string]string{
		"Content-Security-Policy":      "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'; object-src 'none'",
		"X-Content-Type-Options":       "nosniff",
		"X-Frame-Options":              "DENY",
		"Referrer-Policy":              "no-referrer",
		"Cross-Origin-Opener-Policy":   "same-origin",
		"Cross-Origin-Resource-Policy": "same-origin",
	}
	for k, v := range want {
		if got := h.Get(k); got != v {
			t.Errorf("%s: %s = %q, want %q", name, k, got, v)
		}
	}
	for k := range h {
		if strings.HasPrefix(strings.ToLower(k), "access-control-") {
			t.Errorf("%s: forbidden CORS header %s", name, k)
		}
	}
}

// ---------------------------------------------------------------------------
// Host check

func TestHostCheck421(t *testing.T) {
	s, b, _ := newTestServer(t)
	cookie, csrf := login(t, s)
	hosts := []string{
		"evil.example", "evil.example:47771", "localhost:47771", "localhost", "LOCALHOST:47771",
		"127.0.0.1", "127.0.0.1:47772", "127.0.0.1:80", "[::1]:47771", "127.0.0.1.:47771",
		"0.0.0.0:47771", "127.0.0.2:47771", "",
	}
	paths := []string{"/", "/app.js", "/api/v1/status", "/api/v1/session", "/api/v1/events", "/api/v1/keyring/x/qr.png"}
	before := b.callCount()
	for _, host := range hosts {
		for _, p := range paths {
			w := do(s, "GET", p, "", withHost(host), withCookie(cookie))
			if w.Code != http.StatusMisdirectedRequest {
				t.Errorf("Host %q %s: got %d, want 421", host, p, w.Code)
			}
			if w.Body.Len() != 0 {
				t.Errorf("Host %q %s: 421 must have no body, got %q", host, p, w.Body)
			}
			checkSecurityHeaders(t, "421", w.Header())
		}
		w := do(s, "POST", "/api/v1/client/disconnect", "{}", append(authed(cookie, csrf), withHost(host))...)
		if w.Code != http.StatusMisdirectedRequest {
			t.Errorf("POST Host %q: got %d, want 421", host, w.Code)
		}
	}
	if b.callCount() != before {
		t.Error("backend was called for a misdirected request")
	}
}

func TestLocalhostHostIs421(t *testing.T) {
	s, _, _ := newTestServer(t)
	w := do(s, "GET", "/api/v1/status", "", withHost("localhost:47771"))
	if w.Code != 421 {
		t.Fatalf("Host localhost:47771 → %d, want 421", w.Code)
	}
}

// ---------------------------------------------------------------------------
// sessions and tokens

func TestNoSession401(t *testing.T) {
	s, b, _ := newTestServer(t)
	for _, p := range []string{"/api/v1/status", "/api/v1/gateways", "/api/v1/events", "/api/v1/keyring/abc/qr.png", "/api/v1/nonexistent", "/api/v1/session"} {
		w := do(s, "GET", p, "")
		if w.Code != 401 {
			t.Errorf("GET %s without session: %d, want 401", p, w.Code)
		}
		w = do(s, "GET", p, "", withCookie("bogus"))
		if w.Code != 401 {
			t.Errorf("GET %s with bogus cookie: %d, want 401", p, w.Code)
		}
	}
	w := do(s, "POST", "/api/v1/client/disconnect", "{}", withHeader("Origin", testOrigin), withHeader(csrfHeader, "x"))
	if w.Code != 401 {
		t.Errorf("POST without session: %d, want 401", w.Code)
	}
	if b.callCount() != 0 {
		t.Error("backend called without a session")
	}
	// "/" serves the login page without a session.
	w = do(s, "GET", "/", "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), `data-page="login"`) {
		t.Errorf("/ without session should serve login.html, got %d", w.Code)
	}
	w = do(s, "GET", "/index.html", "")
	if !strings.Contains(w.Body.String(), `data-page="login"`) {
		t.Error("/index.html without session should serve login.html")
	}
}

func TestLoginFlowAndCookieAttributes(t *testing.T) {
	s, b, _ := newTestServer(t)
	u := s.MintLoginURL()
	tok := tokenOf(t, u)
	if len(tok) != 43 {
		t.Errorf("token length %d, want 43 (32 bytes base64url)", len(tok))
	}
	w := exchange(s, tok, withHeader("Sec-Fetch-Site", "same-origin"))
	if w.Code != 200 {
		t.Fatalf("exchange: %d %s", w.Code, w.Body)
	}
	sc := w.Header().Values("Set-Cookie")
	if len(sc) != 1 {
		t.Fatalf("Set-Cookie: %v", sc)
	}
	c := sc[0]
	for _, want := range []string{"pvp_s=", "HttpOnly", "SameSite=Strict", "Path=/"} {
		if !strings.Contains(c, want) {
			t.Errorf("Set-Cookie %q lacks %q", c, want)
		}
	}
	for _, bad := range []string{"Domain=", "Max-Age", "Expires"} {
		if strings.Contains(c, bad) {
			t.Errorf("Set-Cookie %q must not contain %q", c, bad)
		}
	}
	if ct := w.Header().Get("Cache-Control"); ct != "no-store" {
		t.Errorf("Cache-Control on /api: %q", ct)
	}
	var body map[string]string
	json.Unmarshal(w.Body.Bytes(), &body)
	if len(body["csrf"]) != 43 || len(body) != 1 {
		t.Errorf("session body %v", body)
	}
	cookie := w.Result().Cookies()[0].Value
	if len(cookie) != 43 || cookie == body["csrf"] {
		t.Errorf("cookie %q", cookie)
	}
	// Authenticated GET works and reaches the backend.
	b.results[api.StatusGet] = []byte(`{"version":"1.2.3"}`)
	w = do(s, "GET", "/api/v1/status", "", withCookie(cookie))
	if w.Code != 200 || w.Body.String() != `{"version":"1.2.3"}` {
		t.Fatalf("status: %d %s", w.Code, w.Body)
	}
	if b.lastCall(t).method != api.StatusGet {
		t.Error("status.get not called")
	}
	// "/" now serves the app.
	w = do(s, "GET", "/", "", withCookie(cookie))
	if !strings.Contains(w.Body.String(), `data-page="app"`) {
		t.Error("/ with a session should serve index.html")
	}
	// GET /session returns the same CSRF token (page reload).
	w = do(s, "GET", "/api/v1/session", "", withCookie(cookie))
	var again map[string]string
	json.Unmarshal(w.Body.Bytes(), &again)
	if w.Code != 200 || again["csrf"] != body["csrf"] {
		t.Errorf("GET /session: %d %v", w.Code, again)
	}
}

func TestTokenSingleUse(t *testing.T) {
	s, _, _ := newTestServer(t)
	tok := tokenOf(t, s.MintLoginURL())
	if w := exchange(s, tok); w.Code != 200 {
		t.Fatalf("first use: %d", w.Code)
	}
	if w := exchange(s, tok); w.Code != 401 {
		t.Fatalf("second use: %d, want 401", w.Code)
	}
	// A token is also burnt by a failed attempt (deleted on first sight).
	tok2 := tokenOf(t, s.MintLoginURL())
	if w := exchange(s, tok2, withHeader("Sec-Fetch-Site", "same-origin")); w.Code != 200 {
		t.Fatalf("tok2: %d", w.Code)
	}
	if w := exchange(s, "not-a-token"); w.Code != 401 {
		t.Fatalf("unknown token: %d", w.Code)
	}
	if w := exchange(s, ""); w.Code != 401 {
		t.Fatalf("empty token: %d", w.Code)
	}
}

func TestTokenExpiry(t *testing.T) {
	s, _, clk := newTestServer(t)
	tok := tokenOf(t, s.MintLoginURL())
	clk.add(59 * time.Second)
	if w := exchange(s, tok); w.Code != 200 {
		t.Fatalf("at 59 s: %d, want 200", w.Code)
	}
	tok = tokenOf(t, s.MintLoginURL())
	clk.add(60 * time.Second)
	if w := exchange(s, tok); w.Code != 401 {
		t.Fatalf("at 60 s: %d, want 401", w.Code)
	}
	tok = tokenOf(t, s.MintLoginURL())
	clk.add(10 * time.Minute)
	if w := exchange(s, tok); w.Code != 401 {
		t.Fatalf("at 10 min: %d, want 401", w.Code)
	}
}

func TestMaxEightOutstandingTokens(t *testing.T) {
	s, _, clk := newTestServer(t)
	var toks []string
	for i := 0; i < 9; i++ {
		toks = append(toks, tokenOf(t, s.MintLoginURL()))
		clk.add(time.Millisecond)
	}
	s.auth.mu.Lock()
	n := len(s.auth.tokens)
	s.auth.mu.Unlock()
	if n != 8 {
		t.Fatalf("%d outstanding tokens, want 8", n)
	}
	if w := exchange(s, toks[0]); w.Code != 401 {
		t.Errorf("oldest token should have been evicted: %d", w.Code)
	}
	for i := 1; i < 9; i++ {
		clk.add(250 * time.Millisecond) // stay under the 5 req/s limit
		if w := exchange(s, toks[i]); w.Code != 200 {
			t.Errorf("token %d: %d", i, w.Code)
		}
	}
}

func TestSessionEndpointChecks(t *testing.T) {
	s, _, clk := newTestServer(t)
	tok := tokenOf(t, s.MintLoginURL())
	body := `{"token":"` + tok + `"}`
	cases := []struct {
		name string
		opts []reqOpt
		want int
	}{
		{"no origin", nil, 403},
		{"wrong origin", []reqOpt{withHeader("Origin", "http://evil.example")}, 403},
		{"localhost origin", []reqOpt{withHeader("Origin", "http://localhost:47771")}, 403},
		{"cross-site", []reqOpt{withHeader("Origin", testOrigin), withHeader("Sec-Fetch-Site", "cross-site")}, 403},
		{"text/plain", []reqOpt{withHeader("Origin", testOrigin), withHeader("Content-Type", "text/plain")}, 415},
	}
	for _, c := range cases {
		clk.add(time.Second)
		if w := do(s, "POST", "/api/v1/session", body, c.opts...); w.Code != c.want {
			t.Errorf("%s: %d, want %d", c.name, w.Code, c.want)
		}
	}
	// The token was never consumed by the refused attempts.
	clk.add(time.Second)
	if w := exchange(s, tok); w.Code != 200 {
		t.Errorf("valid exchange after refusals: %d", w.Code)
	}
}

func TestSessionRateLimit(t *testing.T) {
	s, _, clk := newTestServer(t)
	codes := []int{}
	for i := 0; i < 7; i++ {
		codes = append(codes, do(s, "GET", "/api/v1/session", "").Code)
	}
	for i, c := range codes {
		want := 401
		if i >= 5 {
			want = 429
		}
		if c != want {
			t.Errorf("request %d: %d, want %d (%v)", i, c, want, codes)
		}
	}
	clk.add(time.Second)
	if c := do(s, "GET", "/api/v1/session", "").Code; c != 401 {
		t.Errorf("after 1 s: %d, want 401 (not limited)", c)
	}
	// Other endpoints are not limited.
	for i := 0; i < 20; i++ {
		if c := do(s, "GET", "/api/v1/status", "").Code; c != 401 {
			t.Fatalf("status %d", c)
		}
	}
}

func TestMaxFourSessions(t *testing.T) {
	s, _, clk := newTestServer(t)
	var cookies []string
	for i := 0; i < 5; i++ {
		clk.add(time.Second)
		c, _ := login(t, s)
		cookies = append(cookies, c)
	}
	if w := do(s, "GET", "/api/v1/status", "", withCookie(cookies[0])); w.Code != 401 {
		t.Errorf("least recently used session should be evicted: %d", w.Code)
	}
	for i := 1; i < 5; i++ {
		if w := do(s, "GET", "/api/v1/status", "", withCookie(cookies[i])); w.Code != 200 {
			t.Errorf("session %d: %d", i, w.Code)
		}
	}
}

func TestSessionIdleExpiry(t *testing.T) {
	s, _, clk := newTestServer(t)
	cookie, _ := login(t, s)
	clk.add(11 * time.Hour)
	if w := do(s, "GET", "/api/v1/status", "", withCookie(cookie)); w.Code != 200 {
		t.Fatalf("after 11 h idle: %d", w.Code)
	}
	clk.add(11 * time.Hour) // activity above reset the idle timer
	if w := do(s, "GET", "/api/v1/status", "", withCookie(cookie)); w.Code != 200 {
		t.Fatalf("after 11 h idle again: %d", w.Code)
	}
	clk.add(12 * time.Hour)
	if w := do(s, "GET", "/api/v1/status", "", withCookie(cookie)); w.Code != 401 {
		t.Fatalf("after 12 h idle: %d, want 401", w.Code)
	}
}

func TestCookieTossingDoesNotShadow(t *testing.T) {
	s, _, _ := newTestServer(t)
	cookie, _ := login(t, s)
	r := httptest.NewRequest("GET", "http://"+testHost+"/api/v1/status", nil)
	r.Header.Set("Cookie", "pvp_s=attacker; pvp_s="+cookie)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("got %d", w.Code)
	}
}

func TestLogout(t *testing.T) {
	s, _, _ := newTestServer(t)
	cookie, csrf := login(t, s)
	if w := do(s, "DELETE", "/api/v1/session", "", withCookie(cookie), withHeader("Origin", testOrigin)); w.Code != 403 {
		t.Errorf("logout without CSRF: %d", w.Code)
	}
	if w := do(s, "DELETE", "/api/v1/session", "", authed(cookie, csrf)...); w.Code != 200 {
		t.Fatalf("logout: %d", w.Code)
	}
	if w := do(s, "GET", "/api/v1/status", "", withCookie(cookie)); w.Code != 401 {
		t.Errorf("after logout: %d", w.Code)
	}
}

// ---------------------------------------------------------------------------
// CSRF / Origin / Sec-Fetch-Site

func TestNonGETRequiresCSRFOriginAndFetchSite(t *testing.T) {
	s, b, _ := newTestServer(t)
	cookie, csrf := login(t, s)
	path := "/api/v1/client/disconnect"
	cases := []struct {
		name string
		opts []reqOpt
		want int
	}{
		{"no csrf", []reqOpt{withCookie(cookie), withHeader("Origin", testOrigin)}, 403},
		{"wrong csrf", []reqOpt{withCookie(cookie), withHeader("Origin", testOrigin), withHeader(csrfHeader, "AAAA")}, 403},
		{"csrf of another length", []reqOpt{withCookie(cookie), withHeader("Origin", testOrigin), withHeader(csrfHeader, csrf+"x")}, 403},
		{"no origin", []reqOpt{withCookie(cookie), withHeader(csrfHeader, csrf)}, 403},
		{"evil origin", []reqOpt{withCookie(cookie), withHeader("Origin", "http://evil.example"), withHeader(csrfHeader, csrf)}, 403},
		{"localhost origin", []reqOpt{withCookie(cookie), withHeader("Origin", "http://localhost:47771"), withHeader(csrfHeader, csrf)}, 403},
		{"other port origin", []reqOpt{withCookie(cookie), withHeader("Origin", "http://127.0.0.1:8080"), withHeader(csrfHeader, csrf)}, 403},
		{"https origin", []reqOpt{withCookie(cookie), withHeader("Origin", "https://127.0.0.1:47771"), withHeader(csrfHeader, csrf)}, 403},
		{"null origin", []reqOpt{withCookie(cookie), withHeader("Origin", "null"), withHeader(csrfHeader, csrf)}, 403},
		{"cross-site", append(authed(cookie, csrf), withHeader("Sec-Fetch-Site", "cross-site")), 403},
		{"same-site", append(authed(cookie, csrf), withHeader("Sec-Fetch-Site", "same-site")), 403},
		{"fetch-site none", append(authed(cookie, csrf), withHeader("Sec-Fetch-Site", "none")), 200},
		{"no fetch-site header", []reqOpt{withCookie(cookie), withHeader("Origin", testOrigin), withHeader(csrfHeader, csrf)}, 200},
		{"all good", authed(cookie, csrf), 200},
	}
	for _, c := range cases {
		before := b.callCount()
		w := do(s, "POST", path, "{}", c.opts...)
		if w.Code != c.want {
			t.Errorf("%s: %d, want %d (%s)", c.name, w.Code, c.want, w.Body)
		}
		if c.want == 403 && b.callCount() != before {
			t.Errorf("%s: backend called on a refused request", c.name)
		}
	}
	// Two Origin headers are refused.
	r := httptest.NewRequest("POST", "http://"+testHost+path, strings.NewReader("{}"))
	r.Header.Set("Content-Type", "application/json")
	r.AddCookie(&http.Cookie{Name: cookieName, Value: cookie})
	r.Header.Add("Origin", testOrigin)
	r.Header.Add("Origin", testOrigin)
	r.Header.Set(csrfHeader, csrf)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Errorf("duplicate Origin: %d", w.Code)
	}
	// Every non-GET method is covered.
	for _, m := range []string{"PUT", "PATCH", "DELETE"} {
		if w := do(s, m, "/api/v1/settings", "{}", withCookie(cookie), withHeader("Origin", testOrigin)); w.Code != 403 {
			t.Errorf("%s without CSRF: %d", m, w.Code)
		}
	}
	// A cross-site GET is refused too.
	if w := do(s, "GET", "/api/v1/status", "", withCookie(cookie), withHeader("Sec-Fetch-Site", "cross-site")); w.Code != 403 {
		t.Errorf("cross-site GET: %d", w.Code)
	}
}

// ---------------------------------------------------------------------------
// bodies

func TestBodyLimits(t *testing.T) {
	s, b, _ := newTestServer(t)
	cookie, csrf := login(t, s)
	path := "/api/v1/keyring"
	big := `{"key_text":"` + strings.Repeat("A", maxBody) + `"}`
	if w := do(s, "POST", path, big, authed(cookie, csrf)...); w.Code != 413 {
		t.Errorf("oversized body: %d, want 413", w.Code)
	}
	// Same, without a Content-Length (chunked).
	r := httptest.NewRequest("POST", "http://"+testHost+path, io.MultiReader(strings.NewReader(big)))
	r.ContentLength = -1
	r.Header.Set("Content-Type", "application/json")
	for _, o := range authed(cookie, csrf) {
		o(r)
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != 413 {
		t.Errorf("oversized chunked body: %d, want 413", w.Code)
	}
	// Exactly 64 KiB is accepted.
	exact := `{"k":"` + strings.Repeat("A", maxBody-8) + `"}`
	if len(exact) != maxBody {
		t.Fatal(len(exact))
	}
	if w := do(s, "POST", path, exact, authed(cookie, csrf)...); w.Code != 200 {
		t.Errorf("64 KiB body: %d, want 200", w.Code)
	}
	for _, ct := range []string{"text/plain", "application/x-www-form-urlencoded", "multipart/form-data; boundary=x", ""} {
		opts := append(authed(cookie, csrf), withHeader("Content-Type", ct))
		if w := do(s, "POST", path, `{"key_text":"x"}`, opts...); w.Code != 415 {
			t.Errorf("Content-Type %q: %d, want 415", ct, w.Code)
		}
	}
	opts := append(authed(cookie, csrf), withHeader("Content-Type", "application/json; charset=utf-8"))
	if w := do(s, "POST", path, `{"key_text":"x"}`, opts...); w.Code != 200 {
		t.Errorf("json with charset: %d", w.Code)
	}
	before := b.callCount()
	for _, bad := range []string{`not json`, `[1,2]`, `"str"`, `{"a":`, `null`} {
		if w := do(s, "POST", path, bad, authed(cookie, csrf)...); w.Code != 400 {
			t.Errorf("body %q: %d, want 400", bad, w.Code)
		}
	}
	if b.callCount() != before {
		t.Error("backend called with an invalid body")
	}
}

// ---------------------------------------------------------------------------
// headers

func TestSecurityHeadersEverywhere(t *testing.T) {
	s, b, _ := newTestServer(t)
	cookie, csrf := login(t, s)
	b.results[api.KeyringReveal] = []byte(`{"key_text":"PVP1-AAAAA"}`)
	reqs := []struct {
		method, path, body string
		opts               []reqOpt
	}{
		{"GET", "/", "", nil},
		{"GET", "/", "", []reqOpt{withCookie(cookie)}},
		{"GET", "/login.html", "", nil},
		{"GET", "/app.js", "", nil},
		{"GET", "/app.css", "", nil},
		{"GET", "/icons.svg", "", nil},
		{"GET", "/nope", "", nil},
		{"POST", "/", "", nil},
		{"GET", "/api/v1/status", "", nil},
		{"GET", "/api/v1/status", "", []reqOpt{withCookie(cookie)}},
		{"GET", "/api/v1/nope", "", []reqOpt{withCookie(cookie)}},
		{"POST", "/api/v1/client/disconnect", "{}", []reqOpt{withCookie(cookie)}},
		{"POST", "/api/v1/client/disconnect", "{}", authed(cookie, csrf)},
		{"GET", "/api/v1/keyring/k1/qr.png", "", []reqOpt{withCookie(cookie)}},
		{"OPTIONS", "/api/v1/status", "", []reqOpt{withHeader("Origin", "http://evil.example"), withHeader("Access-Control-Request-Method", "POST")}},
		{"OPTIONS", "/api/v1/status", "", []reqOpt{withCookie(cookie), withHeader("Origin", testOrigin)}},
		{"GET", "/api/v1/status", "", []reqOpt{withHeader("Origin", "http://evil.example"), withCookie(cookie)}},
		{"GET", "/", "", []reqOpt{withHost("evil.example")}},
	}
	for _, r := range reqs {
		w := do(s, r.method, r.path, r.body, r.opts...)
		checkSecurityHeaders(t, r.method+" "+r.path, w.Header())
		if strings.HasPrefix(r.path, "/api/") && w.Header().Get("Cache-Control") != "no-store" {
			t.Errorf("%s %s: Cache-Control %q", r.method, r.path, w.Header().Get("Cache-Control"))
		}
	}
	// Static types and nosniff-relevant content types.
	for p, ct := range map[string]string{"/app.js": "text/javascript", "/app.css": "text/css", "/icons.svg": "image/svg+xml", "/login.html": "text/html"} {
		if got := do(s, "GET", p, "").Header().Get("Content-Type"); !strings.HasPrefix(got, ct) {
			t.Errorf("%s: Content-Type %q", p, got)
		}
	}
}

func TestEmbeddedUIHasNoInlineCode(t *testing.T) {
	for _, name := range []string{"/index.html", "/login.html"} {
		html := string(static[name].data)
		for _, bad := range []string{"<script>", "style=", "onclick", "onload", "javascript:"} {
			if strings.Contains(html, bad) {
				t.Errorf("%s contains %q (CSP forbids inline code)", name, bad)
			}
		}
		if !strings.Contains(html, `<script src="/app.js" defer></script>`) {
			t.Errorf("%s does not load /app.js", name)
		}
	}
	js := string(static["/app.js"].data)
	for _, bad := range []string{".innerHTML", ".outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function"} {
		if strings.Contains(js, bad) {
			t.Errorf("app.js uses %q", bad)
		}
	}
}

// ---------------------------------------------------------------------------
// routes

func TestRouteTableMapping(t *testing.T) {
	s, b, _ := newTestServer(t)
	cookie, csrf := login(t, s)
	cases := []struct {
		method, path, body string
		core               string
		args               map[string]any
	}{
		{"GET", "/status", "", api.StatusGet, map[string]any{}},
		{"GET", "/keyring", "", api.KeyringList, map[string]any{}},
		{"POST", "/keyring", `{"key_text":"PVP1-X","label":"Home"}`, api.KeyringAdd, map[string]any{"key_text": "PVP1-X", "label": "Home"}},
		{"POST", "/keyring/create", `{"label":"Mine"}`, api.KeyringCreate, map[string]any{"label": "Mine"}},
		{"POST", "/keyring/create", "", api.KeyringCreate, map[string]any{}},
		{"PATCH", "/keyring/k-1", `{"label":"New"}`, api.KeyringRename, map[string]any{"id": "k-1", "label": "New"}},
		{"DELETE", "/keyring/k-1", "", api.KeyringRemove, map[string]any{"id": "k-1"}},
		{"POST", "/keyring/k-1/reveal", "", api.KeyringReveal, map[string]any{"id": "k-1"}},
		{"POST", "/gateway/network", `{"keyring_id":"k-2"}`, api.GatewaySetNetwork, map[string]any{"keyring_id": "k-2"}},
		{"POST", "/gateway/reset-key", "", api.GatewayResetKey, map[string]any{}},
		{"POST", "/gateway/enable", "", api.GatewayEnable, map[string]any{}},
		{"POST", "/gateway/disable", "", api.GatewayDisable, map[string]any{}},
		{"GET", "/gateways", "", api.GatewaysList, map[string]any{}},
		{"POST", "/gateways/gw_PUB-key/unlock", `{"key_text":"PVP1-Y"}`, api.GatewaysUnlock, map[string]any{"gateway_id": "gw_PUB-key", "key_text": "PVP1-Y"}},
		{"POST", "/gateways/manual", `{"label":"L","host":"h.example","ctrl_port":51821}`, api.GatewaysManualAdd, map[string]any{"label": "L", "host": "h.example", "ctrl_port": float64(51821)}},
		{"DELETE", "/gateways/manual/m-1", "", api.GatewaysManualRm, map[string]any{"id": "m-1"}},
		{"GET", "/gateways/gwid/info", "", api.GatewaysInfo, map[string]any{"gateway_id": "gwid"}},
		{"GET", "/gateways/manual/info", "", api.GatewaysInfo, map[string]any{"gateway_id": "manual"}},
		{"POST", "/client/connect", `{"gateway_id":"gwid"}`, api.ClientConnect, map[string]any{"gateway_id": "gwid"}},
		{"POST", "/client/disconnect", "", api.ClientDisconnect, map[string]any{}},
		{"POST", "/client/selftest", "", api.ClientSelftest, map[string]any{}},
		{"GET", "/settings", "", api.SettingsGet, map[string]any{}},
		{"PUT", "/settings", `{"ui":{"theme":"dark"}}`, api.SettingsSet, map[string]any{"ui": map[string]any{"theme": "dark"}}},
		{"POST", "/firewall/add", "", api.FirewallAdd, map[string]any{}},
		{"GET", "/log", "", api.LogGet, map[string]any{}},
		{"POST", "/quit", "", api.AppQuit, map[string]any{}},
		// Path parameters override body fields of the same name.
		{"PATCH", "/keyring/real", `{"id":"evil","label":"x"}`, api.KeyringRename, map[string]any{"id": "real", "label": "x"}},
		{"POST", "/gateways/real/unlock", `{"gateway_id":"evil","key_text":"k"}`, api.GatewaysUnlock, map[string]any{"gateway_id": "real", "key_text": "k"}},
		// Escaped path values are decoded and JSON-encoded safely.
		{"DELETE", "/keyring/a%22b", "", api.KeyringRemove, map[string]any{"id": `a"b`}},
	}
	for _, c := range cases {
		var opts []reqOpt
		if isSafeMethod(c.method) {
			opts = []reqOpt{withCookie(cookie)}
		} else {
			opts = authed(cookie, csrf)
		}
		before := b.callCount()
		w := do(s, c.method, "/api/v1"+c.path, c.body, opts...)
		if w.Code != 200 {
			t.Errorf("%s %s: %d %s", c.method, c.path, w.Code, w.Body)
			continue
		}
		if b.callCount() != before+1 {
			t.Errorf("%s %s: backend called %d times", c.method, c.path, b.callCount()-before)
			continue
		}
		got := b.lastCall(t)
		if got.method != c.core {
			t.Errorf("%s %s → %q, want %q", c.method, c.path, got.method, c.core)
		}
		gj, _ := json.Marshal(got.args)
		wj, _ := json.Marshal(c.args)
		if !bytes.Equal(gj, wj) {
			t.Errorf("%s %s args %s, want %s", c.method, c.path, gj, wj)
		}
		if ct := w.Header().Get("Content-Type"); ct != "application/json; charset=utf-8" {
			t.Errorf("%s %s: Content-Type %q", c.method, c.path, ct)
		}
	}
	// Every §14.1 core method is reachable over HTTP.
	seen := map[string]bool{}
	for _, c := range cases {
		seen[c.core] = true
	}
	for _, rt := range routeTable {
		if !seen[rt.core] {
			t.Errorf("route %s %s not covered", rt.method, rt.path)
		}
	}
	// Wrong method / unknown path → JSON 404, backend untouched.
	before := b.callCount()
	for _, r := range [][2]string{{"GET", "/client/connect"}, {"DELETE", "/status"}, {"GET", "/nope"}} {
		opts := authed(cookie, csrf)
		if w := do(s, r[0], "/api/v1"+r[1], "", opts...); w.Code != 404 {
			t.Errorf("%s %s: %d, want 404", r[0], r[1], w.Code)
		}
	}
	if b.callCount() != before {
		t.Error("backend called for an unknown route")
	}
}

func TestErrorStatusMapping(t *testing.T) {
	s, b, _ := newTestServer(t)
	cookie, csrf := login(t, s)
	b.errs[api.ClientConnect] = &api.Error{Code: api.CodeLocked, Message: "enter the key", HTTP: 409}
	b.errs[api.GatewaysUnlock] = &api.Error{Code: api.CodeUnreachable, Message: "no answer", HTTP: 504}
	b.errs[api.KeyringAdd] = &api.Error{Code: api.CodeKeyFormat, Message: "bad key"} // HTTP 0 → 400
	cases := []struct {
		path, code string
		status     int
	}{
		{"/client/connect", "locked", 409},
		{"/gateways/x/unlock", "unreachable", 504},
		{"/keyring", "key_format", 400},
	}
	for _, c := range cases {
		w := do(s, "POST", "/api/v1"+c.path, `{"a":1}`, authed(cookie, csrf)...)
		var e map[string]string
		json.Unmarshal(w.Body.Bytes(), &e)
		if w.Code != c.status || e["code"] != c.code || e["message"] == "" {
			t.Errorf("%s: %d %s", c.path, w.Code, w.Body)
		}
	}
}

func TestQRPNG(t *testing.T) {
	s, b, _ := newTestServer(t)
	cookie, _ := login(t, s)
	b.results[api.KeyringReveal] = []byte(`{"key_text":"PVP1-K7Q2M-ZB3XW-AAAAA-BBBBB-CCCCC-DDDDD-EEEEE-FFFFF-GGGGG-HHHHH-IIIII"}`)
	w := do(s, "GET", "/api/v1/keyring/entry-1/qr.png", "", withCookie(cookie), withHeader("Sec-Fetch-Site", "same-origin"))
	if w.Code != 200 {
		t.Fatalf("qr: %d %s", w.Code, w.Body)
	}
	if ct := w.Header().Get("Content-Type"); ct != "image/png" {
		t.Errorf("Content-Type %q", ct)
	}
	if cc := w.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control %q", cc)
	}
	img, err := png.Decode(bytes.NewReader(w.Body.Bytes()))
	if err != nil || img.Bounds().Dx() < 100 {
		t.Fatalf("not a PNG: %v", err)
	}
	c := b.lastCall(t)
	if c.method != api.KeyringReveal || c.args["id"] != "entry-1" || len(c.args) != 1 {
		t.Errorf("backend call %+v", c)
	}
	b.errs[api.KeyringReveal] = api.NotFound("keyring entry")
	if w := do(s, "GET", "/api/v1/keyring/zzz/qr.png", "", withCookie(cookie)); w.Code != 404 {
		t.Errorf("unknown entry: %d", w.Code)
	}
	if w := do(s, "GET", "/api/v1/keyring/entry-1/qr.png", ""); w.Code != 401 {
		t.Errorf("qr without session: %d", w.Code)
	}
}

// ---------------------------------------------------------------------------
// listening

func TestCandidates(t *testing.T) {
	s := New(newFake(), Options{})
	got := s.candidates()
	want := []int{47771, 47772, 47773, 47774, 47775, 47776, 47777, 47778, 47779, 47780}
	if len(got) != len(want) {
		t.Fatalf("%v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("%v", got)
		}
	}
	s = New(newFake(), Options{Port: 47775})
	if got := s.candidates(); got[0] != 47775 || len(got) != 9 {
		t.Errorf("preferred 47775: %v", got)
	}
	s = New(newFake(), Options{Port: 80})
	if got := s.candidates(); got[0] != 47771 {
		t.Errorf("privileged port must be ignored: %v", got)
	}
}

func TestListenFallsBackWhenBusy(t *testing.T) {
	busy, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	free, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	freePort := free.Addr().(*net.TCPAddr).Port
	free.Close()
	s := New(newFake(), Options{ports: []int{busy.Addr().(*net.TCPAddr).Port, freePort}})
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if s.Port() != freePort {
		t.Fatalf("port %d, want %d", s.Port(), freePort)
	}
	if !strings.HasPrefix(s.MintLoginURL(), "http://127.0.0.1:"+itoa(freePort)+"/#t=") {
		t.Error("login URL does not use the bound port")
	}
	if s.srv.ReadHeaderTimeout != 5*time.Second || s.srv.IdleTimeout != 60*time.Second || s.srv.MaxHeaderBytes != 16<<10 {
		t.Error("server timeouts")
	}
}

func itoa(i int) string { return strconv.Itoa(i) }

// ---------------------------------------------------------------------------
// SSE over a real connection

func startLive(t *testing.T, setup ...func(*Server)) (*Server, *fakeBackend, string) {
	t.Helper()
	b := newFake()
	s := New(b, Options{ports: []int{0}})
	s.heartbeat = 50 * time.Millisecond
	for _, f := range setup {
		f(s)
	}
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s, b, "http://" + s.host
}

func liveLogin(t *testing.T, s *Server, base string) string {
	t.Helper()
	tok := strings.TrimPrefix(s.MintLoginURL(), base+"/#t=")
	req, _ := http.NewRequest("POST", base+"/api/v1/session", strings.NewReader(`{"token":"`+tok+`"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", base)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	for _, c := range resp.Cookies() {
		if c.Name == cookieName {
			return c.Value
		}
	}
	t.Fatalf("no cookie (%d)", resp.StatusCode)
	return ""
}

func openStream(t *testing.T, base, cookie string) (*http.Response, *bufio.Reader) {
	t.Helper()
	req, _ := http.NewRequest("GET", base+"/api/v1/events", nil)
	req.AddCookie(&http.Cookie{Name: cookieName, Value: cookie})
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp, bufio.NewReader(resp.Body)
}

// readUntil reads lines until one has the prefix, or fails after 3 s.
func readUntil(t *testing.T, rd *bufio.Reader, prefix string) string {
	t.Helper()
	ch := make(chan string, 1)
	go func() {
		for {
			line, err := rd.ReadString('\n')
			if err != nil {
				ch <- "EOF:" + err.Error()
				return
			}
			if strings.HasPrefix(line, prefix) {
				ch <- strings.TrimRight(line, "\n")
				return
			}
		}
	}()
	select {
	case l := <-ch:
		return l
	case <-time.After(3 * time.Second):
		t.Fatalf("timeout waiting for %q", prefix)
		return ""
	}
}

func TestSSE(t *testing.T) {
	s, b, base := startLive(t)
	cookie := liveLogin(t, s, base)

	resp, rd := openStream(t, base, cookie)
	defer resp.Body.Close()
	if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "text/event-stream" {
		t.Fatalf("events: %d %q", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	checkSecurityHeaders(t, "sse", resp.Header)
	if resp.Header.Get("Cache-Control") != "no-store" {
		t.Error("SSE Cache-Control")
	}
	readUntil(t, rd, ": connected")
	deadline := time.Now().Add(2 * time.Second)
	for b.subCount() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	// Pretty-printed JSON is compacted to a single data line.
	b.emit("{\n  \"type\": \"log\",\n  \"line\": \"hello\"\n}")
	if got := readUntil(t, rd, "data: "); got != `data: {"type":"log","line":"hello"}` {
		t.Errorf("event line %q", got)
	}
	b.emit("not json") // dropped
	b.emit(`{"type":"status","status":{}}`)
	if got := readUntil(t, rd, "data: "); got != `data: {"type":"status","status":{}}` {
		t.Errorf("event line %q", got)
	}
	readUntil(t, rd, ": heartbeat")

	// One stream per session: a second stream ends the first.
	resp2, rd2 := openStream(t, base, cookie)
	defer resp2.Body.Close()
	readUntil(t, rd2, ": connected")
	if got := readUntil(t, rd, "EOF"); !strings.HasPrefix(got, "EOF") {
		t.Errorf("first stream still open: %q", got)
	}

	// No cookie → 401, wrong Host → 421.
	r, _ := http.NewRequest("GET", base+"/api/v1/events", nil)
	if resp, err := http.DefaultClient.Do(r); err != nil || resp.StatusCode != 401 {
		t.Errorf("SSE without cookie: %v %v", err, resp)
	} else {
		resp.Body.Close()
	}
	r, _ = http.NewRequest("GET", base+"/api/v1/events", nil)
	r.Host = "localhost:" + itoa(s.Port())
	r.AddCookie(&http.Cookie{Name: cookieName, Value: cookie})
	if resp, err := http.DefaultClient.Do(r); err != nil || resp.StatusCode != 421 {
		t.Errorf("SSE with wrong Host: %v %v", err, resp)
	} else {
		resp.Body.Close()
	}

	// Server Close ends the stream promptly.
	go s.Close()
	if got := readUntil(t, rd2, "EOF"); !strings.HasPrefix(got, "EOF") {
		t.Errorf("stream not closed by Server.Close: %q", got)
	}
}

func TestSSEEndsWhenSessionExpires(t *testing.T) {
	clk := &clock{t: time.Now()}
	s, _, base := startLive(t, func(s *Server) { s.now = clk.now })
	cookie := liveLogin(t, s, base)
	resp, rd := openStream(t, base, cookie)
	defer resp.Body.Close()
	readUntil(t, rd, ": connected")
	clk.add(13 * time.Hour)
	if got := readUntil(t, rd, "EOF"); !strings.HasPrefix(got, "EOF") {
		t.Errorf("stream should end on idle expiry: %q", got)
	}
}
