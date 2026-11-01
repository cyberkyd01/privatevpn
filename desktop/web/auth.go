//go:build !android

package web

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"net/http"
	"sync"
	"time"
)

// authState holds login tokens and sessions. Everything is in memory and
// dies with the process ("all dropped on restart", §13.4). Maps are keyed by
// SHA-256 of the secret so lookups do not compare secrets directly.
type authState struct {
	mu       sync.Mutex
	tokens   map[[32]byte]time.Time // token hash → expiry
	sessions map[[32]byte]*session  // cookie hash → session
	bucket   tokenBucket            // /api/v1/session limiter
}

type session struct {
	csrf     string
	lastUsed time.Time
	stream   chan struct{} // closed to end this session's SSE stream; nil if none
}

func (a *authState) init() {
	a.tokens = map[[32]byte]time.Time{}
	a.sessions = map[[32]byte]*session{}
	a.bucket = tokenBucket{rate: sessionRate, burst: sessionRate}
}

// randSecret returns 32 random bytes, base64url without padding.
func randSecret() string {
	var b [32]byte
	rand.Read(b[:]) // never fails (crypto/rand, Go ≥ 1.24)
	return base64.RawURLEncoding.EncodeToString(b[:])
}

func hashSecret(s string) [32]byte { return sha256.Sum256([]byte(s)) }

// purgeLocked drops expired tokens and idle sessions.
func (a *authState) purgeLocked(now time.Time) {
	for k, exp := range a.tokens {
		if !now.Before(exp) {
			delete(a.tokens, k)
		}
	}
	for k, s := range a.sessions {
		if now.Sub(s.lastUsed) >= sessionIdle {
			a.dropSessionLocked(k, s)
		}
	}
}

func (a *authState) dropSessionLocked(k [32]byte, s *session) {
	if s.stream != nil {
		close(s.stream)
		s.stream = nil
	}
	delete(a.sessions, k)
}

// mint creates a login token valid for 60 s. At most 8 are outstanding;
// minting a ninth evicts the one closest to expiry.
func (a *authState) mint(now time.Time) string {
	tok := randSecret()
	a.mu.Lock()
	defer a.mu.Unlock()
	a.purgeLocked(now)
	for len(a.tokens) >= maxTokens {
		var oldest [32]byte
		var oldestExp time.Time
		first := true
		for k, exp := range a.tokens {
			if first || exp.Before(oldestExp) {
				oldest, oldestExp, first = k, exp, false
			}
		}
		delete(a.tokens, oldest)
	}
	a.tokens[hashSecret(tok)] = now.Add(tokenTTL)
	return tok
}

// consume redeems a token: it is deleted on first sight, valid or not
// (single use), and must not be expired.
func (a *authState) consume(tok string, now time.Time) bool {
	if len(tok) == 0 || len(tok) > 128 {
		return false
	}
	k := hashSecret(tok)
	a.mu.Lock()
	defer a.mu.Unlock()
	exp, ok := a.tokens[k]
	delete(a.tokens, k)
	return ok && now.Before(exp)
}

// newSession creates a session (evicting the least recently used one when
// four exist) and returns the cookie value and the CSRF token.
func (a *authState) newSession(now time.Time) (cookie, csrf string) {
	cookie, csrf = randSecret(), randSecret()
	a.mu.Lock()
	defer a.mu.Unlock()
	a.purgeLocked(now)
	for len(a.sessions) >= maxSessions {
		var lruKey [32]byte
		var lru *session
		for k, s := range a.sessions {
			if lru == nil || s.lastUsed.Before(lru.lastUsed) {
				lruKey, lru = k, s
			}
		}
		a.dropSessionLocked(lruKey, lru)
	}
	a.sessions[hashSecret(cookie)] = &session{csrf: csrf, lastUsed: now}
	return cookie, csrf
}

// sessionRef identifies an authenticated request's session.
type sessionRef struct {
	key  [32]byte
	csrf string
}

// lookup validates the pvp_s cookie(s) and refreshes the idle timer. Every
// cookie named pvp_s is tried, so a cookie "tossed" by another 127.0.0.1
// origin cannot shadow the real one.
func (a *authState) lookup(r *http.Request, now time.Time) (sessionRef, bool) {
	cookies := r.CookiesNamed(cookieName)
	if len(cookies) == 0 || len(cookies) > 8 {
		return sessionRef{}, false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, c := range cookies {
		if len(c.Value) == 0 || len(c.Value) > 128 {
			continue
		}
		k := hashSecret(c.Value)
		s, ok := a.sessions[k]
		if !ok {
			continue
		}
		if now.Sub(s.lastUsed) >= sessionIdle {
			a.dropSessionLocked(k, s)
			continue
		}
		s.lastUsed = now
		return sessionRef{key: k, csrf: s.csrf}, true
	}
	return sessionRef{}, false
}

// touch refreshes a session's idle timer; false if it no longer exists.
func (a *authState) touch(k [32]byte, now time.Time) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	s, ok := a.sessions[k]
	if !ok {
		return false
	}
	if now.Sub(s.lastUsed) >= sessionIdle {
		a.dropSessionLocked(k, s)
		return false
	}
	s.lastUsed = now
	return true
}

// drop deletes a session (logout).
func (a *authState) drop(k [32]byte) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if s, ok := a.sessions[k]; ok {
		a.dropSessionLocked(k, s)
	}
}

// attachStream registers the session's SSE stream, ending any previous one
// (one stream per session). The returned channel is closed when the stream
// must stop. ok is false when the session is gone.
func (a *authState) attachStream(k [32]byte) (stop chan struct{}, ok bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	s, ok := a.sessions[k]
	if !ok {
		return nil, false
	}
	if s.stream != nil {
		close(s.stream)
	}
	s.stream = make(chan struct{})
	return s.stream, true
}

// detachStream clears the stream if it is still the current one.
func (a *authState) detachStream(k [32]byte, stop chan struct{}) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if s, ok := a.sessions[k]; ok && s.stream == stop {
		close(s.stream)
		s.stream = nil
	}
}

// csrfOK: exactly one X-PVP-CSRF header equal to the session's token.
func csrfOK(r *http.Request, want string) bool {
	v := r.Header.Values(csrfHeader)
	return len(v) == 1 && want != "" && subtle.ConstantTimeCompare([]byte(v[0]), []byte(want)) == 1
}

// tokenBucket is a minimal rate limiter (rate tokens/s, burst capacity).
type tokenBucket struct {
	mu     sync.Mutex
	rate   float64
	burst  float64
	tokens float64
	last   time.Time
}

func (b *tokenBucket) allow(now time.Time) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.last.IsZero() {
		b.tokens = b.burst
	} else if el := now.Sub(b.last).Seconds(); el > 0 {
		b.tokens += el * b.rate
		if b.tokens > b.burst {
			b.tokens = b.burst
		}
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}
