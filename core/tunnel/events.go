package tunnel

import (
	"regexp"
	"sync"
	"time"
)

// Event is an asynchronous tunnel state change (helper "ev" line, §13.5).
type Event struct {
	State   string // "up", "down" or "error"
	Message string // human readable; never contains peer data (§12.1)
}

// Notifier is optionally implemented by Tunnels that report asynchronous
// state changes: a failed endpoint-route update after a network change, or
// (desktop/helper.Client) the privileged helper exiting. fn must not block.
type Notifier interface {
	SetNotify(fn func(Event))
}

// EndpointRouteReporter is optionally implemented by Tunnels that keep an
// endpoint exclusion route (Windows, macOS). It reports whether the route
// is in place or not needed (helper status "endpoint_ok").
type EndpointRouteReporter interface {
	EndpointRouteOK() bool
}

var (
	rePeerTag = regexp.MustCompile(`peer\([^)]*\)`)
	reIPv4    = regexp.MustCompile(`\d{1,3}(?:\.\d{1,3}){3}(?::\d{1,5})?`)
	reIPv6    = regexp.MustCompile(`(?i)\[?(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}(?:%[0-9a-z_.\-]+)?\]?(?::\d{1,5})?`)
	reB64Key  = regexp.MustCompile(`[A-Za-z0-9+/]{43}=`)
	reHexKey  = regexp.MustCompile(`(?i)[0-9a-f]{64}`)
)

// Redact removes anything that looks like a peer key, a peer tag, or an
// IPv4/IPv6 address (with optional port) from s. It is applied to every
// wireguard-go log line and to command error output before it can reach the
// event log or the helper pipe (§12.1). It over-redacts by design.
func Redact(s string) string {
	s = rePeerTag.ReplaceAllString(s, "peer")
	s = reB64Key.ReplaceAllString(s, "<key>")
	s = reHexKey.ReplaceAllString(s, "<key>")
	s = reIPv4.ReplaceAllString(s, "<addr>")
	s = reIPv6.ReplaceAllString(s, "<addr>")
	return s
}

// debouncer runs fn once, d after the last kick. Safe for concurrent use.
type debouncer struct {
	mu      sync.Mutex
	d       time.Duration
	fn      func()
	t       *time.Timer
	stopped bool
}

func newDebouncer(d time.Duration, fn func()) *debouncer {
	return &debouncer{d: d, fn: fn}
}

func (b *debouncer) kick() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.stopped {
		return
	}
	if b.t == nil {
		b.t = time.AfterFunc(b.d, b.fn)
		return
	}
	b.t.Reset(b.d)
}

// stop prevents future runs. A run already in progress is not waited for.
func (b *debouncer) stop() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.stopped = true
	if b.t != nil {
		b.t.Stop()
	}
}
