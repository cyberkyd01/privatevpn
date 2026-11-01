// Package eventlog is the only logging facility in Private VPN Pro.
//
// It is an in-memory ring buffer; nothing is ever written to disk or to a
// system log (ARCHITECTURE §12). Callers must never log client addresses,
// endpoints, keys, lease tokens, DNS names or forwarded-flow destinations.
package eventlog

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

// DefaultCapacity is the number of lines kept by Default.
const DefaultCapacity = 1000

// maxLineLen caps a single line so a hostile string cannot bloat memory.
const maxLineLen = 512

// Log is a fixed-size ring buffer of log lines with live subscribers.
type Log struct {
	mu    sync.Mutex
	lines []string
	next  int
	full  bool
	subID int
	subs  map[int]func(string)
	nowFn func() time.Time
}

// Default is the process-wide log.
var Default = New(DefaultCapacity)

// New returns an empty log holding at most capacity lines.
func New(capacity int) *Log {
	if capacity < 1 {
		capacity = 1
	}
	return &Log{lines: make([]string, capacity), subs: map[int]func(string){}, nowFn: time.Now}
}

// Printf records "<RFC3339 UTC> <component>: <message>".
func (l *Log) Printf(component, format string, args ...any) {
	msg := sanitize(fmt.Sprintf(format, args...))
	line := l.nowFn().UTC().Format(time.RFC3339) + " " + component + ": " + msg
	if len(line) > maxLineLen {
		line = line[:maxLineLen] + "…"
	}
	l.mu.Lock()
	l.lines[l.next] = line
	l.next = (l.next + 1) % len(l.lines)
	if l.next == 0 {
		l.full = true
	}
	subs := make([]func(string), 0, len(l.subs))
	for _, fn := range l.subs {
		subs = append(subs, fn)
	}
	l.mu.Unlock()
	for _, fn := range subs {
		fn(line)
	}
}

// Lines returns the buffered lines, oldest first.
func (l *Log) Lines() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []string
	if l.full {
		out = append(out, l.lines[l.next:]...)
	}
	out = append(out, l.lines[:l.next]...)
	return out
}

// Subscribe calls fn (synchronously, from the logging goroutine) for every
// new line until cancel is called. fn must not block.
func (l *Log) Subscribe(fn func(line string)) (cancel func()) {
	l.mu.Lock()
	l.subID++
	id := l.subID
	l.subs[id] = fn
	l.mu.Unlock()
	return func() {
		l.mu.Lock()
		delete(l.subs, id)
		l.mu.Unlock()
	}
}

// sanitize removes control characters (incl. newlines) so one call is one line.
func sanitize(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) {
			return ' '
		}
		return r
	}, s)
}

// Redacted is embedded (or returned from String) by types that hold client
// data, so that an accidental %v prints nothing identifying.
type Redacted struct{}

func (Redacted) String() string { return "<redacted>" }
