//go:build !android

package web

import (
	"bytes"
	"encoding/json"
	"net/http"
	"sync/atomic"
	"time"
)

// resyncEvent tells the page that events were dropped (slow consumer) and it
// should refetch its state. It is web-only, not part of §14.3.
var resyncEvent = []byte(`{"type":"resync"}`)

// handleEvents streams engine events as SSE (`data: <event JSON>`), one
// stream per session (a new stream ends the previous one), with a comment
// heartbeat every 20 s. Authentication (cookie, Host, Sec-Fetch-Site) has
// already been done by serveAPI; EventSource cannot send headers, and
// SameSite=Strict keeps the cookie off cross-site requests.
func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	ri := info(r)
	stop, ok := s.auth.attachStream(ri.sess.key)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "unauthorized", "not signed in")
		return
	}
	defer s.auth.detachStream(ri.sess.key, stop)

	events := make(chan []byte, 128)
	var dropped atomic.Bool
	cancel := s.b.Subscribe(func(ev []byte) {
		// Called from engine goroutines: never block.
		select {
		case events <- ev:
		default:
			dropped.Store(true)
		}
	})
	defer cancel()

	rc := http.NewResponseController(w)
	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	write := func(p ...[]byte) bool {
		rc.SetWriteDeadline(time.Now().Add(10 * time.Second))
		for _, b := range p {
			if _, err := w.Write(b); err != nil {
				return false
			}
		}
		return rc.Flush() == nil
	}
	if !write([]byte("retry: 3000\n: connected\n\n")) {
		return
	}

	tick := time.NewTicker(s.heartbeat)
	defer tick.Stop()
	var buf bytes.Buffer
	for {
		select {
		case <-r.Context().Done():
			return
		case <-stop:
			return
		case <-s.done:
			return
		case ev := <-events:
			if dropped.Swap(false) && !write([]byte("data: "), resyncEvent, []byte("\n\n")) {
				return
			}
			buf.Reset()
			// Compact guarantees a single line (a newline would end the
			// SSE field); invalid JSON is not forwarded.
			if json.Compact(&buf, ev) != nil {
				continue
			}
			if !write([]byte("data: "), buf.Bytes(), []byte("\n\n")) {
				return
			}
		case <-tick.C:
			// An open stream counts as activity; an expired or evicted
			// session ends the stream.
			if !s.auth.touch(ri.sess.key, s.now()) {
				return
			}
			if dropped.Swap(false) && !write([]byte("data: "), resyncEvent, []byte("\n\n")) {
				return
			}
			if !write([]byte(": heartbeat\n\n")) {
				return
			}
		}
	}
}
