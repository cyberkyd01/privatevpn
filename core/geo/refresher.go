package geo

import (
	"context"
	"errors"
	"math/rand/v2"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/cyberkyd01/privatevpn/core/eventlog"
)

// Options configures a Refresher.
type Options struct {
	Enabled   func() bool    // nil = enabled; off → no requests, Source "none"
	Manual    func() *Manual // nil = none; overrides location fields, public IP still looked up
	UserAgent string         // "PrivateVPN/<version>"
	Client    *http.Client   // nil = NewHTTPClient(nil)
	Log       *eventlog.Log  // nil = no logging
	OnUpdate  func()         // called after each refresh (success or failure)
}

// timing holds the §10.3 schedule; tests shorten it.
type timing struct {
	period         time.Duration // periodic refresh
	jitter         time.Duration // ± around period
	netDelay       time.Duration // delay after a network change
	netMaxDebounce time.Duration // a burst of changes postpones the lookup at most this long
	netMinGap      time.Duration // network-triggered lookups start ≥ this long after the previous lookup
	staleAfter     time.Duration
	lookupTimeout  time.Duration // whole Lookup (3 providers + second family)
}

var defaultTiming = timing{
	period:         10 * time.Minute,
	jitter:         time.Minute,
	netDelay:       5 * time.Second,
	netMaxDebounce: 30 * time.Second,
	netMinGap:      60 * time.Second,
	staleAfter:     30 * time.Minute,
	lookupTimeout:  45 * time.Second,
}

// Refresher keeps the gateway's public IP and location current (§10.3):
// a lookup on Start, then every 10 min ± 1 min, and 5 s after a network
// change (debounced, never sooner than 60 s after the previous lookup).
// Failures keep the last value. The result lives in memory only.
type Refresher struct {
	o      Options
	t      timing
	now    func() time.Time
	lookup func(context.Context, *http.Client, string) (Result, error)

	netCh  chan struct{}
	stopCh chan struct{}
	done   chan struct{}
	ctx    context.Context
	cancel context.CancelFunc

	runMu   sync.Mutex
	started bool
	stopped bool

	mu       sync.Mutex
	last     Result
	lastOK   time.Time
	have     bool
	logState int // 0 nothing logged, 1 last logged success, 2 last logged failure
	logProv  string
}

// NewRefresher returns a stopped Refresher; call Start.
func NewRefresher(o Options) *Refresher {
	if o.Client == nil {
		o.Client = NewHTTPClient(nil)
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Refresher{
		o:      o,
		t:      defaultTiming,
		now:    time.Now,
		lookup: Lookup,
		netCh:  make(chan struct{}, 1),
		stopCh: make(chan struct{}),
		done:   make(chan struct{}),
		ctx:    ctx,
		cancel: cancel,
	}
}

// Start performs a lookup immediately (in the background) and schedules the
// periodic refresh. Calling it again, or after Stop, does nothing.
func (r *Refresher) Start() {
	r.runMu.Lock()
	defer r.runMu.Unlock()
	if r.started || r.stopped {
		return
	}
	r.started = true
	go r.run()
}

// Stop cancels any lookup in flight and waits for the background goroutine
// to exit; OnUpdate is not called afterwards. It is idempotent and must not
// be called from OnUpdate.
func (r *Refresher) Stop() {
	r.runMu.Lock()
	started := r.started
	if !r.stopped {
		r.stopped = true
		r.cancel()
		close(r.stopCh)
	}
	r.runMu.Unlock()
	if started {
		<-r.done
	}
}

// NetworkChanged schedules a lookup 5 s later. Repeated calls are
// debounced, and the lookup never starts sooner than 60 s after the previous
// one. It never blocks.
func (r *Refresher) NetworkChanged() {
	select {
	case r.netCh <- struct{}{}:
	default:
	}
}

// Current returns the latest result. stale reports that the last successful
// lookup is more than 30 min old. When disabled, Source is "none" and
// nothing else is set; when no lookup has succeeded yet, Source is "none"
// unless a manual location is configured. The manual override is applied
// on every call.
func (r *Refresher) Current() (res Result, stale bool) {
	if !r.enabled() {
		return Result{Source: sourceNone}, false
	}
	r.mu.Lock()
	res, have, lastOK := r.last, r.have, r.lastOK
	r.mu.Unlock()
	if !have {
		res = Result{Source: sourceNone}
	} else {
		stale = r.now().Sub(lastOK) > r.t.staleAfter
	}
	if r.o.Manual != nil {
		if m := r.o.Manual(); m != nil {
			res = applyManual(res, m)
		}
	}
	return res, stale
}

func (r *Refresher) enabled() bool { return r.o.Enabled == nil || r.o.Enabled() }

func (r *Refresher) run() {
	defer close(r.done)
	select { // a change reported before Start is covered by the first lookup
	case <-r.netCh:
	default:
	}
	timer := time.NewTimer(0)
	defer timer.Stop()
	var lastStart, netDue, netFirst time.Time
	nextPeriodic := time.Now()
	for {
		due := nextPeriodic
		if !netDue.IsZero() && netDue.Before(due) {
			due = netDue
		}
		timer.Reset(time.Until(due))
		select {
		case <-r.stopCh:
			return
		case <-r.netCh:
			now := time.Now()
			want := now.Add(r.t.netDelay)
			if netDue.IsZero() {
				netFirst = now
			} else if want.Sub(netFirst) > r.t.netMaxDebounce {
				want = netDue
			}
			if g := lastStart.Add(r.t.netMinGap); want.Before(g) {
				want = g
			}
			netDue = want
			continue
		case <-timer.C:
		}
		if time.Now().Before(due) {
			continue
		}
		lastStart = time.Now()
		netDue = time.Time{}
		r.refresh()
		nextPeriodic = time.Now().Add(r.period())
	}
}

// period returns the refresh interval with uniform jitter.
func (r *Refresher) period() time.Duration {
	d := r.t.period
	if j := r.t.jitter; j > 0 && j < d {
		d += time.Duration(rand.Int64N(int64(2*j)+1)) - j
	}
	return d
}

// refresh performs one lookup (or, when disabled, drops the cached value).
func (r *Refresher) refresh() {
	if !r.enabled() {
		r.mu.Lock()
		r.last, r.lastOK, r.have = Result{}, time.Time{}, false
		r.mu.Unlock()
		return
	}
	ctx, cancel := context.WithTimeout(r.ctx, r.t.lookupTimeout)
	res, err := r.lookup(ctx, r.o.Client, r.o.UserAgent)
	cancel()
	if r.ctx.Err() != nil {
		return // stopping
	}
	r.mu.Lock()
	if err == nil {
		r.last, r.lastOK, r.have = res, r.now(), true
	}
	r.mu.Unlock()
	r.logResult(res, err)
	if r.o.OnUpdate != nil {
		r.o.OnUpdate()
	}
}

// logResult logs state transitions only, at "updated via <provider>" /
// failure-class granularity: never addresses or location.
func (r *Refresher) logResult(res Result, err error) {
	if r.o.Log == nil {
		return
	}
	var msg string
	r.mu.Lock()
	if err == nil {
		if r.logState != 1 || r.logProv != res.Provider {
			msg = "updated via " + Sanitize(res.Provider, capProvider)
		}
		r.logState, r.logProv = 1, res.Provider
	} else {
		if r.logState != 2 {
			msg = "lookup failed"
			var le *lookupError
			if errors.As(err, &le) {
				msg += " (" + le.classes() + ")"
			}
			if r.have {
				msg += ", keeping last value"
			}
		}
		r.logState = 2
	}
	r.mu.Unlock()
	if msg != "" {
		r.o.Log.Printf("geo", "%s", msg)
	}
}

func (e *lookupError) classes() string {
	parts := make([]string, len(e.errs))
	for i, err := range e.errs {
		parts[i] = err.Error()
	}
	return strings.Join(parts, "; ")
}
