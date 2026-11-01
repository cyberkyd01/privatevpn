package geo

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cyberkyd01/private-vpn-pro/core/eventlog"
)

// fakeLookup records call times and returns canned results.
type fakeLookup struct {
	mu    sync.Mutex
	calls []time.Time
	res   Result
	err   error
	block bool // wait for ctx cancellation
}

func (f *fakeLookup) lookup(ctx context.Context, _ *http.Client, _ string) (Result, error) {
	f.mu.Lock()
	f.calls = append(f.calls, time.Now())
	res, err, block := f.res, f.err, f.block
	f.mu.Unlock()
	if block {
		<-ctx.Done()
		return Result{Source: "none"}, ctx.Err()
	}
	return res, err
}

func (f *fakeLookup) set(res Result, err error) {
	f.mu.Lock()
	f.res, f.err = res, err
	f.mu.Unlock()
}

func (f *fakeLookup) times() []time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]time.Time(nil), f.calls...)
}

func (f *fakeLookup) count() int { return len(f.times()) }

func goodResult() Result {
	return Result{Source: "geoip", Provider: "ipwho.is", Country: "United Kingdom", CountryCode: "GB",
		City: "London", Lat: 51.5, Lon: -0.12, HasCoords: true, AccuracyKm: 25, ISP: "Datacamp Limited",
		ASN: "AS212238", PublicIP: netip.MustParseAddr("203.0.113.7"), TZName: "Europe/London",
		HasOffset: true, CheckedAt: time.Now()}
}

// shortTiming keeps the scheduling logic but in milliseconds.
var shortTiming = timing{
	period:         time.Hour,
	jitter:         0,
	netDelay:       40 * time.Millisecond,
	netMaxDebounce: 200 * time.Millisecond,
	netMinGap:      150 * time.Millisecond,
	staleAfter:     30 * time.Minute,
	lookupTimeout:  5 * time.Second,
}

func newTestRefresher(o Options, f *fakeLookup, tm timing) *Refresher {
	r := NewRefresher(o)
	r.t = tm
	r.lookup = f.lookup
	return r
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func TestRefresherStartAndPeriodic(t *testing.T) {
	f := &fakeLookup{res: goodResult()}
	var updates atomic.Int32
	tm := shortTiming
	tm.period, tm.jitter = 60*time.Millisecond, 10*time.Millisecond
	r := newTestRefresher(Options{OnUpdate: func() { updates.Add(1) }}, f, tm)
	start := time.Now()
	r.Start()
	r.Start() // no-op
	waitFor(t, "first lookup", func() bool { return f.count() >= 1 })
	if d := f.times()[0].Sub(start); d > time.Second {
		t.Errorf("first lookup after %v, want immediate", d)
	}
	waitFor(t, "periodic lookups", func() bool { return f.count() >= 4 })
	r.Stop()
	ts := f.times()
	for i := 1; i < len(ts); i++ {
		if gap := ts[i].Sub(ts[i-1]); gap < 45*time.Millisecond {
			t.Errorf("gap %d = %v, want ≥ period-jitter (50ms) minus slack", i, gap)
		}
	}
	n := f.count()
	time.Sleep(150 * time.Millisecond)
	if f.count() != n {
		t.Error("lookup after Stop")
	}
	if int(updates.Load()) != n {
		t.Errorf("OnUpdate called %d times for %d lookups", updates.Load(), n)
	}
	r.Stop() // idempotent
}

func TestRefresherPeriodJitter(t *testing.T) {
	r := NewRefresher(Options{})
	seen := map[time.Duration]bool{}
	for i := 0; i < 200; i++ {
		d := r.period()
		if d < 9*time.Minute || d > 11*time.Minute {
			t.Fatalf("period %v outside 10 min ± 1 min", d)
		}
		seen[d] = true
	}
	if len(seen) < 10 {
		t.Errorf("period has little jitter: %d distinct values", len(seen))
	}
}

func TestRefresherNetworkChangedDebounceAndMinGap(t *testing.T) {
	f := &fakeLookup{res: goodResult()}
	r := newTestRefresher(Options{}, f, shortTiming)
	r.Start()
	defer r.Stop()
	waitFor(t, "initial lookup", func() bool { return f.count() == 1 })
	t0 := f.times()[0]

	// A burst right after the initial lookup: one lookup, not before the
	// 150 ms minimum gap.
	for i := 0; i < 5; i++ {
		r.NetworkChanged()
		time.Sleep(5 * time.Millisecond)
	}
	waitFor(t, "network-triggered lookup", func() bool { return f.count() == 2 })
	t1 := f.times()[1]
	if gap := t1.Sub(t0); gap < shortTiming.netMinGap {
		t.Errorf("network lookup %v after previous, want ≥ %v", gap, shortTiming.netMinGap)
	}
	time.Sleep(300 * time.Millisecond)
	if n := f.count(); n != 2 {
		t.Fatalf("burst caused %d lookups, want 1", n-1)
	}

	// Long after the previous lookup: the 40 ms delay applies.
	called := time.Now()
	r.NetworkChanged()
	waitFor(t, "delayed lookup", func() bool { return f.count() == 3 })
	if d := f.times()[2].Sub(called); d < shortTiming.netDelay {
		t.Errorf("lookup %v after NetworkChanged, want ≥ %v", d, shortTiming.netDelay)
	}
}

func TestRefresherDebounceIsBounded(t *testing.T) {
	f := &fakeLookup{res: goodResult()}
	tm := shortTiming
	tm.netMinGap = 0
	tm.netDelay = 50 * time.Millisecond
	tm.netMaxDebounce = 120 * time.Millisecond
	r := newTestRefresher(Options{}, f, tm)
	r.Start()
	defer r.Stop()
	waitFor(t, "initial lookup", func() bool { return f.count() == 1 })
	// Changes every 20 ms for 600 ms would postpone a pure trailing
	// debounce forever; the bound forces lookups during the burst.
	stop := time.Now().Add(600 * time.Millisecond)
	for time.Now().Before(stop) {
		r.NetworkChanged()
		time.Sleep(20 * time.Millisecond)
	}
	if n := f.count() - 1; n < 2 {
		t.Errorf("%d lookups during a 600 ms burst, want ≥ 2", n)
	}
}

func TestRefresherNetworkChangedBeforeStart(t *testing.T) {
	f := &fakeLookup{res: goodResult()}
	r := newTestRefresher(Options{}, f, shortTiming)
	r.NetworkChanged()
	r.NetworkChanged()
	r.Start()
	defer r.Stop()
	waitFor(t, "initial lookup", func() bool { return f.count() == 1 })
	time.Sleep(300 * time.Millisecond)
	if n := f.count(); n != 1 {
		t.Errorf("%d lookups, want only the initial one", n)
	}
}

func TestRefresherDisabled(t *testing.T) {
	var enabled atomic.Bool
	f := &fakeLookup{res: goodResult()}
	tm := shortTiming
	tm.netMinGap = 0
	r := newTestRefresher(Options{
		Enabled: enabled.Load,
		Manual:  func() *Manual { return &Manual{City: "Somewhere"} },
	}, f, tm)
	r.Start()
	defer r.Stop()
	time.Sleep(100 * time.Millisecond)
	if f.count() != 0 {
		t.Fatal("lookup while disabled")
	}
	if res, stale := r.Current(); res != (Result{Source: "none"}) || stale {
		t.Errorf("disabled Current = %+v, %v", res, stale)
	}

	enabled.Store(true)
	r.NetworkChanged()
	waitFor(t, "lookup after enabling", func() bool { return f.count() == 1 })
	waitFor(t, "result stored", func() bool { res, _ := r.Current(); return res.PublicIP.IsValid() })

	// Disabling hides the result at once and drops it at the next refresh.
	enabled.Store(false)
	if res, _ := r.Current(); res.Source != "none" || res.PublicIP.IsValid() {
		t.Errorf("Current after disabling = %+v", res)
	}
	r.NetworkChanged()
	waitFor(t, "cache dropped", func() bool {
		r.mu.Lock()
		defer r.mu.Unlock()
		return !r.have
	})
	if f.count() != 1 {
		t.Error("lookup while disabled")
	}
}

func TestRefresherManualOverlay(t *testing.T) {
	f := &fakeLookup{res: goodResult()}
	var manual atomic.Pointer[Manual]
	r := newTestRefresher(Options{Manual: manual.Load}, f, shortTiming)

	// Manual location before any lookup: location shown, no public IP.
	manual.Store(&Manual{Country: "Germany", Region: "Bavaria", City: "Munich", Lat: 48.14, Lon: 11.58, HasCoords: true, TZName: "Europe/Berlin"})
	res, stale := r.Current()
	if res.Source != "manual" || res.City != "Munich" || res.PublicIP.IsValid() || stale {
		t.Errorf("manual before lookup = %+v, %v", res, stale)
	}

	r.refresh()
	res, _ = r.Current()
	if res.Source != "manual" || res.Country != "Germany" || res.Region != "Bavaria" || res.City != "Munich" ||
		res.CountryCode != "" || res.Lat != 48.14 || res.Lon != 11.58 || !res.HasCoords || res.AccuracyKm != 0 ||
		res.TZName != "Europe/Berlin" {
		t.Errorf("manual overlay = %+v", res)
	}
	if res.PublicIP != netip.MustParseAddr("203.0.113.7") || res.ISP != "Datacamp Limited" || res.ASN != "AS212238" {
		t.Errorf("manual overlay lost lookup fields: %+v", res)
	}

	// Clearing the override restores the GeoIP result.
	manual.Store(nil)
	if res, _ = r.Current(); res.Source != "geoip" || res.City != "London" || res.AccuracyKm != 25 {
		t.Errorf("after clearing manual = %+v", res)
	}
}

func TestRefresherKeepsLastValueAndStale(t *testing.T) {
	var now atomic.Pointer[time.Time]
	t0 := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	now.Store(&t0)
	f := &fakeLookup{res: goodResult()}
	var updates atomic.Int32
	r := newTestRefresher(Options{OnUpdate: func() { updates.Add(1) }}, f, defaultTiming)
	r.now = func() time.Time { return *now.Load() }

	if res, stale := r.Current(); res.Source != "none" || stale {
		t.Errorf("before any lookup = %+v, %v", res, stale)
	}
	r.refresh()
	if res, stale := r.Current(); res.Source != "geoip" || stale {
		t.Errorf("after success = %+v, %v", res, stale)
	}

	f.set(Result{Source: "none"}, errors.New("boom"))
	t1 := t0.Add(20 * time.Minute)
	now.Store(&t1)
	r.refresh()
	res, stale := r.Current()
	if res.PublicIP != netip.MustParseAddr("203.0.113.7") || res.City != "London" || stale {
		t.Errorf("after failure = %+v, %v (want last value, not stale)", res, stale)
	}
	t2 := t0.Add(31 * time.Minute)
	now.Store(&t2)
	if res, stale = r.Current(); !stale || res.PublicIP != netip.MustParseAddr("203.0.113.7") {
		t.Errorf("31 min after success: %+v, stale=%v", res, stale)
	}
	if updates.Load() != 2 {
		t.Errorf("OnUpdate called %d times, want 2 (success and failure)", updates.Load())
	}

	// A new success clears staleness.
	f.set(goodResult(), nil)
	r.refresh()
	if _, stale = r.Current(); stale {
		t.Error("stale after a fresh success")
	}
}

func TestRefresherLogging(t *testing.T) {
	log := eventlog.New(50)
	f := &fakeLookup{res: goodResult()}
	r := newTestRefresher(Options{Log: log}, f, shortTiming)
	r.refresh()
	r.refresh() // unchanged state: no new line
	f.set(Result{Source: "none"}, &lookupError{errs: []error{
		&providerError{provider: "ipwho.is", class: "timeout"},
		&providerError{provider: "ipinfo.io", class: "status 429"},
	}})
	r.refresh()
	r.refresh()
	f.set(goodResult(), nil)
	r.refresh()

	lines := log.Lines()
	want := []string{
		"geo: updated via ipwho.is",
		"geo: lookup failed (ipwho.is: timeout; ipinfo.io: status 429), keeping last value",
		"geo: updated via ipwho.is",
	}
	if len(lines) != len(want) {
		t.Fatalf("log lines = %q", lines)
	}
	for i, l := range lines {
		if !strings.HasSuffix(l, " "+want[i]) {
			t.Errorf("line %d = %q, want suffix %q", i, l, want[i])
		}
		for _, bad := range []string{"203.0.113.7", "London", "51.5", "Datacamp", "AS212238"} {
			if strings.Contains(l, bad) {
				t.Errorf("log line leaks %q: %q", bad, l)
			}
		}
	}
}

func TestRefresherStop(t *testing.T) {
	// Stop before Start returns at once; Start afterwards does nothing.
	f := &fakeLookup{res: goodResult()}
	r := newTestRefresher(Options{}, f, shortTiming)
	r.Stop()
	r.Start()
	time.Sleep(50 * time.Millisecond)
	if f.count() != 0 {
		t.Error("Start after Stop ran a lookup")
	}

	// Stop cancels a lookup in flight; OnUpdate is not called.
	var updates atomic.Int32
	f = &fakeLookup{block: true}
	r = newTestRefresher(Options{OnUpdate: func() { updates.Add(1) }}, f, shortTiming)
	r.Start()
	waitFor(t, "lookup in flight", func() bool { return f.count() == 1 })
	done := make(chan struct{})
	go func() { r.Stop(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Stop did not cancel the lookup in flight")
	}
	if updates.Load() != 0 {
		t.Error("OnUpdate after Stop")
	}
}

// TestRefresherWithLookup runs the real Lookup against httptest providers.
func TestRefresherWithLookup(t *testing.T) {
	fs := newFakeServer(t, map[string]resp{
		"/ipwho":  failResp,
		"/ipinfo": okJSON(mustJSON(t, ipinfoBase(), nil)),
	})
	useProviders(t, fs.URL)
	updated := make(chan struct{}, 4)
	r := NewRefresher(Options{
		UserAgent: ua,
		Client:    testClient(t, v4Only, fs),
		OnUpdate:  func() { updated <- struct{}{} },
	})
	r.t = shortTiming
	r.Start()
	defer r.Stop()
	select {
	case <-updated:
	case <-time.After(10 * time.Second):
		t.Fatal("no update")
	}
	res, stale := r.Current()
	if res.Source != "geoip" || res.Provider != "ipinfo.io" || res.PublicIP != netip.MustParseAddr("203.0.113.7") || stale {
		t.Errorf("Current = %+v, %v", res, stale)
	}
}
