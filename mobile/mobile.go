// Package mobile is the gomobile facade used by the Android app
// (ARCHITECTURE §11.2). Its exported API is the entire Kotlin↔Go surface:
// the Callbacks interface, Start, Stop and Call. Everything else is JSON
// (method table §14.4, events §14.3).
//
// Bound with:
//
//	gomobile bind -target android/arm64,android/arm,android/amd64 -androidapi 26 \
//	  -javapkg app.privatevpn -o android/app/libs/core.aar ./mobile
//
// which generates the Java package app.privatevpn.mobile.
package mobile

import (
	"errors"
	"net/http"
	"runtime/debug"
	"sync"

	"github.com/cyberkyd01/privatevpn/core/api"
	"github.com/cyberkyd01/privatevpn/core/engine"
	"github.com/cyberkyd01/privatevpn/core/eventlog"
)

// Callbacks is implemented in Kotlin. Methods are called from Go threads;
// Kotlin must hop to the main thread where it needs to.
type Callbacks interface {
	// OnEvent receives one §14.3 event document.
	OnEvent(eventJSON string)
	// EstablishTun builds the VpnService interface from a §9.1 TunnelConfig
	// and returns its detached file descriptor (§9.5).
	EstablishTun(configJSON string) (int, error)
	// CloseTun tells Kotlin that Go has closed the device; Kotlin stops the
	// VPN service.
	CloseTun()
	// SystemInfo returns {"os_version","model","tz","dns":[…]} (§11.2).
	SystemInfo() string
}

// eventQueueLen bounds the events waiting for delivery to Kotlin. Engine
// subscribers must not block, so a full queue drops the event; status,
// gateways and keyring events are full snapshots, so the next one repairs
// the UI.
const eventQueueLen = 256

var (
	// lifeMu serialises Start and Stop (a Start never overlaps the Close of
	// the previous engine); mu guards the fields below and is never held
	// while the engine runs a method. callMu is read-held for the duration
	// of every Call so that Stop closes the engine only once no method is
	// running on it.
	lifeMu    sync.Mutex
	callMu    sync.RWMutex
	stdioOnce sync.Once
	mu        sync.Mutex
	eng       *engine.Engine
	unsub     func()
	drained   chan struct{}
)

// recoverTo turns a panic in an exported function into an "internal" error.
// Every exported function is entered from a JNI thread: an unrecovered panic
// would end the whole app process, with no state visible to the user. The
// panic value is discarded on purpose — it may quote keys, addresses or
// other data that must never leave the core (§12.1).
func recoverTo(err *error) {
	if r := recover(); r != nil {
		*err = errors.New(string(api.Errf(api.CodeInternal, http.StatusInternalServerError, "internal error in the core").JSON()))
	}
}

// Start creates the engine with dataDir as its state directory and starts
// discovery. It is idempotent: while the core runs, further calls return nil
// and keep the first Callbacks.
func Start(dataDir, appVersion string, cb Callbacks) (err error) {
	defer recoverTo(&err)
	lifeMu.Lock()
	defer lifeMu.Unlock()
	mu.Lock()
	running := eng != nil
	mu.Unlock()
	if running {
		return nil
	}
	if cb == nil {
		return errors.New(string(api.BadRequest("callbacks required").JSON()))
	}
	// A Go panic must not dump goroutines (and the values on their stacks)
	// into logcat (§12.1); stdout/stderr go to /dev/null on Android.
	debug.SetTraceback("none")
	stdioOnce.Do(silenceStdio)

	e, err := engine.New(engine.Options{
		DataDir:    dataDir,
		AppVersion: appVersion,
		Log:        eventlog.Default,
		Platform: engine.Platform{
			NewTunnel:        newTunnel(cb),
			MobileSystemInfo: cb.SystemInfo,
		},
	})
	if err != nil {
		return errors.New(string(api.Internal(err).JSON()))
	}

	q := make(chan string, eventQueueLen)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for ev := range q {
			deliver(cb, ev)
		}
	}()
	var qmu sync.Mutex
	qclosed := false
	cancel := e.Subscribe(func(ev []byte) {
		qmu.Lock()
		defer qmu.Unlock()
		if qclosed {
			return
		}
		select {
		case q <- string(ev):
		default: // Kotlin is not keeping up; drop rather than block the engine.
		}
	})

	mu.Lock()
	eng = e
	drained = done
	unsub = func() {
		cancel()
		qmu.Lock()
		qclosed = true
		close(q)
		qmu.Unlock()
	}
	mu.Unlock()
	return nil
}

// deliver hands one event to Kotlin. A panic here (a JNI failure, or a
// Kotlin exception the binding could not convert) is confined to the event
// so that the delivery goroutine keeps running.
func deliver(cb Callbacks, ev string) {
	defer func() { _ = recover() }()
	cb.OnEvent(ev)
}

// Stop shuts the engine down (client disconnect with LEAVE, discovery off)
// and stops event delivery. Start may be called again afterwards.
func Stop() {
	defer func() { _ = recover() }()
	lifeMu.Lock()
	defer lifeMu.Unlock()
	mu.Lock()
	e, cancel, done := eng, unsub, drained
	eng, unsub, drained = nil, nil, nil
	mu.Unlock()
	if e == nil {
		return
	}
	// New Calls now fail with not_started; wait for the ones in flight
	// before closing the engine underneath them.
	callMu.Lock()
	e.Close()
	callMu.Unlock()
	cancel()
	<-done
}

// Call runs one §14.4 method with a JSON argument document and returns the
// JSON result. On failure the error message is the {"code","message"} JSON.
func Call(method, argsJSON string) (res string, err error) {
	defer recoverTo(&err)
	callMu.RLock()
	defer callMu.RUnlock()
	mu.Lock()
	e := eng
	mu.Unlock()
	if e == nil {
		return "", errors.New(string(api.Errf("not_started", http.StatusServiceUnavailable, "core is not running").JSON()))
	}
	out, aerr := e.Call(method, []byte(argsJSON))
	if aerr != nil {
		return "", errors.New(string(aerr.JSON()))
	}
	return string(out), nil
}
