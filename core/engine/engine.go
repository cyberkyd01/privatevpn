// Package engine is the orchestrator behind both front-ends: it owns the
// keyring and settings, discovery, the gateway role, the client role and the
// event bus. Desktop (desktop/web, desktop/tray) and Android (mobile) talk to
// it only through Call and Subscribe (ARCHITECTURE §14).
package engine

import (
	"encoding/json"
	"errors"
	"sync"

	"github.com/cyberkyd01/private-vpn-pro/core/api"
	"github.com/cyberkyd01/private-vpn-pro/core/eventlog"
	"github.com/cyberkyd01/private-vpn-pro/core/tunnel"
)

// Platform supplies OS-specific capabilities. Nil funcs mean "unsupported".
type Platform struct {
	// NewTunnel returns the client-mode tunnel; called lazily on first
	// connect (desktop: helper.New; Android: tunnel.NewAndroid).
	NewTunnel func() (tunnel.Tunnel, error)
	// FirewallAdd/FirewallCheck manage the Windows inbound UDP rule.
	FirewallAdd   func() error
	FirewallCheck func() (present bool, err error)
	// SetAutostart registers/unregisters login autostart (desktop).
	SetAutostart func(on bool) error
	// Quit is invoked for app.quit (after the engine has shut down roles).
	Quit func()
	// MobileSystemInfo returns the Android SystemInfo JSON (§11.2).
	MobileSystemInfo func() string
}

// Options configure New.
type Options struct {
	DataDir    string
	AppVersion string
	Platform   Platform
	Log        *eventlog.Log
	// Autostart is true when launched at login. Informational: roles are
	// restored the same way at every start — gateway mode if it was on, and
	// the client session that was still wanted when the app last stopped
	// (its kill-switch block has been holding since; the administrator
	// prompt for the tunnel appears once the gateway answered a JOIN).
	Autostart bool
}

// Engine is safe for concurrent use.
type Engine struct {
	opts Options
	log  *eventlog.Log

	subMu  sync.Mutex
	subID  int
	subs   map[int]func([]byte)
	closed bool

	core *core // role state; see core.go
}

// New loads state from DataDir and starts discovery.
func New(opts Options) (*Engine, error) {
	if opts.DataDir == "" {
		return nil, errors.New("engine: DataDir required")
	}
	if opts.Log == nil {
		opts.Log = eventlog.Default
	}
	if opts.AppVersion == "" {
		opts.AppVersion = "0.0.0"
	}
	e := &Engine{opts: opts, log: opts.Log, subs: map[int]func([]byte){}}
	c, err := newCore(e)
	if err != nil {
		return nil, err
	}
	e.core = c
	return e, nil
}

// Call runs one method. args may be nil or empty for methods without
// arguments. The result is a JSON document.
func (e *Engine) Call(method string, args []byte) ([]byte, *api.Error) {
	if len(args) == 0 {
		args = []byte("{}")
	}
	if len(args) > 64<<10 {
		return nil, api.BadRequest("arguments too large")
	}
	e.subMu.Lock()
	closed := e.closed
	e.subMu.Unlock()
	if closed {
		return nil, api.Errf(api.CodeConflict, 409, "Private VPN Pro is shutting down")
	}
	h, ok := handlers[method]
	if !ok {
		return nil, api.Errf(api.CodeNotFound, 404, "unknown method %q", method)
	}
	res, aerr := h(e.core, args)
	if aerr != nil {
		return nil, aerr
	}
	if res == nil {
		res = struct{}{}
	}
	b, err := json.Marshal(res)
	if err != nil {
		return nil, api.Internal(err)
	}
	return b, nil
}

// Subscribe registers fn for every event (§14.3). fn is called from engine
// goroutines and must not block.
func (e *Engine) Subscribe(fn func(event []byte)) (cancel func()) {
	e.subMu.Lock()
	e.subID++
	id := e.subID
	e.subs[id] = fn
	e.subMu.Unlock()
	return func() {
		e.subMu.Lock()
		delete(e.subs, id)
		e.subMu.Unlock()
	}
}

func (e *Engine) emit(ev any) {
	b, err := json.Marshal(ev)
	if err != nil {
		return
	}
	e.subMu.Lock()
	fns := make([]func([]byte), 0, len(e.subs))
	for _, fn := range e.subs {
		fns = append(fns, fn)
	}
	e.subMu.Unlock()
	for _, fn := range fns {
		fn(b)
	}
}

// Close stops all roles (client disconnect with LEAVE, gateway off) and
// discovery. The persisted gateway.enabled flag is kept for autostart.
func (e *Engine) Close() {
	e.subMu.Lock()
	if e.closed {
		e.subMu.Unlock()
		return
	}
	e.closed = true
	e.subMu.Unlock()
	e.core.shutdown()
}
