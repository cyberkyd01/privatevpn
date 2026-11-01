package engine

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"runtime"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cyberkyd01/private-vpn-pro/core/api"
	"github.com/cyberkyd01/private-vpn-pro/core/beacon"
	"github.com/cyberkyd01/private-vpn-pro/core/eventlog"
	"github.com/cyberkyd01/private-vpn-pro/core/netkey"
	"github.com/cyberkyd01/private-vpn-pro/core/state"
	"github.com/cyberkyd01/private-vpn-pro/core/sysinfo"
	"github.com/cyberkyd01/private-vpn-pro/core/tunnel"
)

const isAndroid = runtime.GOOS == "android"

// core holds all role state behind Engine.
type core struct {
	e     *Engine
	log   *eventlog.Log
	store *state.Store
	table *beacon.Table

	// opMu serialises role transitions (enable/disable/connect/…).
	opMu sync.Mutex

	mu       sync.Mutex
	recv     *beacon.Receiver
	gw       *gatewayRole // nil when gateway mode is off
	sess     *session     // nil when no client session
	tun      tunnel.Tunnel
	manual   map[string]*manualRuntime
	info     map[string]cachedInfo
	subkeys  map[string]subkeyCache
	lastErr  *api.Error
	resuming bool // resumeLoop is running (status.client.resume_pending)
	watcher  *sysinfo.Watcher
	gwEmitAt time.Time
	gwTimer  *time.Timer

	stop chan struct{}
	wg   sync.WaitGroup
}

type subkeyCache struct {
	key [32]byte
	sub netkey.Subkeys
}

type handlerFunc func(c *core, args []byte) (any, *api.Error)

var handlers = map[string]handlerFunc{}

func handle(name string, fn handlerFunc) { handlers[name] = fn }

func newCore(e *Engine) (*core, error) {
	st, err := state.Open(e.opts.DataDir, applyDefaults)
	if err != nil {
		return nil, err
	}
	c := &core{
		e: e, log: e.log, store: st, table: beacon.NewTable(),
		manual: map[string]*manualRuntime{}, info: map[string]cachedInfo{},
		subkeys: map[string]subkeyCache{}, stop: make(chan struct{}),
	}
	if isAndroid && e.opts.Platform.MobileSystemInfo != nil {
		c.applyMobileInfo()
	}
	e.log.Subscribe(func(line string) {
		e.emit(map[string]any{"type": api.EventLog, "line": line})
	})
	c.startDiscovery()
	if !isAndroid {
		c.watcher = sysinfo.NewWatcher(10*time.Second, c.networkChanged)
	}
	c.wg.Add(1)
	go c.housekeeping()
	c.log.Printf("app", "Private VPN Pro %s started (%s)", e.opts.AppVersion, sysinfo.OSName())
	if !isAndroid {
		c.firstRunAutostart()
		// Restore the roles that were on before a restart or crash.
		if g := st.Get().Gateway; g != nil && g.Enabled {
			go func() {
				if aerr := c.gatewayEnable(); aerr != nil {
					c.log.Printf("gateway", "could not restore gateway mode: %s", aerr.Message)
				}
			}()
		}
		if cl := st.Get().Client; cl != nil && cl.AutoReconnect && cl.ResumeGatewayID != "" {
			c.wg.Add(1)
			c.resuming = true
			go c.resumeLoop(cl.ResumeGatewayID)
		}
	}
	return c, nil
}

// firstRunAutostart registers login autostart once, so the app (and its
// gateway / client roles) come back after a restart; the user can turn it
// off in Settings.
func (c *core) firstRunAutostart() {
	st := c.store.Get()
	if st.UI.AutostartConfigured || c.e.opts.Platform.SetAutostart == nil {
		return
	}
	on := c.e.opts.Platform.SetAutostart(true) == nil
	c.store.Update(func(st *state.State) error {
		st.UI.AutostartConfigured = true
		st.UI.Autostart = on
		return nil
	})
}

// Resume timing; atomic so tests can shorten it.
var resumeFirstNs, resumeRetryNs atomic.Int64

func init() {
	resumeFirstNs.Store(int64(3 * time.Second))
	resumeRetryNs.Store(int64(10 * time.Second))
}

// resumeLoop reconnects to the gateway of a session that was still wanted
// when the app last stopped (restart, crash, logoff). Joining needs no
// privileges, so it retries quietly until the gateway is reachable; the
// administrator prompt for the tunnel appears only once a JOIN succeeded.
// Any failure at or after that prompt (declined, or the tunnel could not be
// created) stops the automatic attempts: retrying would show the prompt
// again every few seconds. The block, if one is engaged, stays, and the UI
// offers Reconnect / Disconnect.
func (c *core) resumeLoop(gwID string) {
	defer c.wg.Done()
	defer func() {
		// Whatever the outcome, the UI must stop saying "reconnecting".
		c.mu.Lock()
		c.resuming = false
		c.mu.Unlock()
		select {
		case <-c.stop:
		default:
			c.emitStatus()
		}
	}()
	c.log.Printf("client", "reconnecting to the previous gateway after restart")
	for attempt := 0; ; attempt++ {
		wait := time.Duration(resumeFirstNs.Load())
		if attempt > 0 {
			wait = time.Duration(resumeRetryNs.Load())
		}
		select {
		case <-c.stop:
			return
		case <-time.After(wait):
		}
		st := c.store.Get()
		if st.Client == nil || st.Client.ResumeGatewayID != gwID || !st.Client.AutoReconnect {
			return // user connected elsewhere, disconnected, or turned it off
		}
		c.mu.Lock()
		busy := c.sess != nil
		lastErr := c.lastErr
		c.mu.Unlock()
		if busy {
			// A session (ours or the user's) is running; wait for it.
			continue
		}
		if lastErr != nil {
			switch lastErr.Code {
			case api.CodeElevation:
				c.log.Printf("client", "automatic reconnect stopped: administrator approval was declined")
				return
			case api.CodeInternal:
				c.log.Printf("client", "automatic reconnect stopped: the tunnel could not be created")
				return
			}
		}
		it, aerr := c.findItem(gwID)
		if aerr != nil || it.Access != "member" {
			continue // not discovered yet
		}
		b, _ := json.Marshal(map[string]string{"gateway_id": gwID})
		c.clientConnectH(b)
		// Wait for this attempt to finish (connected, held or failed).
		for {
			select {
			case <-c.stop:
				return
			case <-time.After(time.Second):
			}
			c.mu.Lock()
			s := c.sess
			c.mu.Unlock()
			if s == nil {
				break // failed before a tunnel existed: retry
			}
			s.mu.Lock()
			done := s.tunUp
			s.mu.Unlock()
			if done {
				return // tunnel installed: the session loop owns recovery now
			}
		}
	}
}

func (c *core) setResume(gwID string) {
	c.store.Update(func(st *state.State) error {
		if st.Client != nil {
			st.Client.ResumeGatewayID = gwID
		}
		return nil
	})
}

func applyDefaults(st *state.State) {
	if st.ManualGateways == nil {
		st.ManualGateways = []state.ManualGateway{}
	}
	if st.KnownGateways == nil {
		st.KnownGateways = []state.KnownGateway{}
	}
	if st.Keyring == nil {
		st.Keyring = []state.KeyEntry{}
	}
	if st.Client == nil {
		st.Client = &state.Client{KillSwitch: true, AllowLAN: true, AutoReconnect: true}
	}
	if isAndroid {
		st.DeviceName = ""
		st.Gateway = nil
		st.Client.KillSwitchEngaged = false // the OS removes the VPN with the process
		return
	}
	if st.DeviceName == "" {
		st.DeviceName = sysinfo.DefaultDeviceName()
	}
	if st.Gateway == nil {
		st.Gateway = &state.Gateway{WGPort: 51820, CtrlPort: 51821, Geo: state.GeoSettings{Enabled: true}}
	}
	if st.UI.Port == 0 {
		st.UI.Port = 47771
	}
	if st.UI.Theme == "" {
		st.UI.Theme = "system"
	}
}

func (c *core) startDiscovery() {
	r, err := beacon.StartReceiver(beacon.Port, c.onBeacon)
	if err != nil {
		c.log.Printf("discovery", "cannot listen on UDP %d (%v); retrying", beacon.Port, errClass(err))
		return
	}
	c.mu.Lock()
	c.recv = r
	c.mu.Unlock()
}

func (c *core) onBeacon(raw []byte, from netip.Addr) {
	if c.table.Handle(raw, from, c.keyRefs()) {
		c.gatewaysChanged()
	}
}

// housekeeping expires table entries, refreshes manual gateways and keeps
// the online flags in the UI current.
func (c *core) housekeeping() {
	defer c.wg.Done()
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	n := 0
	for {
		select {
		case <-c.stop:
			return
		case <-tick.C:
		}
		n++
		c.table.Expire()
		c.mu.Lock()
		noRecv := c.recv == nil
		c.mu.Unlock()
		if noRecv && n%6 == 0 {
			c.startDiscovery()
		}
		if n%6 == 1 {
			c.refreshManual()
		}
		c.gatewaysChanged()
	}
}

func (c *core) networkChanged() {
	c.mu.Lock()
	r, g := c.recv, c.gw
	c.mu.Unlock()
	if isAndroid {
		c.applyMobileInfo()
	}
	if r != nil {
		r.Rejoin()
	}
	if g != nil {
		g.networkChanged()
	}
	c.log.Printf("app", "network changed")
}

func (c *core) shutdown() {
	select {
	case <-c.stop:
		return
	default:
	}
	close(c.stop)
	// Under opMu: a transition in flight (e.g. the autostart enable) must
	// finish before its role is stopped, and none may start afterwards.
	c.opMu.Lock()
	// Shutdown is not a disconnect (OS shutdown, logoff, signal): a client
	// session is abandoned without removing its tunnel, so the kill switch
	// keeps blocking and the session resumes after the restart. An explicit
	// quit (app.quit) disconnects first.
	c.mu.Lock()
	s := c.sess
	c.sess = nil
	c.mu.Unlock()
	if s != nil {
		s.endOnce.Do(func() { s.cancel() })
	}
	if !isAndroid {
		c.gatewayStop()
	}
	c.opMu.Unlock()
	c.mu.Lock()
	r, w := c.recv, c.watcher
	c.recv, c.tun = nil, nil
	c.mu.Unlock()
	if w != nil {
		w.Stop()
	}
	if r != nil {
		r.Close()
	}
	c.wg.Wait()
}

// quit is the user's explicit Quit: disconnect (removing the block), forget
// the resume target, then shut down.
func (c *core) quit() {
	c.setResume("")
	c.clientDisconnect()
	c.e.Close()
}

// ---- keyring helpers ----

// keyRefs returns beacon keys for every keyring entry, most recently used first.
func (c *core) keyRefs() []beacon.KeyRef {
	kr := c.store.Get().Keyring
	sort.SliceStable(kr, func(i, j int) bool { return kr[i].LastUsed > kr[j].LastUsed })
	out := make([]beacon.KeyRef, 0, len(kr))
	for _, k := range kr {
		out = append(out, beacon.KeyRef{ID: k.ID, KBeacon: c.subkeysFor(k).Beacon})
	}
	return out
}

func (c *core) subkeysFor(k state.KeyEntry) netkey.Subkeys {
	var key [32]byte
	copy(key[:], k.Key)
	c.mu.Lock()
	defer c.mu.Unlock()
	if sc, ok := c.subkeys[k.ID]; ok && sc.key == key {
		return sc.sub
	}
	sub := netkey.Key(key).Derive()
	c.subkeys[k.ID] = subkeyCache{key: key, sub: sub}
	return sub
}

func (c *core) keyEntry(id string) (state.KeyEntry, bool) {
	if id == "" {
		return state.KeyEntry{}, false
	}
	for _, k := range c.store.Get().Keyring {
		if k.ID == id {
			return k, true
		}
	}
	return state.KeyEntry{}, false
}

func (c *core) touchKey(id string) {
	now := time.Now().Unix()
	c.store.Update(func(st *state.State) error {
		for i := range st.Keyring {
			if st.Keyring[i].ID == id {
				st.Keyring[i].LastUsed = now
			}
		}
		return nil
	})
}

// ---- events ----

func (c *core) emitStatus() {
	c.e.emit(map[string]any{"type": api.EventStatus, "status": c.statusDoc()})
}

func (c *core) emitKeyring() {
	c.e.emit(map[string]any{"type": api.EventKeyring, "entries": c.keyringList()})
}

// gatewaysChanged emits the gateway list, coalesced to at most 2/s.
func (c *core) gatewaysChanged() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.gwTimer != nil {
		return
	}
	wait := 500*time.Millisecond - time.Since(c.gwEmitAt)
	if wait < 0 {
		wait = 0
	}
	c.gwTimer = time.AfterFunc(wait, func() {
		c.mu.Lock()
		c.gwTimer = nil
		c.gwEmitAt = time.Now()
		c.mu.Unlock()
		c.e.emit(map[string]any{"type": api.EventGateways, "gateways": c.gatewayList()})
	})
}

func (c *core) emitError(aerr *api.Error) {
	c.e.emit(map[string]any{"type": api.EventError, "code": aerr.Code, "message": aerr.Message})
}

// ---- small helpers ----

func decode[T any](args []byte) (T, *api.Error) {
	var v T
	dec := json.NewDecoder(bytes.NewReader(args))
	if err := dec.Decode(&v); err != nil {
		return v, api.BadRequest("invalid arguments")
	}
	return v, nil
}

func newID() string {
	var b [16]byte
	rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	h := hex.EncodeToString(b[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

func pubID(pub [32]byte) string { return base64.RawURLEncoding.EncodeToString(pub[:]) }

func parsePubID(id string) ([32]byte, bool) {
	var pub [32]byte
	b, err := base64.RawURLEncoding.DecodeString(id)
	if err != nil || len(b) != 32 {
		return pub, false
	}
	copy(pub[:], b)
	return pub, true
}

// errClass reduces an error to a non-identifying description for logs.
func errClass(err error) string {
	if err == nil {
		return ""
	}
	s := err.Error()
	if len(s) > 120 {
		s = s[:120]
	}
	return s
}

func osName(code byte) string {
	switch code {
	case 1:
		return "windows"
	case 2:
		return "macos"
	case 3:
		return "linux"
	}
	return "unknown"
}
