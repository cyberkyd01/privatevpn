//go:build !android

// Package tray is the desktop tray icon and menu (ARCHITECTURE §13.1), built
// on fyne.io/systray. There is no application window: "Open PrivateVPN"
// mints a single-use login URL and opens the web UI in the browser.
package tray

import (
	"embed"
	"encoding/json"
	"net/url"
	"runtime"
	"strconv"
	"sync"
	"time"

	"fyne.io/systray"

	"github.com/cyberkyd01/privatevpn/core/api"
)

// Backend is the engine as seen by the tray (core/engine.Engine satisfies it).
type Backend interface {
	Call(method string, args []byte) ([]byte, *api.Error)
	Subscribe(fn func(event []byte)) (cancel func())
}

// Options configure Run.
type Options struct {
	Backend Backend
	// LoginURL mints a single-use login URL (web.Server.MintLoginURL).
	LoginURL func() string
	// OnReady runs once the tray icon exists (optional).
	OnReady func()
	// OnExit runs on the tray's event loop when it stops, before Run
	// returns (optional).
	OnExit func()
}

//go:embed icons/*.png icons/*.ico
var iconFS embed.FS

func mustIcon(name string) []byte {
	b, err := iconFS.ReadFile("icons/" + name)
	if err != nil {
		panic("tray: missing icon " + name)
	}
	return b
}

var iconNames = [...]string{iconIdle: "idle", iconGateway: "gateway", iconConnected: "connected", iconBoth: "both", iconWarning: "warning"}

// Run shows the tray icon and blocks until Quit. On macOS it must be called
// from the main goroutine (fyne.io/systray locks the main OS thread).
func Run(o Options) {
	t := &tray{o: o, notify: make(chan struct{}, 1), stop: make(chan struct{})}
	systray.Run(t.onReady, t.onExit)
}

// Quit ends Run. Safe to call from any goroutine, more than once.
func Quit() { systray.Quit() }

type itemState struct {
	title            string
	shown, enabled   bool
	checked, applied bool
}

type tray struct {
	o Options

	mu         sync.Mutex
	st         statusModel
	haveStatus bool
	gws        []gatewayModel
	entries    []menuEntry // what the Connect-to slots show
	flash      string
	flashUntil time.Time
	gwBusy     bool
	quitting   bool

	notify    chan struct{}
	stop      chan struct{}
	stopOnce  sync.Once
	cancelSub func()

	// Menu items; created in onReady, then only touched by loop().
	open, status, problems, gateway, connect, disconnect, copyKey, quit, none, more *systray.MenuItem
	slots                                                                           []*systray.MenuItem
	applied                                                                         map[*systray.MenuItem]*itemState
	icon                                                                            iconKind
	iconSet                                                                         bool
	tooltip                                                                         string
}

func (t *tray) onReady() {
	t.applied = map[*systray.MenuItem]*itemState{}
	t.setIcon(iconIdle)
	systray.SetTooltip("PrivateVPN")

	t.open = systray.AddMenuItem("Open PrivateVPN", "Open PrivateVPN in your browser")
	t.status = systray.AddMenuItem("Starting…", "")
	t.status.Disable()
	t.problems = systray.AddMenuItem("Problems", "Open PrivateVPN to see every problem and what to do")
	t.problems.Hide()
	t.gateway = systray.AddMenuItemCheckbox("Gateway mode",
		"Share this computer's Internet connection. Members' traffic will exit from your Internet connection and carry your public IP.", false)
	t.connect = systray.AddMenuItem("Connect to", "Route this device's traffic through a gateway")
	t.none = t.connect.AddSubMenuItem("No gateways found", "")
	t.none.Disable()
	for i := 0; i < maxEntries; i++ {
		it := t.connect.AddSubMenuItemCheckbox("-", "", false)
		it.Hide()
		t.slots = append(t.slots, it)
	}
	t.more = t.connect.AddSubMenuItem("More…", "Open PrivateVPN to see every gateway")
	t.more.Hide()
	t.disconnect = systray.AddMenuItem("Disconnect", "Stop using the VPN and remove the kill switch's block (may ask for administrator approval)")
	t.disconnect.Disable()
	systray.AddSeparator()
	t.copyKey = systray.AddMenuItem("Copy my gateway key", "Copy the network key this gateway serves to the clipboard")
	t.copyKey.Hide()
	t.quit = systray.AddMenuItem("Quit", "Disconnect, remove the kill switch's block and quit PrivateVPN")

	if runtime.GOOS == "windows" {
		// Windows convention: left click opens the app, right click the menu.
		systray.SetOnTapped(func() { go t.openUI("") })
	}

	t.listen(t.open, func() { t.openUI("") })
	t.listen(t.problems, func() { t.openUI("") })
	t.listen(t.gateway, t.toggleGateway)
	t.listen(t.more, func() { t.openUI("") })
	t.listen(t.disconnect, t.disconnectClient)
	t.listen(t.copyKey, t.copyGatewayKey)
	t.listen(t.quit, t.quitApp)
	for i, it := range t.slots {
		t.listen(it, func() { t.selectSlot(i) })
	}

	t.cancelSub = t.o.Backend.Subscribe(t.onEvent)
	go t.loop()
	go t.refresh()
	if t.o.OnReady != nil {
		t.o.OnReady()
	}
}

func (t *tray) onExit() {
	t.stopOnce.Do(func() { close(t.stop) })
	if t.cancelSub != nil {
		t.cancelSub()
	}
	if t.o.OnExit != nil {
		t.o.OnExit()
	}
}

// listen runs fn (in its own goroutine) for every click on it.
func (t *tray) listen(it *systray.MenuItem, fn func()) {
	go func() {
		for {
			select {
			case <-it.ClickedCh:
				go fn()
			case <-t.stop:
				return
			}
		}
	}()
}

func (t *tray) kick() {
	select {
	case t.notify <- struct{}{}:
	default:
	}
}

// onEvent receives engine events (§14.3); it must not block.
func (t *tray) onEvent(ev []byte) {
	var head struct {
		Type     string          `json:"type"`
		Status   json.RawMessage `json:"status"`
		Gateways json.RawMessage `json:"gateways"`
	}
	if json.Unmarshal(ev, &head) != nil {
		return
	}
	switch head.Type {
	case api.EventStatus:
		if st, ok := parseStatus(head.Status); ok {
			t.mu.Lock()
			t.st, t.haveStatus = st, true
			t.mu.Unlock()
			t.kick()
		}
	case api.EventGateways:
		if gws, ok := parseGateways(head.Gateways); ok {
			t.mu.Lock()
			t.gws = gws
			t.mu.Unlock()
			t.kick()
		}
	}
}

// refresh polls status and the gateway list (start-up, after actions, and
// periodically as a fallback for missed events).
func (t *tray) refresh() {
	if res, err := t.o.Backend.Call(api.StatusGet, nil); err == nil {
		if st, ok := parseStatus(res); ok {
			t.mu.Lock()
			t.st, t.haveStatus = st, true
			t.mu.Unlock()
		}
	}
	if res, err := t.o.Backend.Call(api.GatewaysList, nil); err == nil {
		var r struct {
			Gateways json.RawMessage `json:"gateways"`
		}
		if json.Unmarshal(res, &r) == nil {
			if gws, ok := parseGateways(r.Gateways); ok {
				t.mu.Lock()
				t.gws = gws
				t.mu.Unlock()
			}
		}
	}
	t.kick()
}

func (t *tray) loop() {
	tick := time.NewTicker(15 * time.Second)
	defer tick.Stop()
	t.render()
	for {
		select {
		case <-t.notify:
			t.render()
		case <-tick.C:
			go t.refresh()
			t.render()
		case <-t.stop:
			return
		}
	}
}

func (t *tray) showFlash(msg string) {
	t.mu.Lock()
	t.flash = sanitize(msg, 80)
	t.flashUntil = time.Now().Add(8 * time.Second)
	t.mu.Unlock()
	t.kick()
	time.AfterFunc(8*time.Second+50*time.Millisecond, t.kick)
}

// render applies the current state to the menu; only loop() calls it.
func (t *tray) render() {
	t.mu.Lock()
	st, have, gws, busy := t.st, t.haveStatus, t.gws, t.gwBusy
	flash := ""
	if time.Now().Before(t.flashUntil) {
		flash = t.flash
	}
	entries, more := connectEntries(gws, st)
	t.entries = entries
	t.mu.Unlock()

	line := "Starting…"
	if have {
		line = statusLine(st)
	}
	if flash != "" {
		line = flash
	}
	goos := runtime.GOOS
	t.apply(t.status, itemState{title: menuText(goos, line), shown: true})
	pl := ""
	if have {
		pl = problemLine(st)
	}
	t.apply(t.problems, itemState{title: menuText(goos, pl), shown: pl != "", enabled: true})
	tip := "PrivateVPN — " + line
	if have && st.Problems > 0 && flash == "" {
		tip += " (" + strconv.Itoa(st.Problems) + " " + pluralProblems(st.Problems) + ")"
	}
	if tip != t.tooltip {
		t.tooltip = tip
		systray.SetTooltip(tip)
	}
	if k := iconFor(st); !t.iconSet || k != t.icon {
		t.setIcon(k)
	}
	t.apply(t.gateway, itemState{title: "Gateway mode", shown: true, enabled: have && !busy, checked: st.GatewayEnabled})
	t.apply(t.disconnect, itemState{title: "Disconnect", shown: true, enabled: canDisconnect(st.ClientState)})
	t.apply(t.copyKey, itemState{title: "Copy my gateway key", shown: st.GatewayNetworkID != "", enabled: true})
	t.apply(t.none, itemState{title: "No gateways found", shown: len(entries) == 0})
	for i, it := range t.slots {
		if i < len(entries) {
			e := entries[i]
			t.apply(it, itemState{title: menuText(goos, e.Title), shown: true, enabled: !e.Disabled, checked: e.Checked})
		} else {
			t.apply(it, itemState{title: "-", shown: false})
		}
	}
	moreTitle := "More…"
	if more > 0 {
		moreTitle = "More… (" + strconv.Itoa(more) + " in PrivateVPN)"
	}
	t.apply(t.more, itemState{title: moreTitle, shown: more > 0, enabled: true})
}

// apply changes only what differs from the last applied state.
func (t *tray) apply(it *systray.MenuItem, want itemState) {
	cur := t.applied[it]
	if cur == nil {
		cur = &itemState{}
		t.applied[it] = cur
	}
	first := !cur.applied
	if first || cur.title != want.title {
		it.SetTitle(want.title)
	}
	if first || cur.enabled != want.enabled {
		if want.enabled {
			it.Enable()
		} else {
			it.Disable()
		}
	}
	if first || cur.checked != want.checked {
		if want.checked {
			it.Check()
		} else {
			it.Uncheck()
		}
	}
	if first || cur.shown != want.shown {
		if want.shown {
			it.Show()
		} else {
			it.Hide()
		}
	}
	want.applied = true
	*cur = want
}

func (t *tray) setIcon(k iconKind) {
	t.icon, t.iconSet = k, true
	name := iconNames[k]
	switch runtime.GOOS {
	case "darwin":
		systray.SetTemplateIcon(mustIcon(name+"_template.png"), mustIcon(name+".png"))
	case "windows":
		systray.SetIcon(mustIcon(name + ".ico"))
	default:
		systray.SetIcon(mustIcon(name + ".png"))
	}
}

// --- actions ---------------------------------------------------------------

// openUI opens the web UI with a fresh single-use login link. extra is
// appended to the fragment (e.g. "unlock=<gateway id>").
func (t *tray) openUI(extra string) {
	if t.o.LoginURL == nil {
		return
	}
	u := t.o.LoginURL()
	if extra != "" {
		u += "&" + extra
	}
	if err := OpenBrowser(u); err != nil {
		t.showFlash("Could not open the browser")
	}
}

func argsJSON(m map[string]string) []byte {
	b, _ := json.Marshal(m)
	return b
}

func (t *tray) selectSlot(i int) {
	t.mu.Lock()
	if i >= len(t.entries) {
		t.mu.Unlock()
		return
	}
	e := t.entries[i]
	t.mu.Unlock()
	unlock := "unlock=" + url.QueryEscape(e.ID)
	switch {
	case e.Locked:
		t.openUI(unlock)
		return
	case e.Disabled:
		return
	case e.Checked:
		t.openUI("")
		return
	}
	_, err := t.o.Backend.Call(api.ClientConnect, argsJSON(map[string]string{"gateway_id": e.ID}))
	if err != nil {
		switch err.Code {
		case api.CodeLocked:
			t.openUI(unlock)
		case api.CodeElevation:
			t.showFlash("Administrator approval is needed to connect")
		default:
			t.showFlash("Could not connect: " + err.Message)
		}
	}
	t.refresh()
}

func (t *tray) toggleGateway() {
	t.mu.Lock()
	if t.gwBusy || !t.haveStatus {
		t.mu.Unlock()
		return
	}
	on := t.st.GatewayEnabled
	t.gwBusy = true
	t.mu.Unlock()
	t.kick()
	method := api.GatewayEnable
	if on {
		method = api.GatewayDisable
	}
	_, err := t.o.Backend.Call(method, nil)
	t.mu.Lock()
	t.gwBusy = false
	t.mu.Unlock()
	switch {
	case err != nil:
		t.showFlash("Gateway mode: " + err.Message)
	case !on:
		t.showFlash("Gateway on — members' traffic exits with your public IP")
	}
	t.refresh()
}

func (t *tray) disconnectClient() {
	// Removing the tunnel and its block may start the tunnel helper (an
	// administrator prompt), so say what is happening while it runs.
	t.showFlash("Disconnecting… (your system may ask for administrator approval)")
	if _, err := t.o.Backend.Call(api.ClientDisconnect, nil); err != nil {
		t.showFlash("Could not disconnect: " + err.Message)
	} else {
		t.showFlash("Disconnected — not protected (VPN off)")
	}
	t.refresh()
}

// quitApp is the user's explicit Quit: app.quit disconnects (removing the
// kill switch's block, possibly after an administrator prompt), forgets the
// auto-reconnect target, closes the engine and then ends the tray through
// Platform.Quit. Ending the tray here first would close the engine the
// "shutdown" way, which deliberately keeps the block.
func (t *tray) quitApp() {
	t.mu.Lock()
	if t.quitting {
		t.mu.Unlock()
		return
	}
	t.quitting = true
	active := canDisconnect(t.st.ClientState)
	t.mu.Unlock()
	if active {
		t.showFlash("Disconnecting… (your system may ask for administrator approval)")
	} else {
		t.showFlash("Quitting…")
	}
	_, err := t.o.Backend.Call(api.AppQuit, nil)
	if err == nil {
		// The engine calls Platform.Quit when it is done. Should that not
		// happen (e.g. the administrator prompt was left open), let a later
		// click send app.quit again.
		time.AfterFunc(2*time.Minute, func() {
			t.mu.Lock()
			t.quitting = false
			t.mu.Unlock()
		})
		return
	}
	switch err.Code {
	case api.CodeNotFound, api.CodeConflict:
		// No app.quit in this backend, or the engine is already shutting down.
		Quit()
	default:
		t.mu.Lock()
		t.quitting = false
		t.mu.Unlock()
		t.showFlash("Could not quit: " + err.Message)
	}
}

func pluralProblems(n int) string {
	if n == 1 {
		return "problem"
	}
	return "problems"
}

func (t *tray) copyGatewayKey() {
	t.mu.Lock()
	id := t.st.GatewayNetworkID
	t.mu.Unlock()
	if id == "" {
		return
	}
	res, err := t.o.Backend.Call(api.KeyringReveal, argsJSON(map[string]string{"id": id}))
	if err != nil {
		t.showFlash("Could not read the key: " + err.Message)
		return
	}
	var r struct {
		KeyText string `json:"key_text"`
	}
	if json.Unmarshal(res, &r) != nil || r.KeyText == "" {
		t.showFlash("Could not read the key")
		return
	}
	if cerr := CopyToClipboard(r.KeyText); cerr != nil {
		t.showFlash("Could not copy: no clipboard tool available")
		return
	}
	t.showFlash("Gateway key copied — share it only with people you trust")
}
