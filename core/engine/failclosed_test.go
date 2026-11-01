package engine

import (
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cyberkyd01/private-vpn-pro/core/eventlog"
	"github.com/cyberkyd01/private-vpn-pro/core/tunnel"
)

// pair starts a gateway engine and a client engine (using tun) that holds
// the gateway's key; it returns the gateway's list id for client.connect.
func pair(t *testing.T, tun *nsTunnel) (gw, cl *Engine, gwID string) {
	t.Helper()
	gw = newTestEngine(t)
	wgPort, ctrlPort := freeUDPPorts(t)
	if _, code := call(t, gw, "settings.set", map[string]any{"gateway": map[string]any{
		"wg_port": wgPort, "ctrl_port": ctrlPort, "geo": map[string]any{"enabled": false}}}); code != "" {
		t.Fatal("settings:", code)
	}
	if _, code := call(t, gw, "gateway.enable", nil); code != "" {
		t.Fatal("enable:", code)
	}
	netID := status(t, gw)["gateway"].(map[string]any)["network"].(map[string]any)["id"].(string)
	rv, _ := call(t, gw, "keyring.reveal", map[string]any{"id": netID})

	var err error
	cl, err = New(Options{DataDir: t.TempDir(), AppVersion: "1.0.0", Log: eventlog.New(200),
		Platform: Platform{NewTunnel: func() (tunnel.Tunnel, error) { return tun, nil }}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cl.Close)
	res, _ := call(t, cl, "gateways.manual_add", map[string]any{"host": "127.0.0.1", "ctrl_port": ctrlPort})
	res, code := call(t, cl, "gateways.unlock", map[string]any{"gateway_id": "m-" + res["id"].(string), "key_text": rv["key_text"]})
	if code != "" {
		t.Fatal("unlock:", code)
	}
	return gw, cl, res["gateway_id"].(string)
}

// connectedPair starts a gateway engine and a client engine connected to it
// through a userspace tunnel.
func connectedPair(t *testing.T) (gw, cl *Engine, tun *nsTunnel) {
	t.Helper()
	tun = &nsTunnel{}
	gw, cl, gwID := pair(t, tun)
	if _, code := call(t, cl, "client.connect", map[string]any{"gateway_id": gwID}); code != "" {
		t.Fatal("connect:", code)
	}
	waitUntil(t, func() bool { return clientState(t, cl) == "connected" })
	return gw, cl, tun
}

func clientState(t *testing.T, e *Engine) string {
	return status(t, e)["client"].(map[string]any)["state"].(string)
}

func hasProblem(t *testing.T, e *Engine, code string) bool {
	for _, p := range status(t, e)["problems"].([]any) {
		if p.(map[string]any)["code"] == code {
			return true
		}
	}
	return false
}

func shortTimers(t *testing.T) {
	ri, rj := renewNs.Load(), rejoinNs.Load()
	renewNs.Store(int64(300 * time.Millisecond))
	rejoinNs.Store(int64(300 * time.Millisecond))
	t.Cleanup(func() { renewNs.Store(ri); rejoinNs.Store(rj) })
}

// The gateway going offline must hold traffic in the tunnel (never fall back
// to the physical network) and recover by itself when it returns.
func TestGatewayOfflineHoldsTunnel(t *testing.T) {
	shortTimers(t)
	gw, cl, tun := connectedPair(t)
	call(t, gw, "gateway.disable", nil)
	waitUntil(t, func() bool { return clientState(t, cl) == "degraded" })
	tun.mu.Lock()
	up, downs := tun.dev != nil, tun.downs
	tun.mu.Unlock()
	if !up || downs != 0 {
		t.Fatalf("tunnel removed while the gateway was offline (up=%v downs=%d): traffic would leak", up, downs)
	}
	if !hasProblem(t, cl, "degraded") {
		t.Fatal("degraded state not listed as a problem")
	}
	if _, code := call(t, gw, "gateway.enable", nil); code != "" {
		t.Fatal("re-enable:", code)
	}
	waitUntil(t, func() bool { return clientState(t, cl) == "connected" })
}

// A dead tunnel process leaves the session blocked; Disconnect removes the
// block through a fresh tunnel and clears the persisted flag.
func TestTunnelLostStaysBlocked(t *testing.T) {
	_, cl, tun := connectedPair(t)
	if st := cl.core.store.Get(); !st.Client.KillSwitchEngaged {
		t.Fatal("kill switch not recorded as engaged while connected")
	}
	tun.mu.Lock()
	tun.failStatus = true
	tun.mu.Unlock()
	waitUntil(t, func() bool { return clientState(t, cl) == "blocked" })
	if tun.downs != 0 {
		t.Fatal("tunnel torn down after the tunnel process died")
	}
	if !hasProblem(t, cl, "blocked") {
		t.Fatal("blocked state not listed as a problem")
	}
	if _, code := call(t, cl, "client.disconnect", nil); code != "" {
		t.Fatal("disconnect:", code)
	}
	if tun.downs != 1 {
		t.Fatalf("Down calls = %d, want 1", tun.downs)
	}
	if cl.core.store.Get().Client.KillSwitchEngaged || clientState(t, cl) != "idle" {
		t.Fatal("block not released after Disconnect")
	}
}

// A block left by a crashed run is reported at start and released by
// Disconnect.
func TestLeftoverBlockReported(t *testing.T) {
	dir := t.TempDir()
	doc, _ := json.Marshal(map[string]any{"schema": 2, "client": map[string]any{
		"kill_switch": true, "allow_lan": true, "kill_switch_engaged": true}})
	os.WriteFile(filepath.Join(dir, "state.json"), doc, 0o600)
	tun := &nsTunnel{}
	e, err := New(Options{DataDir: dir, AppVersion: "1.0.0", Log: eventlog.New(50),
		Platform: Platform{NewTunnel: func() (tunnel.Tunnel, error) { return tun, nil }}})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if clientState(t, e) != "blocked" || !hasProblem(t, e, "kill_switch_engaged") {
		t.Fatal("leftover block not reported")
	}
	if _, code := call(t, e, "client.disconnect", nil); code != "" {
		t.Fatal(code)
	}
	if tun.downs != 1 || clientState(t, e) != "idle" || hasProblem(t, e, "kill_switch_engaged") {
		t.Fatal("leftover block not released")
	}
}

// An OS shutdown (Engine.Close) keeps the tunnel's block and the resume
// target; the next start reconnects by itself. An explicit quit disconnects
// and forgets the target.
func TestSurvivesRestart(t *testing.T) {
	_, cl, tun := connectedPair(t)
	dir := cl.opts.DataDir
	if cl.core.store.Get().Client.ResumeGatewayID == "" {
		t.Fatal("resume target not recorded")
	}
	cl.Close() // shutdown / logoff / crash-like stop
	if tun.downs != 0 || !cl.core.store.Get().Client.KillSwitchEngaged {
		t.Fatal("shutdown removed the tunnel block; traffic would leak across the restart")
	}

	tun2 := &nsTunnel{}
	cl2, err := New(Options{DataDir: dir, AppVersion: "1.0.0", Log: eventlog.New(200),
		Platform: Platform{NewTunnel: func() (tunnel.Tunnel, error) { return tun2, nil }}})
	if err != nil {
		t.Fatal(err)
	}
	defer cl2.Close()
	if st := status(t, cl2); st["client"].(map[string]any)["state"] != "blocked" && st["client"].(map[string]any)["resume_pending"] != true {
		t.Fatalf("restart state not reported: %v", st["client"])
	}
	waitUntil(t, func() bool { return clientState(t, cl2) == "connected" })

	cl2.core.quit()
	if tun2.downs != 1 {
		t.Fatalf("explicit quit did not remove the tunnel (downs=%d)", tun2.downs)
	}
	st := cl2.core.store.Get().Client
	if st.ResumeGatewayID != "" || st.KillSwitchEngaged {
		t.Fatalf("quit left resume=%q engaged=%v", st.ResumeGatewayID, st.KillSwitchEngaged)
	}
}

func shortResume(t *testing.T) {
	f, r := resumeFirstNs.Load(), resumeRetryNs.Load()
	resumeFirstNs.Store(int64(200 * time.Millisecond))
	resumeRetryNs.Store(int64(200 * time.Millisecond))
	t.Cleanup(func() { resumeFirstNs.Store(f); resumeRetryNs.Store(r) })
}

// A tunnel that comes up but never handshakes (gateway firewall) is still a
// session the user wanted: the block is recorded as engaged and a restart
// comes back to this gateway, without waiting for a first handshake.
func TestResumeTargetSetAtTunnelUp(t *testing.T) {
	tun := &nsTunnel{breakPSK: true}
	_, cl, gwID := pair(t, tun)
	if _, code := call(t, cl, "client.connect", map[string]any{"gateway_id": gwID}); code != "" {
		t.Fatal("connect:", code)
	}
	waitUntil(t, func() bool { return clientState(t, cl) == "tunnel_up" })
	st := cl.core.store.Get().Client
	if st.ResumeGatewayID != gwID || !st.KillSwitchEngaged {
		t.Fatalf("after tunnel up: resume=%q engaged=%v", st.ResumeGatewayID, st.KillSwitchEngaged)
	}
	if _, code := call(t, cl, "client.disconnect", nil); code != "" {
		t.Fatal("disconnect:", code)
	}
	st = cl.core.store.Get().Client
	if st.ResumeGatewayID != "" || st.KillSwitchEngaged || tun.downs != 1 {
		t.Fatalf("after disconnect: resume=%q engaged=%v downs=%d", st.ResumeGatewayID, st.KillSwitchEngaged, tun.downs)
	}
}

// The native tunnels install the block before the adapter. When the first
// Up then fails and nothing was engaged before, the block it installed is
// lifted again (Down) and the UI reports an unprotected, not a blocked,
// device — the state file and the OS must agree.
func TestFailedFirstUpLiftsItsBlock(t *testing.T) {
	tun := &nsTunnel{failUp: true}
	_, cl, gwID := pair(t, tun)
	if _, code := call(t, cl, "client.connect", map[string]any{"gateway_id": gwID}); code != "" {
		t.Fatal("connect:", code)
	}
	waitUntil(t, func() bool { return clientState(t, cl) == "idle" && hasProblem(t, cl, "internal") })
	tun.mu.Lock()
	ups, downs := tun.ups, tun.downs
	tun.mu.Unlock()
	if ups != 1 || downs < 1 {
		t.Fatalf("ups=%d downs=%d: the block of the failed Up was not lifted", ups, downs)
	}
	if cl.core.store.Get().Client.KillSwitchEngaged || hasProblem(t, cl, "kill_switch_engaged") {
		t.Fatal("kill switch reported as engaged after a failed first Up")
	}
}

// With a block already engaged (left by a crash), a failed Up keeps it:
// Down is never called by itself, the state stays blocked and both the block
// and the reason are listed.
func TestFailedUpKeepsEngagedBlock(t *testing.T) {
	tun := &nsTunnel{failUp: true}
	_, cl, gwID := pair(t, tun)
	cl.core.setKillSwitchEngaged(true)
	if _, code := call(t, cl, "client.connect", map[string]any{"gateway_id": gwID}); code != "" {
		t.Fatal("connect:", code)
	}
	waitUntil(t, func() bool { return clientState(t, cl) == "blocked" && hasProblem(t, cl, "internal") })
	// nsTunnel.Close counts as a Down; a real helper keeps the block on Close.
	if !cl.core.store.Get().Client.KillSwitchEngaged || !hasProblem(t, cl, "kill_switch_engaged") {
		t.Fatal("engaged block not kept/reported after a failed Up")
	}
}

// After a restart the resume loop retries quietly while the gateway is not
// reachable, but once the tunnel stage fails (prompt declined, or the OS
// refused the tunnel) it stops: retrying would show the administrator
// prompt every few seconds. The block stays and the problems say why.
func TestResumeStopsAfterTunnelFailure(t *testing.T) {
	shortResume(t)
	_, cl, _ := connectedPair(t)
	dir := cl.opts.DataDir
	cl.Close() // OS shutdown: block kept, resume armed

	tun2 := &nsTunnel{failUp: true}
	cl2, err := New(Options{DataDir: dir, AppVersion: "1.0.0", Log: eventlog.New(200),
		Platform: Platform{NewTunnel: func() (tunnel.Tunnel, error) { return tun2, nil }}})
	if err != nil {
		t.Fatal(err)
	}
	defer cl2.Close()
	waitUntil(t, func() bool { tun2.mu.Lock(); defer tun2.mu.Unlock(); return tun2.ups >= 1 })
	waitUntil(t, func() bool { return hasProblem(t, cl2, "internal") })
	time.Sleep(6 * time.Duration(resumeRetryNs.Load()))
	tun2.mu.Lock()
	ups := tun2.ups
	tun2.mu.Unlock()
	if ups != 1 {
		t.Fatalf("resume kept retrying the tunnel stage (%d Up calls): every retry is an administrator prompt", ups)
	}
	st := status(t, cl2)
	if st["client"].(map[string]any)["state"] != "blocked" || st["client"].(map[string]any)["resume_pending"] == true ||
		!hasProblem(t, cl2, "kill_switch_engaged") {
		t.Fatalf("after the failed resume: %v", st["client"])
	}
	if !cl2.core.store.Get().Client.KillSwitchEngaged {
		t.Fatal("block released by a failed resume")
	}
}

func TestMergeEndpoints(t *testing.T) {
	a := netip.MustParseAddrPort("192.168.1.10:51821")
	b := netip.MustParseAddrPort("192.168.1.11:51821")
	c := netip.MustParseAddrPort("203.0.113.5:51821")
	got := mergeEndpoints([]netip.AddrPort{b, a, b, {}}, []netip.AddrPort{a, c})
	want := []netip.AddrPort{b, a, c}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
	if got := mergeEndpoints(nil, []netip.AddrPort{c}); len(got) != 1 || got[0] != c {
		t.Fatalf("nothing discovered: got %v", got)
	}
}
