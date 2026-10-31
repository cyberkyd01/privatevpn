//go:build !android

package engine

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
	_ "time/tzdata" // manual time zones on Windows need the IANA database

	"github.com/cyberkyd01/privatevpn/core/api"
	"github.com/cyberkyd01/privatevpn/core/beacon"
	"github.com/cyberkyd01/privatevpn/core/control"
	"github.com/cyberkyd01/privatevpn/core/gateway"
	"github.com/cyberkyd01/privatevpn/core/geo"
	"github.com/cyberkyd01/privatevpn/core/netbind"
	"github.com/cyberkyd01/privatevpn/core/netkey"
	"github.com/cyberkyd01/privatevpn/core/state"
	"github.com/cyberkyd01/privatevpn/core/sysinfo"
	"github.com/cyberkyd01/privatevpn/core/wire"
)

const gatewayMTU = 1280

// gatewayRole is a running gateway (gateway engine + control + beacons + geo).
type gatewayRole struct {
	c        *core
	gw       *gateway.Gateway
	ctrl     *control.Server
	sender   *beacon.Sender
	geo      *geo.Refresher
	netID    string
	sub      netkey.Subkeys
	pub      [32]byte
	subnet   netip.Prefix
	started  time.Time
	ctrlPort int

	mu       sync.Mutex
	hostDeny []netip.Prefix
	firewall string // present | missing | unknown | n/a
}

func init() {
	handle(api.GatewayEnable, func(c *core, _ []byte) (any, *api.Error) { return nil, c.gatewayEnable() })
	handle(api.GatewayDisable, func(c *core, _ []byte) (any, *api.Error) { return nil, c.gatewayDisable() })
	handle(api.GatewaySetNetwork, (*core).gatewaySetNetwork)
	handle(api.GatewayResetKey, (*core).gatewayResetKey)
	handle(api.FirewallAdd, (*core).firewallAdd)
}

func publicKey(priv []byte) ([32]byte, error) {
	var pub [32]byte
	k, err := ecdh.X25519().NewPrivateKey(priv)
	if err != nil {
		return pub, err
	}
	copy(pub[:], k.PublicKey().Bytes())
	return pub, nil
}

func parseVersion(v string) [3]byte {
	var out [3]byte
	parts := strings.SplitN(strings.TrimPrefix(v, "v"), ".", 3)
	for i, p := range parts {
		if j := strings.IndexFunc(p, func(r rune) bool { return r < '0' || r > '9' }); j >= 0 {
			p = p[:j]
		}
		if n, err := strconv.Atoi(p); err == nil && n >= 0 && n < 256 {
			out[i] = byte(n)
		}
	}
	return out
}

// ensureNetwork returns the keyring entry this gateway serves, creating a
// network when none is bound (§5.1).
func (c *core) ensureNetwork() (state.KeyEntry, *api.Error) {
	st := c.store.Get()
	if k, ok := c.keyEntry(st.Gateway.NetworkID); ok {
		return k, nil
	}
	var pick string
	for _, k := range st.Keyring {
		if k.CreatedHere {
			pick = k.ID
			break
		}
	}
	if pick == "" {
		k, err := netkey.Generate()
		if err != nil {
			return state.KeyEntry{}, api.Internal(err)
		}
		id, _, aerr := c.addKey(k, "My network", true)
		if aerr != nil {
			return state.KeyEntry{}, aerr
		}
		pick = id
		c.log.Printf("keyring", "created network for this gateway")
	}
	c.store.Update(func(st *state.State) error {
		st.Gateway.NetworkID = pick
		return nil
	})
	k, _ := c.keyEntry(pick)
	return k, nil
}

func (c *core) gatewayEnable() *api.Error {
	c.opMu.Lock()
	defer c.opMu.Unlock()
	return c.gatewayEnableLocked()
}

// gatewayEnableLocked starts the gateway role; opMu held.
func (c *core) gatewayEnableLocked() *api.Error {
	select {
	case <-c.stop:
		return api.Errf(api.CodeConflict, http.StatusConflict, "shutting down")
	default:
	}
	c.mu.Lock()
	running, connected := c.gw != nil, c.sess != nil
	c.mu.Unlock()
	if running {
		return nil
	}
	if connected && !netbind.CanMark() {
		// Without the mark every forwarded flow and off-LAN reply would
		// enter the upstream tunnel or fail closed (§7.4, D12).
		return api.Errf(api.CodeConflict, http.StatusConflict,
			"dual role on Linux needs CAP_NET_ADMIN (setcap cap_net_admin+ep privatevpn); disconnect before enabling gateway mode")
	}
	k, aerr := c.ensureNetwork()
	if aerr != nil {
		return aerr
	}
	st := c.store.Get()
	g := st.Gateway
	priv := g.PrivateKey
	if len(priv) != 32 {
		key, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			return api.Internal(err)
		}
		priv = key.Bytes()
	}
	pub, err := publicKey(priv)
	if err != nil {
		return api.Internal(err)
	}
	subnet := gateway.DeriveSubnet(pub)
	if g.Subnet != "" {
		if p, err := netip.ParsePrefix(g.Subnet); err == nil {
			subnet = p.Masked()
		}
	}
	sub := c.subkeysFor(k)
	r := &gatewayRole{c: c, netID: k.ID, sub: sub, pub: pub, subnet: subnet, started: time.Now(),
		ctrlPort: g.CtrlPort, firewall: "n/a"}
	r.refreshHostDeny()

	var privArr [32]byte
	copy(privArr[:], priv)
	gw, err := gateway.Start(gateway.Config{
		PrivateKey: privArr, PresharedKey: sub.PSK, ListenPort: g.WGPort, Subnet: subnet,
		MTU: gatewayMTU, LANAccess: g.LANAccess, DNSUpstreams: c.dnsUpstreams,
		ExtraDeny: r.extraDeny, EndpointHook: c.endpointHook, Log: c.log,
	})
	if err != nil {
		return api.Errf(api.CodeConflict, http.StatusConflict, "cannot start the gateway on UDP %d: %s", g.WGPort, errClass(err))
	}
	r.gw = gw
	// Everything the control handler (Join/Info) reads must exist before
	// the listener starts serving.
	r.geo = geo.NewRefresher(geo.Options{
		Enabled:   func() bool { s := c.store.Get(); return s.Gateway != nil && s.Gateway.Geo.Enabled },
		Manual:    c.geoManual,
		UserAgent: "PrivateVPN/" + c.e.opts.AppVersion,
		Client:    geo.NewHTTPClient(netbind.Dialer(10 * time.Second).DialContext),
		Log:       c.log,
		OnUpdate:  c.emitStatus,
	})
	ctrl, err := control.Listen(control.ServerConfig{Port: g.CtrlPort, ControlKey: sub.Control, GatewayPub: pub, Handler: r, Log: c.log})
	if err != nil {
		gw.Close()
		return api.Errf(api.CodeConflict, http.StatusConflict, "cannot listen on UDP %d: %s", g.CtrlPort, errClass(err))
	}
	r.ctrl = ctrl
	r.sender = beacon.StartSender(ctrl.Conn(), r.buildBeacon, c.log)
	r.geo.Start()

	c.store.Update(func(st *state.State) error {
		st.Gateway.Enabled = true
		st.Gateway.PrivateKey = priv
		return nil
	})
	c.table.SetSelf(pub)
	c.mu.Lock()
	c.gw = r
	c.mu.Unlock()
	c.log.Printf("gateway", "enabled (wg %d, ctrl %d, subnet %s)", gw.ListenPort(), r.ctrlPort, subnet)
	go r.checkFirewall(true)
	c.emitStatus()
	c.gatewaysChanged()
	c.emitKeyring()
	return nil
}

// gatewayStop shuts the running gateway down without changing settings.
func (c *core) gatewayStop() {
	c.mu.Lock()
	r := c.gw
	c.gw = nil
	c.mu.Unlock()
	if r == nil {
		return
	}
	r.sender.Stop()
	r.geo.Stop()
	r.ctrl.Close()
	r.gw.Close()
	c.table.SetSelf([32]byte{})
	c.log.Printf("gateway", "disabled")
}

func (c *core) gatewayDisable() *api.Error {
	c.opMu.Lock()
	defer c.opMu.Unlock()
	c.gatewayStop()
	c.store.Update(func(st *state.State) error {
		st.Gateway.Enabled = false
		return nil
	})
	c.emitStatus()
	c.gatewaysChanged()
	return nil
}

// restartGateway applies changed settings to a running gateway. Stop and
// start happen under one opMu hold so no other transition interleaves.
func (c *core) restartGateway() *api.Error {
	c.opMu.Lock()
	defer c.opMu.Unlock()
	c.mu.Lock()
	running := c.gw != nil
	c.mu.Unlock()
	if !running {
		return nil
	}
	c.gatewayStop()
	return c.gatewayEnableLocked()
}

func (c *core) gatewaySetNetwork(args []byte) (any, *api.Error) {
	a, aerr := decode[struct {
		KeyringID string `json:"keyring_id"`
	}](args)
	if aerr != nil {
		return nil, aerr
	}
	if _, ok := c.keyEntry(a.KeyringID); !ok {
		return nil, api.NotFound("network")
	}
	c.store.Update(func(st *state.State) error {
		st.Gateway.NetworkID = a.KeyringID
		return nil
	})
	if aerr := c.restartGateway(); aerr != nil {
		return nil, aerr
	}
	c.keyringChanged()
	return nil, nil
}

func (c *core) gatewayResetKey(_ []byte) (any, *api.Error) {
	st := c.store.Get()
	ke, ok := c.keyEntry(st.Gateway.NetworkID)
	if !ok {
		return nil, api.Errf(api.CodeConflict, http.StatusConflict, "this gateway does not serve a network yet")
	}
	k, err := netkey.Generate()
	if err != nil {
		return nil, api.Internal(err)
	}
	c.store.Update(func(st *state.State) error {
		for i := range st.Keyring {
			if st.Keyring[i].ID == ke.ID {
				st.Keyring[i].Key = append([]byte(nil), k[:]...)
			}
		}
		return nil
	})
	c.mu.Lock()
	delete(c.subkeys, ke.ID)
	c.mu.Unlock()
	c.log.Printf("keyring", "gateway key reset; members must enter the new key")
	if aerr := c.restartGateway(); aerr != nil {
		return nil, aerr
	}
	c.keyringChanged()
	return map[string]any{"key_text": k.Text()}, nil
}

func (c *core) firewallAdd(_ []byte) (any, *api.Error) {
	if c.e.opts.Platform.FirewallAdd == nil {
		return nil, api.Unsupported()
	}
	if err := c.e.opts.Platform.FirewallAdd(); err != nil {
		return nil, api.Errf(api.CodeElevation, http.StatusForbidden, "could not add the firewall rule: %s", errClass(err))
	}
	c.mu.Lock()
	r := c.gw
	c.mu.Unlock()
	if r != nil {
		r.checkFirewall(false)
	}
	c.emitStatus()
	return nil, nil
}

func (r *gatewayRole) checkFirewall(autoAdd bool) {
	p := r.c.e.opts.Platform
	if p.FirewallCheck == nil {
		return
	}
	present, err := p.FirewallCheck()
	state := "unknown"
	if err == nil {
		state = map[bool]string{true: "present", false: "missing"}[present]
	}
	if state == "missing" && autoAdd && p.FirewallAdd != nil {
		if err := p.FirewallAdd(); err == nil {
			if ok, err := p.FirewallCheck(); err == nil && ok {
				state = "present"
			}
		}
	}
	r.mu.Lock()
	r.firewall = state
	r.mu.Unlock()
	r.c.emitStatus()
}

func (c *core) geoManual() *geo.Manual {
	st := c.store.Get()
	if st.Gateway == nil || st.Gateway.Geo.Manual == nil {
		return nil
	}
	m := st.Gateway.Geo.Manual
	out := &geo.Manual{Country: m.Country, Region: m.Region, City: m.City, TZName: m.TZName}
	if m.Lat != nil && m.Lon != nil {
		out.Lat, out.Lon, out.HasCoords = *m.Lat, *m.Lon, true
	}
	return out
}

// dnsUpstreams is called by the gateway's DNS forwarder for every query.
func (c *core) dnsUpstreams() []netip.AddrPort {
	st := c.store.Get()
	var out []netip.AddrPort
	if st.Gateway != nil {
		for _, s := range st.Gateway.DNSUpstream {
			if ip, err := netip.ParseAddr(s); err == nil {
				out = append(out, netip.AddrPortFrom(ip, 53))
			}
		}
	}
	if len(out) > 0 {
		return out
	}
	c.mu.Lock()
	dual := c.sess != nil
	c.mu.Unlock()
	for _, ap := range sysinfo.Resolvers() {
		ip := ap.Addr()
		if dual && (ip.IsLoopback() || ip.IsPrivate()) {
			continue // our own resolver may now point into the client tunnel
		}
		if ip.Is4() && !strings.HasPrefix(ip.String(), "10.77.") {
			out = append(out, ap)
		}
	}
	return out
}

// endpointHook adds/removes /32 routes for off-LAN clients in dual role.
func (c *core) endpointHook(ep netip.Addr, add bool) {
	c.mu.Lock()
	s, t := c.sess, c.tun
	c.mu.Unlock()
	if s == nil || t == nil {
		return
	}
	if add {
		t.RouteAdd(ep)
	} else {
		t.RouteDel(ep)
	}
}

func (r *gatewayRole) refreshHostDeny() {
	var deny []netip.Prefix
	for _, a := range sysinfo.HostAddrs() {
		deny = append(deny, netip.PrefixFrom(a, a.BitLen()))
	}
	r.mu.Lock()
	r.hostDeny = deny
	r.mu.Unlock()
}

func (r *gatewayRole) extraDeny() []netip.Prefix {
	r.mu.Lock()
	out := append([]netip.Prefix(nil), r.hostDeny...)
	r.mu.Unlock()
	r.c.mu.Lock()
	s := r.c.sess
	r.c.mu.Unlock()
	if s != nil {
		s.mu.Lock()
		if s.resp.Assigned.IsValid() {
			out = append(out, netip.PrefixFrom(s.resp.Assigned, 24).Masked())
		}
		s.mu.Unlock()
	}
	return out
}

func (r *gatewayRole) refreshPolicy() { r.gw.RefreshPolicy() }

func (r *gatewayRole) networkChanged() {
	r.refreshHostDeny()
	r.gw.RefreshPolicy()
	r.geo.NetworkChanged()
	r.c.mu.Lock()
	s := r.c.sess
	r.c.mu.Unlock()
	ifname := ""
	if s != nil {
		s.mu.Lock()
		ifname = s.ifname
		s.mu.Unlock()
	}
	netbind.RefreshPhysical(ifname)
}

func osCode() byte {
	switch runtime.GOOS {
	case "windows":
		return wire.OSWindows
	case "darwin":
		return wire.OSMacOS
	}
	return wire.OSLinux
}

func (r *gatewayRole) dualRole() bool {
	r.c.mu.Lock()
	defer r.c.mu.Unlock()
	return r.c.sess != nil
}

func (r *gatewayRole) buildBeacon() (wire.Beacon, [32]byte) {
	st := r.c.store.Get()
	flags := uint16(wire.BeaconAccepting | wire.BeaconDetails)
	if r.gw.LANAccess() {
		flags |= wire.BeaconLANAccess
	}
	if r.dualRole() {
		flags |= wire.BeaconDualRole
	}
	n := r.gw.ClientCount()
	if n > 255 {
		n = 255
	}
	b := wire.Beacon{GatewayPub: r.pub, WGPort: uint16(r.gw.ListenPort()), CtrlPort: uint16(r.ctrlPort),
		Flags: flags, OS: osCode(), ClientCount: byte(n), AppVersion: parseVersion(r.c.e.opts.AppVersion),
		Name: st.DeviceName}
	return b, r.sub.Beacon
}

// ---- control.Handler ----

func (r *gatewayRole) Join(pub [32]byte, mtuHint int) (control.JoinResult, wire.ErrCode) {
	l, err := r.gw.Join(pub, mtuHint)
	switch {
	case errors.Is(err, gateway.ErrPoolFull):
		return control.JoinResult{}, wire.ErrPoolFull
	case err != nil:
		return control.JoinResult{}, wire.ErrNotAccepting
	}
	go r.c.emitStatus()
	return control.JoinResult{Assigned: l.IP, GatewayIP: l.GatewayIP, DNS: l.GatewayIP, WGPort: r.gw.ListenPort(),
		MTU: l.MTU, Keepalive: 25, LeaseSec: l.LeaseSec, Token: l.Token, LANAccess: l.LANAccess}, wire.ErrNone
}

func (r *gatewayRole) Renew(pub [32]byte, token [16]byte) (uint32, bool, wire.ErrCode) {
	l, err := r.gw.Renew(pub, token)
	if err != nil {
		return 0, false, wire.ErrUnknownLease
	}
	return l.LeaseSec, l.LANAccess, wire.ErrNone
}

func (r *gatewayRole) Leave(pub [32]byte, token [16]byte) {
	if r.gw.Leave(pub, token) == nil {
		go r.c.emitStatus()
	}
}

// Info builds the §10.5 document (≤ 1100 bytes).
func (r *gatewayRole) Info() []byte {
	g, stale := r.geo.Current()
	st := r.c.store.Get()
	tzName, off, abbr := sysinfo.TimeZone()
	if tzName == "" {
		tzName = g.TZName
	}
	lan := []string{}
	for _, ip := range sysinfo.LANIPv4s() {
		lan = append(lan, ip.String())
	}
	doc := map[string]any{
		"v": 1, "pubkey": pubID(r.pub), "name": st.DeviceName, "os": sysinfo.OSName(),
		"os_version": sysinfo.OSVersion(), "app_version": r.c.e.opts.AppVersion,
		"uptime_sec": int64(sysinfo.Uptime().Seconds()), "gateway_uptime_sec": int64(time.Since(r.started).Seconds()),
		"client_count": r.gw.ClientCount(), "lan_access": r.gw.LANAccess(), "dual_role": r.dualRole(),
		"subnet": r.subnet.String(), "mtu": gatewayMTU, "wg_port": r.gw.ListenPort(), "ctrl_port": r.ctrlPort,
		"lan_ips": lan, "public_ip": addrStr(g.PublicIP), "public_ip6": addrStr(g.PublicIP6),
		"public_ip_checked_at": unixOr0(g.CheckedAt), "stale": stale, "nat": natHint(g.PublicIP),
		"tz":  map[string]any{"name": tzName, "utc_offset_sec": off, "abbrev": abbr},
		"now": time.Now().Unix(),
	}
	gd := map[string]any{"source": g.Source, "provider": g.Provider, "country": g.Country,
		"country_code": g.CountryCode, "region": g.Region, "city": g.City, "isp": g.ISP, "asn": g.ASN,
		"accuracy_km": g.AccuracyKm, "checked_at": unixOr0(g.CheckedAt)}
	if g.HasCoords {
		gd["lat"], gd["lon"] = g.Lat, g.Lon
	}
	doc["geo"] = gd
	b, _ := json.Marshal(doc)
	for _, drop := range []func(){
		func() { delete(gd, "isp") }, func() { delete(gd, "asn") }, func() { delete(doc, "os_version") },
		func() {
			if len(lan) > 2 {
				doc["lan_ips"] = lan[:2]
			}
		},
		func() { delete(gd, "provider") },
	} {
		if len(b) <= wire.MaxInfoJSON {
			break
		}
		drop()
		b, _ = json.Marshal(doc)
	}
	if len(b) > wire.MaxInfoJSON {
		b, _ = json.Marshal(map[string]any{"v": 1, "pubkey": pubID(r.pub), "now": time.Now().Unix()})
	}
	return b
}

func addrStr(a netip.Addr) string {
	if !a.IsValid() {
		return ""
	}
	return a.String()
}

func unixOr0(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}

var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// natHint derives the §10.4 reachability hint.
func natHint(public netip.Addr) string {
	for _, ip := range sysinfo.LANIPv4s() {
		if cgnat.Contains(ip) {
			return "cgnat"
		}
	}
	if !public.IsValid() {
		return "unknown"
	}
	for _, a := range sysinfo.HostAddrs() {
		if a == public {
			return "none"
		}
	}
	return "nat"
}

// gatewayStatus is the gateway part of status.get.
func (c *core) gatewayStatus(st state.State) map[string]any {
	c.mu.Lock()
	r := c.gw
	c.mu.Unlock()
	g := st.Gateway
	out := map[string]any{"enabled": r != nil, "network": nil, "clients": 0, "uptime_sec": 0,
		"wg_port": g.WGPort, "ctrl_port": g.CtrlPort, "subnet": g.Subnet, "lan_access": g.LANAccess,
		"firewall_rule": "n/a", "nat": "unknown", "public_ip": ""}
	if k, ok := c.keyEntry(g.NetworkID); ok {
		out["network"] = map[string]any{"id": k.ID, "label": k.Label}
	}
	if r == nil {
		return out
	}
	gr, _ := r.geo.Current()
	r.mu.Lock()
	fw := r.firewall
	r.mu.Unlock()
	out["clients"] = r.gw.ClientCount()
	out["uptime_sec"] = int64(time.Since(r.started).Seconds())
	out["wg_port"] = r.gw.ListenPort()
	out["ctrl_port"] = r.ctrlPort
	out["subnet"] = r.subnet.String()
	out["lan_access"] = r.gw.LANAccess()
	out["firewall_rule"] = fw
	out["nat"] = natHint(gr.PublicIP)
	out["public_ip"] = addrStr(gr.PublicIP)
	out["fingerprint"] = fingerprint(r.pub)
	return out
}

func (c *core) selfItem() *gwItem {
	c.mu.Lock()
	r := c.gw
	c.mu.Unlock()
	if r == nil {
		return nil
	}
	st := c.store.Get()
	it := &gwItem{ID: pubID(r.pub), Name: clean(st.DeviceName, 32), OS: sysinfo.OSName(),
		AppVersion: r.c.e.opts.AppVersion, Online: true, ClientCount: r.gw.ClientCount(),
		Flags:  gwFlags{Accepting: true, LANAccess: r.gw.LANAccess(), DualRole: r.dualRole()},
		Access: "member", Endpoints: []gwEndpoint{}, Fingerprint: fingerprint(r.pub),
		FirstSeen: r.started.Unix(), IsSelf: true}
	if k, ok := c.keyEntry(r.netID); ok {
		it.Network = &gwNetwork{ID: k.ID, Label: k.Label}
	}
	return it
}

// applyLANAccess updates a running gateway after a settings change.
func (c *core) applyLANAccess(on bool) {
	c.mu.Lock()
	r := c.gw
	c.mu.Unlock()
	if r != nil {
		r.gw.SetLANAccess(on)
	}
}

func (c *core) applyMobileInfo() {}
