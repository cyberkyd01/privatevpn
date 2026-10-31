package engine

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"net/http"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/cyberkyd01/privatevpn/core/api"
	"github.com/cyberkyd01/privatevpn/core/beacon"
	"github.com/cyberkyd01/privatevpn/core/control"
	"github.com/cyberkyd01/privatevpn/core/netkey"
	"github.com/cyberkyd01/privatevpn/core/state"
	"github.com/cyberkyd01/privatevpn/core/wire"
)

// manualRuntime is in-memory state of a manually added gateway.
type manualRuntime struct {
	addr     netip.AddrPort
	lastOK   time.Time
	lastTry  time.Time
	name     string
	os       string
	version  string
	clients  int
	resolved time.Time
}

type cachedInfo struct {
	at       time.Time
	doc      map[string]any
	endpoint string
}

type gwFlags struct {
	Accepting bool `json:"accepting"`
	LANAccess bool `json:"lan_access"`
	DualRole  bool `json:"dual_role"`
}

type gwNetwork struct {
	ID    string `json:"id"`
	Label string `json:"label"`
}

type gwEndpoint struct {
	IP       string `json:"ip"`
	CtrlPort int    `json:"ctrl_port"`
	WGPort   int    `json:"wg_port"`
	Source   string `json:"source"`
	Verified bool   `json:"verified"`
}

type gwManual struct {
	ID       string `json:"id"`
	Label    string `json:"label"`
	Host     string `json:"host"`
	CtrlPort int    `json:"ctrl_port"`
}

// gwItem is the §13.3 list model.
type gwItem struct {
	ID          string       `json:"id"`
	Name        string       `json:"name"`
	OS          string       `json:"os"`
	AppVersion  string       `json:"app_version"`
	Online      bool         `json:"online"`
	LastSeenMs  int64        `json:"last_seen_ms"`
	ClientCount int          `json:"client_count"`
	Flags       gwFlags      `json:"flags"`
	Access      string       `json:"access"`
	Network     *gwNetwork   `json:"network"`
	Endpoints   []gwEndpoint `json:"endpoints"`
	Manual      *gwManual    `json:"manual"`
	Fingerprint string       `json:"fingerprint"`
	FirstSeen   int64        `json:"first_seen"`
	IsNew       bool         `json:"is_new"`
	IsSelf      bool         `json:"is_self"`

	pub      [32]byte
	hasPub   bool
	freshRaw [][]byte
}

func init() {
	handle(api.GatewaysList, func(c *core, _ []byte) (any, *api.Error) {
		return map[string]any{"gateways": c.gatewayList()}, nil
	})
	handle(api.GatewaysUnlock, (*core).gatewaysUnlock)
	handle(api.GatewaysManualAdd, (*core).manualAdd)
	handle(api.GatewaysManualRm, (*core).manualRemove)
	handle(api.GatewaysInfo, (*core).gatewaysInfo)
}

func fingerprint(pub [32]byte) string {
	h := sha256.Sum256(pub[:])
	return hex.EncodeToString(h[:])[:10]
}

func versionString(v [3]byte) string { return fmt.Sprintf("%d.%d.%d", v[0], v[1], v[2]) }

// gatewayList builds the list model from the beacon table, manual entries
// and our own gateway.
func (c *core) gatewayList() []gwItem {
	return c.buildList(false)
}

func (c *core) buildList(withRaw bool) []gwItem {
	now := time.Now()
	st := c.store.Get()
	labels := map[string]string{}
	for _, k := range st.Keyring {
		labels[k.ID] = k.Label
	}
	known := map[string]state.KnownGateway{}
	for _, k := range st.KnownGateways {
		known[k.Pubkey] = k
	}
	items := map[string]*gwItem{}
	var order []string

	for _, e := range c.table.Snapshot() {
		id := pubID(e.Pub)
		it := &gwItem{
			ID: id, Name: clean(e.Beacon.Name, 32), OS: osName(e.Beacon.OS),
			AppVersion: versionString(e.Beacon.AppVersion), Online: e.Online(now),
			LastSeenMs: now.Sub(e.LastSeen).Milliseconds(), ClientCount: int(e.Beacon.ClientCount),
			Flags: gwFlags{
				Accepting: e.Beacon.Flags&wire.BeaconAccepting != 0,
				LANAccess: e.Beacon.Flags&wire.BeaconLANAccess != 0,
				DualRole:  e.Beacon.Flags&wire.BeaconDualRole != 0,
			},
			Fingerprint: fingerprint(e.Pub), FirstSeen: e.FirstSeen.Unix(),
			pub: e.Pub, hasPub: true, Endpoints: []gwEndpoint{},
		}
		if it.Name == "" {
			it.Name = "Gateway " + it.Fingerprint[:4]
		}
		if e.Verified {
			if _, ok := labels[e.NetworkID]; ok {
				it.Access = "member"
				it.Network = &gwNetwork{ID: e.NetworkID, Label: labels[e.NetworkID]}
			}
		}
		for _, ep := range e.Endpoints {
			it.Endpoints = append(it.Endpoints, gwEndpoint{IP: ep.IP.String(), CtrlPort: int(ep.CtrlPort),
				WGPort: int(ep.WGPort), Source: "lan", Verified: ep.Verified})
			if withRaw && now.Sub(ep.LastSeen) <= beacon.FreshBeacon {
				it.freshRaw = append(it.freshRaw, ep.Raw)
			}
		}
		items[id] = it
		order = append(order, id)
	}

	c.mu.Lock()
	manualRT := map[string]manualRuntime{}
	for k, v := range c.manual {
		manualRT[k] = *v
	}
	c.mu.Unlock()
	for _, m := range st.ManualGateways {
		rt := manualRT[m.ID]
		var it *gwItem
		if m.Pubkey != "" {
			it = items[m.Pubkey]
		}
		if it == nil {
			id := m.Pubkey
			if id == "" {
				id = "m-" + m.ID
			}
			it = &gwItem{ID: id, Name: clean(m.Label, 32), OS: rt.os, AppVersion: rt.version,
				ClientCount: rt.clients, LastSeenMs: -1, Endpoints: []gwEndpoint{}}
			if rt.name != "" {
				it.Name = rt.name
			}
			if pub, ok := parsePubID(m.Pubkey); ok {
				it.pub, it.hasPub, it.Fingerprint = pub, true, fingerprint(pub)
			}
			if !rt.lastOK.IsZero() {
				it.Online = now.Sub(rt.lastOK) <= 90*time.Second
				it.LastSeenMs = now.Sub(rt.lastOK).Milliseconds()
				it.Flags.Accepting = true // answered INFO, so it serves members
			}
			items[id] = it
			order = append(order, id)
		}
		it.Manual = &gwManual{ID: m.ID, Label: clean(m.Label, 32), Host: m.Host, CtrlPort: m.CtrlPort}
		ep := rt.addr
		if !ep.IsValid() {
			if ip, err := netip.ParseAddr(m.LastIP); err == nil {
				ep = netip.AddrPortFrom(ip, uint16(m.CtrlPort))
			}
		}
		if ep.IsValid() {
			it.Endpoints = append(it.Endpoints, gwEndpoint{IP: ep.Addr().String(), CtrlPort: int(ep.Port()),
				Source: "manual", Verified: m.NetworkID != "" && !rt.lastOK.IsZero()})
		}
		if it.Access == "" && m.NetworkID != "" {
			if l, ok := labels[m.NetworkID]; ok {
				it.Access = "member"
				it.Network = &gwNetwork{ID: m.NetworkID, Label: l}
			}
		}
	}

	out := make([]gwItem, 0, len(order))
	for _, id := range order {
		it := items[id]
		if it.Access == "" {
			it.Access = "locked"
			if it.hasPub {
				if k, ok := known[pubID(it.pub)]; ok && k.NetworkID != "" {
					if _, held := labels[k.NetworkID]; held {
						it.Access = "key_changed"
					}
				}
			}
		}
		if it.hasPub {
			k, ok := known[pubID(it.pub)]
			it.IsNew = !ok
			if ok && k.FirstSeen != 0 && (it.FirstSeen == 0 || k.FirstSeen < it.FirstSeen) {
				it.FirstSeen = k.FirstSeen
			}
		}
		out = append(out, *it)
	}
	if self := c.selfItem(); self != nil {
		out = append(out, *self)
	}
	rank := map[string]int{"member": 0, "key_changed": 1, "locked": 2}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.IsSelf != b.IsSelf {
			return !a.IsSelf
		}
		if rank[a.Access] != rank[b.Access] {
			return rank[a.Access] < rank[b.Access]
		}
		if a.Online != b.Online {
			return a.Online
		}
		return strings.ToLower(a.Name) < strings.ToLower(b.Name)
	})
	return out
}

// findItem returns the list item for a gateway id, with fresh raw beacons.
func (c *core) findItem(id string) (gwItem, *api.Error) {
	for _, it := range c.buildList(true) {
		// A manual entry keeps answering to its original "m-<uuid>" id after
		// its public key (and therefore its list id) has been learned.
		if !it.IsSelf && (it.ID == id || (it.Manual != nil && "m-"+it.Manual.ID == id)) {
			return it, nil
		}
	}
	return gwItem{}, api.NotFound("gateway")
}

// ctrlEndpoints returns control addresses to try, best first. A manual
// entry whose host has not been resolved yet is resolved now.
func (c *core) ctrlEndpoints(it gwItem) []netip.AddrPort {
	var out []netip.AddrPort
	if it.Manual != nil && len(it.Endpoints) == 0 {
		if ap, err := resolveHost(it.Manual.Host, it.Manual.CtrlPort); err == nil {
			out = append(out, ap)
		}
	}
	for _, ep := range it.Endpoints {
		ip, err := netip.ParseAddr(ep.IP)
		if err != nil || ep.CtrlPort == 0 {
			continue
		}
		out = append(out, netip.AddrPortFrom(ip, uint16(ep.CtrlPort)))
	}
	return out
}

// ---- unlock (§13.3) ----

func (c *core) gatewaysUnlock(args []byte) (any, *api.Error) {
	a, aerr := decode[struct {
		GatewayID string `json:"gateway_id"`
		KeyText   string `json:"key_text"`
	}](args)
	if aerr != nil {
		return nil, aerr
	}
	k, err := netkey.Parse(a.KeyText)
	if err != nil {
		return nil, api.Errf(api.CodeKeyFormat, http.StatusBadRequest, "that is not a valid PrivateVPN key (check for typos)")
	}
	it, aerr := c.findItem(a.GatewayID)
	if aerr != nil {
		return nil, aerr
	}
	sub := k.Derive()
	method := ""
	var infoJSON []byte
	if len(it.freshRaw) > 0 {
		for _, raw := range it.freshRaw {
			if wire.VerifyBeacon(raw, sub.Beacon) {
				method = "beacon"
				break
			}
		}
		if method == "" {
			return nil, api.Errf(api.CodeKeyMismatch, http.StatusBadRequest, "this key does not match %s", it.Name)
		}
	} else {
		eps := c.ctrlEndpoints(it)
		if len(eps) == 0 {
			return nil, api.Errf(api.CodeUnreachable, http.StatusGatewayTimeout, "%s is not reachable right now", it.Name)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		infoJSON, err = control.NewClient(sub.Control).Info(ctx, eps[0])
		cancel()
		var re *control.RemoteError
		switch {
		case errors.As(err, &re):
			return nil, api.Errf(api.CodeKeyMismatch, http.StatusBadRequest, "this key does not match %s", it.Name)
		case err != nil:
			return nil, api.Errf(api.CodeUnreachable, http.StatusGatewayTimeout, "no answer from %s — the key may be wrong or the gateway is offline", it.Name)
		}
		method = "info"
		if pub, ok := infoPubkey(infoJSON); ok {
			if it.hasPub && pub != it.pub {
				return nil, api.Errf(api.CodeKeyMismatch, http.StatusBadRequest, "the gateway at that address has a different identity")
			}
			it.pub, it.hasPub = pub, true
		}
	}

	replaced, id, aerr := c.bindKey(it, k)
	if aerr != nil {
		return nil, aerr
	}
	if it.Manual != nil && infoJSON != nil {
		info := sanitizeInfo(infoJSON)
		c.mu.Lock()
		if rt := c.manual[it.Manual.ID]; rt != nil {
			rt.lastOK = time.Now()
			rt.name, _ = info["name"].(string)
			rt.os, _ = info["os"].(string)
			rt.version, _ = info["app_version"].(string)
		}
		c.mu.Unlock()
	}
	gid := it.ID
	if it.hasPub {
		gid = pubID(it.pub)
	}
	c.log.Printf("keyring", "key for %q verified (%s)", it.Name, method)
	c.keyringChanged()
	return map[string]any{"keyring_id": id, "method": method, "replaced": replaced, "gateway_id": gid}, nil
}

// bindKey applies the replace-or-add rule and records the binding.
func (c *core) bindKey(it gwItem, k netkey.Key) (replaced bool, id string, aerr *api.Error) {
	now := time.Now().Unix()
	pid := ""
	if it.hasPub {
		pid = pubID(it.pub)
	}
	label := clean(it.Name+"'s network", 32)
	err := c.store.Update(func(st *state.State) error {
		// Replace path: this gateway verified under entry E before, and E's
		// current key no longer matches (the gateway reset its key).
		for _, kg := range st.KnownGateways {
			if pid == "" || kg.Pubkey != pid || kg.NetworkID == "" {
				continue
			}
			for i := range st.Keyring {
				if st.Keyring[i].ID == kg.NetworkID && !bytes.Equal(st.Keyring[i].Key, k[:]) {
					dup := false
					for _, e := range st.Keyring {
						if bytes.Equal(e.Key, k[:]) {
							dup = true
						}
					}
					if !dup {
						st.Keyring[i].Key = append([]byte(nil), k[:]...)
						st.Keyring[i].LastUsed = now
						id, replaced = st.Keyring[i].ID, true
					}
				}
			}
		}
		if id == "" {
			for i := range st.Keyring {
				if bytes.Equal(st.Keyring[i].Key, k[:]) {
					id = st.Keyring[i].ID
					st.Keyring[i].LastUsed = now
				}
			}
		}
		if id == "" {
			if len(st.Keyring) >= state.MaxKeyring {
				aerr = api.Errf(api.CodeKeyringFull, http.StatusConflict, "the keyring is full (%d networks); remove one first", state.MaxKeyring)
				return aerr
			}
			id = newID()
			st.Keyring = append(st.Keyring, state.KeyEntry{ID: id, Key: append([]byte(nil), k[:]...),
				Label: label, CreatedAt: now, LastUsed: now})
		}
		if pid != "" {
			upsertKnown(st, pid, it.Name, id, now)
		}
		if it.Manual != nil {
			for i := range st.ManualGateways {
				if st.ManualGateways[i].ID == it.Manual.ID {
					st.ManualGateways[i].NetworkID = id
					if pid != "" {
						st.ManualGateways[i].Pubkey = pid
					}
				}
			}
		}
		return nil
	})
	if aerr != nil {
		return false, "", aerr
	}
	if err != nil {
		return false, "", api.Internal(err)
	}
	if replaced {
		c.mu.Lock()
		delete(c.subkeys, id)
		c.mu.Unlock()
	}
	return replaced, id, nil
}

func upsertKnown(st *state.State, pid, name, netID string, now int64) {
	for i := range st.KnownGateways {
		if st.KnownGateways[i].Pubkey == pid {
			st.KnownGateways[i].Name = clean(name, 32)
			st.KnownGateways[i].NetworkID = netID
			st.KnownGateways[i].LastSeen = now
			return
		}
	}
	if len(st.KnownGateways) >= state.MaxKnown {
		oldest := 0
		for i, k := range st.KnownGateways {
			if k.LastSeen < st.KnownGateways[oldest].LastSeen {
				oldest = i
			}
		}
		st.KnownGateways = append(st.KnownGateways[:oldest], st.KnownGateways[oldest+1:]...)
	}
	st.KnownGateways = append(st.KnownGateways, state.KnownGateway{Pubkey: pid, Name: clean(name, 32),
		NetworkID: netID, FirstSeen: now, LastSeen: now})
}

func infoPubkey(doc []byte) ([32]byte, bool) {
	var v struct {
		Pubkey string `json:"pubkey"`
	}
	if json.Unmarshal(doc, &v) != nil {
		return [32]byte{}, false
	}
	return parsePubID(v.Pubkey)
}

// ---- manual gateways ----

var hostRE = regexp.MustCompile(`^[A-Za-z0-9.-]{1,253}$`)

func (c *core) manualAdd(args []byte) (any, *api.Error) {
	a, aerr := decode[struct {
		Label     string `json:"label"`
		Host      string `json:"host"`
		CtrlPort  int    `json:"ctrl_port"`
		KeyringID string `json:"keyring_id"`
	}](args)
	if aerr != nil {
		return nil, aerr
	}
	host := strings.TrimSpace(a.Host)
	if h, p, err := net.SplitHostPort(host); err == nil {
		port, perr := strconv.Atoi(p)
		if perr != nil {
			return nil, api.BadRequest("invalid port")
		}
		host, a.CtrlPort = h, port
	}
	if _, err := netip.ParseAddr(host); err != nil && !hostRE.MatchString(host) {
		return nil, api.BadRequest("enter a host name or IPv4 address")
	}
	if a.CtrlPort == 0 {
		a.CtrlPort = 51821
	}
	if a.CtrlPort < 1024 || a.CtrlPort > 65535 {
		return nil, api.BadRequest("port must be 1024–65535")
	}
	label := clean(a.Label, 32)
	if label == "" {
		label = clean(host, 32)
	}
	if a.KeyringID != "" {
		if _, ok := c.keyEntry(a.KeyringID); !ok {
			return nil, api.NotFound("network")
		}
	}
	id := newID()
	var full bool
	c.store.Update(func(st *state.State) error {
		if len(st.ManualGateways) >= state.MaxManual {
			full = true
			return nil
		}
		mg := state.ManualGateway{ID: id, Label: label, Host: host, CtrlPort: a.CtrlPort, NetworkID: a.KeyringID}
		if ip, err := netip.ParseAddr(host); err == nil {
			mg.LastIP = ip.Unmap().String() // usable at once, no resolution needed
		}
		st.ManualGateways = append(st.ManualGateways, mg)
		return nil
	})
	if full {
		return nil, api.Errf(api.CodeConflict, http.StatusConflict, "too many manual gateways")
	}
	go c.refreshManualOne(id, true)
	c.gatewaysChanged()
	return map[string]any{"id": id}, nil
}

func (c *core) manualRemove(args []byte) (any, *api.Error) {
	a, aerr := decode[struct {
		ID string `json:"id"`
	}](args)
	if aerr != nil {
		return nil, aerr
	}
	found := false
	c.store.Update(func(st *state.State) error {
		out := st.ManualGateways[:0]
		for _, m := range st.ManualGateways {
			if m.ID == a.ID {
				found = true
				continue
			}
			out = append(out, m)
		}
		st.ManualGateways = out
		return nil
	})
	if !found {
		return nil, api.NotFound("gateway")
	}
	c.mu.Lock()
	delete(c.manual, a.ID)
	c.mu.Unlock()
	c.gatewaysChanged()
	return nil, nil
}

// refreshManual probes every manual gateway (INFO) in the background.
func (c *core) refreshManual() {
	for _, m := range c.store.Get().ManualGateways {
		go c.refreshManualOne(m.ID, false)
	}
}

// refreshManualOne resolves the host and sends INFO under the bound key, or
// trials keyring keys (≤ 2/s) when none is bound.
func (c *core) refreshManualOne(id string, force bool) {
	var m state.ManualGateway
	found := false
	for _, x := range c.store.Get().ManualGateways {
		if x.ID == id {
			m, found = x, true
		}
	}
	if !found {
		return
	}
	c.mu.Lock()
	rt := c.manual[id]
	if rt == nil {
		rt = &manualRuntime{}
		c.manual[id] = rt
	}
	if !force && time.Since(rt.lastTry) < 25*time.Second {
		c.mu.Unlock()
		return
	}
	rt.lastTry = time.Now()
	c.mu.Unlock()

	addr, err := resolveHost(m.Host, m.CtrlPort)
	if err != nil {
		// DNS may be blocked by the kill switch: fall back to the last address.
		ip, perr := netip.ParseAddr(m.LastIP)
		if perr != nil {
			return
		}
		addr = netip.AddrPortFrom(ip, uint16(m.CtrlPort))
	} else if addr.Addr().String() != m.LastIP {
		c.store.Update(func(st *state.State) error {
			for i := range st.ManualGateways {
				if st.ManualGateways[i].ID == id {
					st.ManualGateways[i].LastIP = addr.Addr().String()
				}
			}
			return nil
		})
	}
	c.mu.Lock()
	rt.addr, rt.resolved = addr, time.Now()
	c.mu.Unlock()

	var keys []state.KeyEntry
	if m.NetworkID != "" {
		if k, ok := c.keyEntry(m.NetworkID); ok {
			keys = []state.KeyEntry{k}
		}
	} else {
		keys = c.store.Get().Keyring
	}
	for i, k := range keys {
		if i > 0 {
			time.Sleep(500 * time.Millisecond) // ≤ 2 INFO/s (gateway limit)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		doc, err := control.NewClient(c.subkeysFor(k).Control).Info(ctx, addr)
		cancel()
		if err != nil {
			continue
		}
		info := sanitizeInfo(doc)
		c.mu.Lock()
		rt.lastOK = time.Now()
		rt.name, _ = info["name"].(string)
		rt.os, _ = info["os"].(string)
		rt.version, _ = info["app_version"].(string)
		if n, ok := info["client_count"].(float64); ok {
			rt.clients = int(n)
		}
		c.mu.Unlock()
		pub, hasPub := infoPubkey(doc)
		c.store.Update(func(st *state.State) error {
			for j := range st.ManualGateways {
				if st.ManualGateways[j].ID == id {
					st.ManualGateways[j].NetworkID = k.ID
					if hasPub && st.ManualGateways[j].Pubkey == "" {
						st.ManualGateways[j].Pubkey = pubID(pub)
					}
				}
			}
			return nil
		})
		break
	}
	c.gatewaysChanged()
}

func resolveHost(host string, port int) (netip.AddrPort, error) {
	if ip, err := netip.ParseAddr(host); err == nil {
		if !ip.Unmap().Is4() {
			return netip.AddrPort{}, errors.New("IPv6 gateways are not supported")
		}
		return netip.AddrPortFrom(ip.Unmap(), uint16(port)), nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", host)
	if err != nil || len(ips) == 0 {
		return netip.AddrPort{}, errors.New("cannot resolve host")
	}
	return netip.AddrPortFrom(ips[0].Unmap(), uint16(port)), nil
}

// ---- details (INFO) ----

func (c *core) gatewaysInfo(args []byte) (any, *api.Error) {
	a, aerr := decode[struct {
		GatewayID string `json:"gateway_id"`
	}](args)
	if aerr != nil {
		return nil, aerr
	}
	it, aerr := c.findItem(a.GatewayID)
	if aerr != nil {
		return nil, aerr
	}
	if it.Access != "member" || it.Network == nil {
		return nil, api.Errf(api.CodeLocked, http.StatusConflict, "enter this gateway's key to see its details")
	}
	k, ok := c.keyEntry(it.Network.ID)
	if !ok {
		return nil, api.Errf(api.CodeLocked, http.StatusConflict, "enter this gateway's key to see its details")
	}
	c.mu.Lock()
	ci, cached := c.info[it.ID]
	c.mu.Unlock()
	if cached && time.Since(ci.at) < 25*time.Second {
		return map[string]any{"info": ci.doc, "fetched_at_ms": ci.at.UnixMilli(), "endpoint_used": ci.endpoint}, nil
	}
	cl := control.NewClient(c.subkeysFor(k).Control)
	for _, ep := range c.ctrlEndpoints(it) {
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		doc, err := cl.Info(ctx, ep)
		cancel()
		if err != nil {
			continue
		}
		if pub, ok := infoPubkey(doc); ok && it.hasPub && pub != it.pub {
			continue // a member answering for another gateway's address
		}
		info := sanitizeInfo(doc)
		now := time.Now()
		c.mu.Lock()
		c.info[it.ID] = cachedInfo{at: now, doc: info, endpoint: ep.String()}
		c.mu.Unlock()
		return map[string]any{"info": info, "fetched_at_ms": now.UnixMilli(), "endpoint_used": ep.String()}, nil
	}
	return nil, api.Errf(api.CodeTimeout, http.StatusGatewayTimeout, "%s did not answer", it.Name)
}

// sanitizeInfo validates an untrusted INFO document (§10.6) and returns a
// clean copy containing only known fields.
func sanitizeInfo(doc []byte) map[string]any {
	out := map[string]any{}
	if len(doc) > wire.MaxInfoJSON {
		return out
	}
	var raw map[string]any
	if json.Unmarshal(doc, &raw) != nil {
		return out
	}
	if v, _ := raw["v"].(float64); v != 1 {
		return out
	}
	str := func(m map[string]any, k string, max int) {
		if s, ok := m[k].(string); ok {
			out[k] = clean(s, max)
		}
	}
	num := func(m map[string]any, k string, lo, hi float64, dst map[string]any) {
		if f, ok := m[k].(float64); ok && !math.IsNaN(f) && f >= lo && f <= hi {
			dst[k] = f
		}
	}
	boolean := func(m map[string]any, k string) {
		if b, ok := m[k].(bool); ok {
			out[k] = b
		}
	}
	ip := func(m map[string]any, k string, dst map[string]any) {
		if s, ok := m[k].(string); ok {
			if a, err := netip.ParseAddr(s); err == nil {
				dst[k] = a.String()
			}
		}
	}
	if s, ok := raw["pubkey"].(string); ok {
		if _, ok := parsePubID(s); ok {
			out["pubkey"] = s
		}
	}
	str(raw, "name", 32)
	if s, ok := raw["os"].(string); ok && (s == "windows" || s == "macos" || s == "linux") {
		out["os"] = s
	}
	str(raw, "os_version", 32)
	str(raw, "app_version", 16)
	str(raw, "subnet", 18)
	str(raw, "nat", 8)
	num(raw, "uptime_sec", 0, 1e10, out)
	num(raw, "gateway_uptime_sec", 0, 1e10, out)
	num(raw, "client_count", 0, 253, out)
	num(raw, "mtu", 576, 1500, out)
	num(raw, "wg_port", 1, 65535, out)
	num(raw, "ctrl_port", 1, 65535, out)
	num(raw, "public_ip_checked_at", 0, 1e11, out)
	num(raw, "now", 0, 1e11, out)
	boolean(raw, "lan_access")
	boolean(raw, "dual_role")
	boolean(raw, "stale")
	ip(raw, "public_ip", out)
	ip(raw, "public_ip6", out)
	if l, ok := raw["lan_ips"].([]any); ok {
		ips := []string{}
		for _, x := range l {
			if s, ok := x.(string); ok && len(ips) < 8 {
				if a, err := netip.ParseAddr(s); err == nil && a.Is4() {
					ips = append(ips, a.String())
				}
			}
		}
		out["lan_ips"] = ips
	}
	if g, ok := raw["geo"].(map[string]any); ok {
		geo := map[string]any{}
		gs := func(k string, max int) {
			if s, ok := g[k].(string); ok {
				geo[k] = clean(s, max)
			}
		}
		if s, ok := g["source"].(string); ok && (s == "geoip" || s == "manual" || s == "gps" || s == "none") {
			geo["source"] = s
		}
		gs("provider", 32)
		gs("country", 64)
		if s, ok := g["country_code"].(string); ok && len(s) == 2 && strings.ToUpper(s) == s && s[0] >= 'A' && s[1] >= 'A' && s[0] <= 'Z' && s[1] <= 'Z' {
			geo["country_code"] = s
		}
		gs("region", 64)
		gs("city", 64)
		gs("isp", 64)
		gs("asn", 16)
		if geo["source"] != nil && geo["source"] != "none" {
			_, hasLat := g["lat"].(float64)
			_, hasLon := g["lon"].(float64)
			if hasLat && hasLon {
				num(g, "lat", -90, 90, geo)
				num(g, "lon", -180, 180, geo)
			}
		}
		num(g, "accuracy_km", 0, 20000, geo)
		num(g, "checked_at", 0, 1e11, geo)
		out["geo"] = geo
	}
	if tz, ok := raw["tz"].(map[string]any); ok {
		t := map[string]any{}
		if s, ok := tz["name"].(string); ok && tzNameRE.MatchString(s) {
			t["name"] = s
		}
		if s, ok := tz["abbrev"].(string); ok {
			t["abbrev"] = clean(s, 8)
		}
		num(tz, "utc_offset_sec", -16*3600, 16*3600, t)
		out["tz"] = t
	}
	return out
}

var tzNameRE = regexp.MustCompile(`^[A-Za-z0-9_+\-/]{1,64}$`)
