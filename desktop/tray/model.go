//go:build !android

package tray

import (
	"encoding/json"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// statusModel is the part of status.get (§14.1) the tray uses.
type statusModel struct {
	GatewayEnabled   bool
	GatewayNetworkID string
	GatewayClients   int
	ClientState      string // idle | joining | tunnel_up | connected | degraded | blocked
	ClientGatewayID  string
	ClientGateway    string
	// Unprotected: connected, but the engine reports a leak (protected=false).
	Unprotected   bool
	KillSwitchOff bool // client.kill_switch == "off"
	ResumePending bool // reconnecting the last session after a restart
	// Problems counts status.problems of severity error/warning; FirstProblem
	// is the most severe one's message (sanitised).
	Problems     int
	FirstProblem string
}

// gatewayModel is the part of a §13.3 list entry the tray uses.
type gatewayModel struct {
	ID     string
	Name   string
	Access string // member | locked | key_changed
	Online bool
	IsSelf bool
}

func parseStatus(raw []byte) (statusModel, bool) {
	var s struct {
		Gateway struct {
			Enabled bool `json:"enabled"`
			Network *struct {
				ID string `json:"id"`
			} `json:"network"`
			Clients int `json:"clients"`
		} `json:"gateway"`
		Client struct {
			State         string `json:"state"`
			GatewayID     string `json:"gateway_id"`
			GatewayName   string `json:"gateway_name"`
			Protected     *bool  `json:"protected"`
			KillSwitch    string `json:"kill_switch"`
			ResumePending bool   `json:"resume_pending"`
		} `json:"client"`
		Problems []struct {
			Severity string `json:"severity"`
			Message  string `json:"message"`
		} `json:"problems"`
	}
	if err := json.Unmarshal(raw, &s); err != nil {
		return statusModel{}, false
	}
	m := statusModel{
		GatewayEnabled:  s.Gateway.Enabled,
		GatewayClients:  s.Gateway.Clients,
		ClientState:     s.Client.State,
		ClientGatewayID: s.Client.GatewayID,
		ClientGateway:   sanitize(s.Client.GatewayName, 32),
		Unprotected:     s.Client.State == "connected" && s.Client.Protected != nil && !*s.Client.Protected,
		KillSwitchOff:   s.Client.KillSwitch == "off",
		ResumePending:   s.Client.ResumePending,
	}
	if s.Gateway.Network != nil {
		m.GatewayNetworkID = s.Gateway.Network.ID
	}
	// Errors before warnings; info lines (e.g. carrier-grade NAT) are not problems.
	for _, sev := range []string{"error", "warning"} {
		for _, p := range s.Problems {
			if p.Severity != sev {
				continue
			}
			m.Problems++
			if m.FirstProblem == "" {
				m.FirstProblem = sanitize(p.Message, 70)
			}
		}
	}
	if m.GatewayClients < 0 || m.GatewayClients > 253 {
		m.GatewayClients = 0
	}
	return m, true
}

func parseGateways(raw []byte) ([]gatewayModel, bool) {
	var list []struct {
		ID     string `json:"id"`
		Name   string `json:"name"`
		Access string `json:"access"`
		Online bool   `json:"online"`
		IsSelf bool   `json:"is_self"`
		Manual *struct {
			Label string `json:"label"`
		} `json:"manual"`
	}
	if err := json.Unmarshal(raw, &list); err != nil {
		return nil, false
	}
	out := make([]gatewayModel, 0, len(list))
	for _, g := range list {
		if g.ID == "" || len(g.ID) > 128 {
			continue
		}
		name := sanitize(g.Name, 32)
		if name == "" && g.Manual != nil {
			name = sanitize(g.Manual.Label, 32)
		}
		if name == "" {
			name = "Unnamed gateway"
		}
		access := g.Access
		if access != "member" && access != "key_changed" {
			access = "locked"
		}
		out = append(out, gatewayModel{ID: g.ID, Name: name, Access: access, Online: g.Online, IsSelf: g.IsSelf})
	}
	return out, true
}

// sanitize removes C0/C1 controls and bidi controls (§10.6) and caps the
// length in runes, appending "…" when truncated.
func sanitize(s string, max int) string {
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "")
	}
	s = strings.Map(func(r rune) rune {
		switch {
		case r < 0x20, r >= 0x7f && r < 0xa0:
			return -1
		case r == 0x200e, r == 0x200f, r >= 0x202a && r <= 0x202e, r >= 0x2066 && r <= 0x2069:
			return -1
		}
		return r
	}, s)
	s = strings.TrimSpace(s)
	if utf8.RuneCountInString(s) > max {
		r := []rune(s)
		s = string(r[:max]) + "…"
	}
	return s
}

// iconKind is one of the five tray icon states.
type iconKind int

const (
	iconIdle iconKind = iota
	iconGateway
	iconConnected
	iconBoth
	iconWarning // client connection interrupted, blocked or leaking
)

// tunnelActive: the client tunnel carries (or holds) this device's traffic.
func tunnelActive(state string) bool {
	return state == "tunnel_up" || state == "connected" || state == "degraded" || state == "blocked"
}

// canDisconnect: the Disconnect item is offered whenever a session (or a
// kill-switch block left by one) exists — it is the only way to remove it.
func canDisconnect(state string) bool {
	return state != "" && state != "idle"
}

func iconFor(st statusModel) iconKind {
	if st.ClientState == "degraded" || st.ClientState == "blocked" || st.Unprotected {
		return iconWarning
	}
	c := tunnelActive(st.ClientState)
	switch {
	case c && st.GatewayEnabled:
		return iconBoth
	case c:
		return iconConnected
	case st.GatewayEnabled:
		return iconGateway
	}
	return iconIdle
}

func statusLine(st statusModel) string {
	var parts []string
	name := st.ClientGateway
	switch st.ClientState {
	case "connected":
		switch {
		case st.Unprotected:
			parts = append(parts, "Connected"+to(name)+" — not fully protected")
		case name != "":
			parts = append(parts, "Protected · connected to "+name)
		default:
			parts = append(parts, "Protected · connected")
		}
	case "joining", "tunnel_up":
		if st.ResumePending {
			parts = append(parts, "Reconnecting"+to(name)+" after restart…")
		} else if name != "" {
			parts = append(parts, "Connecting to "+name+"…")
		} else {
			parts = append(parts, "Connecting…")
		}
	case "degraded":
		parts = append(parts, "Connection interrupted — traffic held, reconnecting")
	case "blocked":
		switch {
		case st.ResumePending:
			parts = append(parts, "Reconnecting after restart — Internet blocked")
		case st.KillSwitchOff && st.ClientGatewayID != "":
			parts = append(parts, "VPN connection failed — traffic may not be protected")
		default:
			parts = append(parts, "Internet blocked to protect your IP")
		}
	default:
		if st.ResumePending {
			parts = append(parts, "Reconnecting after restart…")
		} else {
			parts = append(parts, "Not protected (VPN off)")
		}
	}
	if st.GatewayEnabled {
		parts = append(parts, "Gateway on ("+strconv.Itoa(st.GatewayClients)+" "+pluralClients(st.GatewayClients)+")")
	}
	return strings.Join(parts, " · ")
}

func to(name string) string {
	if name == "" {
		return ""
	}
	return " to " + name
}

// problemLine is the tray's one-line summary of status.problems ("" when
// there are none).
func problemLine(st statusModel) string {
	switch {
	case st.Problems == 0:
		return ""
	case st.Problems == 1 && st.FirstProblem != "":
		return "⚠ " + st.FirstProblem
	}
	return "⚠ " + strconv.Itoa(st.Problems) + " problems — open Private VPN Pro for details"
}

func pluralClients(n int) string {
	if n == 1 {
		return "client"
	}
	return "clients"
}

// menuEntry is one item of the "Connect to" submenu.
type menuEntry struct {
	ID       string
	Title    string
	Locked   bool // selecting it opens the web UI on the key prompt
	Disabled bool
	Checked  bool // this device is connected (or connecting) to it
}

// maxEntries is the size of the submenu item pool.
const maxEntries = 12

// connectEntries orders the gateways for the tray: verified+online first,
// then locked / key-changed ones (online only, prefixed with a lock), then
// verified-but-offline ones (disabled). This device's own gateway is left
// out. The second result is the number of entries that did not fit.
func connectEntries(gws []gatewayModel, st statusModel) ([]menuEntry, int) {
	rank := func(g gatewayModel) int {
		switch {
		case g.Access == "member" && g.Online:
			return 0
		case g.Access == "key_changed" && g.Online:
			return 1
		case g.Access == "locked" && g.Online:
			return 2
		case g.Access == "member":
			return 3
		}
		return 4 // locked and offline: not shown
	}
	list := make([]gatewayModel, 0, len(gws))
	for _, g := range gws {
		if !g.IsSelf && rank(g) < 4 {
			list = append(list, g)
		}
	}
	sort.SliceStable(list, func(i, j int) bool {
		ri, rj := rank(list[i]), rank(list[j])
		if ri != rj {
			return ri < rj
		}
		if list[i].Name != list[j].Name {
			return list[i].Name < list[j].Name
		}
		return list[i].ID < list[j].ID
	})
	more := 0
	if len(list) > maxEntries {
		more = len(list) - maxEntries
		list = list[:maxEntries]
	}
	out := make([]menuEntry, 0, len(list))
	for _, g := range list {
		e := menuEntry{ID: g.ID, Title: g.Name}
		if g.Access != "member" {
			e.Locked = true
			e.Title = "🔒 " + g.Name
		} else if !g.Online {
			e.Disabled = true
			e.Title = g.Name + " (offline)"
		}
		if st.ClientGatewayID == g.ID && st.ClientState != "" && st.ClientState != "idle" {
			e.Checked = true
		}
		out = append(out, e)
	}
	return out, more
}

// menuText escapes characters a native menu would interpret: "&" starts a
// mnemonic on Windows, "_" on Linux (dbusmenu).
func menuText(goos, s string) string {
	switch goos {
	case "windows":
		return strings.ReplaceAll(s, "&", "&&")
	case "darwin":
		return s
	default:
		return strings.ReplaceAll(s, "_", "__")
	}
}
