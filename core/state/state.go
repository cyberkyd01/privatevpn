// Package state persists the device's state.json (ARCHITECTURE §12.2).
// It holds the keyring, settings and opted-in gateway identities only —
// never anything about client sessions.
package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// Schema is the current state.json schema version.
const Schema = 2

// Limits.
const (
	MaxKeyring = 16
	MaxKnown   = 64
	MaxManual  = 32
)

// KeyEntry is one network key in the keyring.
type KeyEntry struct {
	ID          string `json:"id"`
	Key         []byte `json:"key"` // 32 bytes, base64 in JSON
	Label       string `json:"label"`
	CreatedHere bool   `json:"created_here"`
	CreatedAt   int64  `json:"created_at"`
	LastUsed    int64  `json:"last_used"`
}

// String hides the key.
func (KeyEntry) String() string { return "<key entry>" }

// GeoManual is the gateway's manual location override.
type GeoManual struct {
	Country string   `json:"country"`
	Region  string   `json:"region"`
	City    string   `json:"city"`
	Lat     *float64 `json:"lat"`
	Lon     *float64 `json:"lon"`
	TZName  string   `json:"tz_name"`
}

// GeoSettings controls the gateway's public IP / location lookup.
type GeoSettings struct {
	Enabled bool       `json:"enabled"`
	Manual  *GeoManual `json:"manual"`
}

// Gateway holds desktop gateway settings.
type Gateway struct {
	Enabled     bool        `json:"enabled"`
	NetworkID   string      `json:"network_id"`
	PrivateKey  []byte      `json:"private_key"`
	WGPort      int         `json:"wg_port"`
	CtrlPort    int         `json:"ctrl_port"`
	Subnet      string      `json:"subnet"` // "" = derived
	LANAccess   bool        `json:"lan_access"`
	DNSUpstream []string    `json:"dns_upstream"`
	Geo         GeoSettings `json:"geo"`
}

// String hides the private key.
func (Gateway) String() string { return "<gateway settings>" }

// ManualGateway is a gateway added by address.
type ManualGateway struct {
	ID        string `json:"id"`
	Label     string `json:"label"`
	Host      string `json:"host"`
	CtrlPort  int    `json:"ctrl_port"`
	NetworkID string `json:"network_id"`
	Pubkey    string `json:"pubkey"` // base64url, "" until learned
	// LastIP is the last address the host resolved to; used when DNS is
	// unavailable (the kill switch blocks it while the VPN is down).
	LastIP string `json:"last_ip,omitempty"`
}

// KnownGateway is a gateway identity seen before (TOFU hints).
type KnownGateway struct {
	Pubkey    string `json:"pubkey"`
	Name      string `json:"name"`
	NetworkID string `json:"network_id"`
	FirstSeen int64  `json:"first_seen"`
	LastSeen  int64  `json:"last_seen"`
}

// Client holds client-mode settings.
type Client struct {
	// KillSwitch blocks all traffic outside the tunnel from the moment a
	// tunnel is up until the user explicitly disconnects (desktop: OS-level
	// block that survives crashes; Android relies on the OS "Block
	// connections without VPN" setting).
	KillSwitch bool `json:"kill_switch"`
	// AllowLAN keeps the local network reachable while the block is active.
	AllowLAN bool `json:"allow_lan"`
	// KillSwitchEngaged records that a block may still be installed (set
	// when a tunnel comes up, cleared after an explicit disconnect), so a
	// restart after a crash can tell the user why the Internet is blocked.
	KillSwitchEngaged bool `json:"kill_switch_engaged"`
	// AutoReconnect resumes the last session after a restart/crash.
	AutoReconnect bool `json:"auto_reconnect"`
	// ResumeGatewayID is the gateway (list id) to reconnect to; set while a
	// session is wanted, cleared by an explicit disconnect or quit.
	ResumeGatewayID string `json:"resume_gateway_id,omitempty"`
}

// UI holds desktop UI settings.
type UI struct {
	Port      int    `json:"port"`
	Autostart bool   `json:"autostart"`
	Theme     string `json:"theme"`
	// AutostartConfigured records that first-run autostart registration ran.
	AutostartConfigured bool `json:"autostart_configured"`
}

// State is the whole persisted document.
type State struct {
	Schema         int             `json:"schema"`
	Keyring        []KeyEntry      `json:"keyring"`
	DeviceName     string          `json:"device_name,omitempty"`
	Gateway        *Gateway        `json:"gateway,omitempty"`
	ManualGateways []ManualGateway `json:"manual_gateways"`
	KnownGateways  []KnownGateway  `json:"known_gateways"`
	Client         *Client         `json:"client,omitempty"`
	UI             UI              `json:"ui"`
}

// Clone returns a deep copy.
func (s State) Clone() State {
	b, _ := json.Marshal(s)
	var c State
	json.Unmarshal(b, &c)
	return c
}

// Store is the loaded state file. Safe for concurrent use.
type Store struct {
	path string
	mu   sync.Mutex
	st   State
}

// Open loads <dir>/state.json, creating it from defaults if missing.
// defaults is applied to a fresh state (and to fill zero fields on load).
func Open(dir string, defaults func(*State)) (*Store, error) {
	if err := ensureDir(dir); err != nil {
		return nil, err
	}
	s := &Store{path: filepath.Join(dir, "state.json")}
	b, err := os.ReadFile(s.path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		s.st = State{Schema: Schema}
	case err != nil:
		return nil, err
	default:
		if len(b) > 1<<20 {
			return nil, errors.New("state: file too large")
		}
		if err := json.Unmarshal(b, &s.st); err != nil {
			return nil, fmt.Errorf("state: %w", err)
		}
		if s.st.Schema > Schema {
			return nil, fmt.Errorf("state: written by a newer version (schema %d)", s.st.Schema)
		}
	}
	s.st.Schema = Schema
	if defaults != nil {
		defaults(&s.st)
	}
	s.sanitize()
	if err := s.saveLocked(); err != nil {
		return nil, err
	}
	return s, nil
}

// sanitize drops malformed entries so a hand-edited file cannot break us.
func (s *Store) sanitize() {
	kr := s.st.Keyring[:0]
	for _, k := range s.st.Keyring {
		if len(k.Key) == 32 && k.ID != "" && len(kr) < MaxKeyring {
			kr = append(kr, k)
		}
	}
	s.st.Keyring = kr
	if len(s.st.KnownGateways) > MaxKnown {
		s.st.KnownGateways = s.st.KnownGateways[:MaxKnown]
	}
	if len(s.st.ManualGateways) > MaxManual {
		s.st.ManualGateways = s.st.ManualGateways[:MaxManual]
	}
	if g := s.st.Gateway; g != nil && len(g.PrivateKey) != 0 && len(g.PrivateKey) != 32 {
		g.PrivateKey = nil
	}
}

// Get returns a deep copy of the current state.
func (s *Store) Get() State {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.st.Clone()
}

// Update applies fn to a copy and persists it atomically; if fn or the write
// fails nothing changes.
func (s *Store) Update(fn func(*State) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := s.st.Clone()
	if err := fn(&next); err != nil {
		return err
	}
	prev := s.st
	s.st = next
	s.sanitize()
	if err := s.saveLocked(); err != nil {
		s.st = prev
		return err
	}
	return nil
}

func (s *Store) saveLocked() error {
	b, err := json.MarshalIndent(s.st, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(s.path, b)
}
