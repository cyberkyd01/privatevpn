package engine

import (
	"bytes"
	"net/http"
	"time"

	"github.com/cyberkyd01/private-vpn-pro/core/api"
	"github.com/cyberkyd01/private-vpn-pro/core/netkey"
	"github.com/cyberkyd01/private-vpn-pro/core/state"
)

type keyringItem struct {
	ID           string `json:"id"`
	Label        string `json:"label"`
	CreatedHere  bool   `json:"created_here"`
	CreatedAt    int64  `json:"created_at"`
	LastUsed     int64  `json:"last_used"`
	GatewaysSeen int    `json:"gateways_seen"`
	ServedHere   bool   `json:"served_here"`
}

func init() {
	handle(api.KeyringList, func(c *core, _ []byte) (any, *api.Error) {
		return map[string]any{"entries": c.keyringList()}, nil
	})
	handle(api.KeyringAdd, (*core).keyringAdd)
	handle(api.KeyringCreate, (*core).keyringCreate)
	handle(api.KeyringRename, (*core).keyringRename)
	handle(api.KeyringRemove, (*core).keyringRemove)
	handle(api.KeyringReveal, (*core).keyringReveal)
}

// keyringList never includes key bytes.
func (c *core) keyringList() []keyringItem {
	st := c.store.Get()
	seen := map[string]int{}
	for _, e := range c.table.Snapshot() {
		if e.Verified {
			seen[e.NetworkID]++
		}
	}
	served := ""
	if st.Gateway != nil {
		served = st.Gateway.NetworkID
	}
	out := make([]keyringItem, 0, len(st.Keyring))
	for _, k := range st.Keyring {
		out = append(out, keyringItem{ID: k.ID, Label: k.Label, CreatedHere: k.CreatedHere,
			CreatedAt: k.CreatedAt, LastUsed: k.LastUsed, GatewaysSeen: seen[k.ID], ServedHere: k.ID == served})
	}
	return out
}

func cleanLabel(s string) (string, *api.Error) {
	s = clean(s, 32)
	if s == "" {
		return "", api.BadRequest("label must not be empty")
	}
	return s, nil
}

// addKey stores key (deduplicated by bytes) and returns its id.
func (c *core) addKey(k netkey.Key, label string, createdHere bool) (id string, existing bool, aerr *api.Error) {
	now := time.Now().Unix()
	err := c.store.Update(func(st *state.State) error {
		for _, e := range st.Keyring {
			if bytes.Equal(e.Key, k[:]) {
				id, existing = e.ID, true
				return nil
			}
		}
		if len(st.Keyring) >= state.MaxKeyring {
			aerr = api.Errf(api.CodeKeyringFull, http.StatusConflict, "the keyring is full (%d networks); remove one first", state.MaxKeyring)
			return aerr
		}
		id = newID()
		st.Keyring = append(st.Keyring, state.KeyEntry{ID: id, Key: append([]byte(nil), k[:]...), Label: label,
			CreatedHere: createdHere, CreatedAt: now, LastUsed: now})
		return nil
	})
	if aerr != nil {
		return "", false, aerr
	}
	if err != nil {
		return "", false, api.Internal(err)
	}
	return id, existing, nil
}

func (c *core) keyringChanged() {
	if c.table.Reverify(c.keyRefs()) {
		c.gatewaysChanged()
	}
	c.gatewaysChanged()
	c.emitKeyring()
	c.emitStatus()
}

func (c *core) keyringAdd(args []byte) (any, *api.Error) {
	a, aerr := decode[struct {
		KeyText string `json:"key_text"`
		Label   string `json:"label"`
	}](args)
	if aerr != nil {
		return nil, aerr
	}
	k, err := netkey.Parse(a.KeyText)
	if err != nil {
		return nil, api.Errf(api.CodeKeyFormat, http.StatusBadRequest, "that is not a valid Private VPN Pro key (check for typos)")
	}
	label := clean(a.Label, 32)
	if label == "" {
		label = "Network"
	}
	id, existing, aerr := c.addKey(k, label, false)
	if aerr != nil {
		return nil, aerr
	}
	c.keyringChanged()
	return map[string]any{"id": id, "existing": existing}, nil
}

func (c *core) keyringCreate(args []byte) (any, *api.Error) {
	if isAndroid {
		return nil, api.Unsupported()
	}
	a, aerr := decode[struct {
		Label string `json:"label"`
	}](args)
	if aerr != nil {
		return nil, aerr
	}
	label := clean(a.Label, 32)
	if label == "" {
		label = "My network"
	}
	k, err := netkey.Generate()
	if err != nil {
		return nil, api.Internal(err)
	}
	id, _, aerr := c.addKey(k, label, true)
	if aerr != nil {
		return nil, aerr
	}
	c.log.Printf("keyring", "created network %q", label)
	c.keyringChanged()
	return map[string]any{"id": id, "key_text": k.Text()}, nil
}

func (c *core) keyringRename(args []byte) (any, *api.Error) {
	a, aerr := decode[struct {
		ID    string `json:"id"`
		Label string `json:"label"`
	}](args)
	if aerr != nil {
		return nil, aerr
	}
	label, aerr := cleanLabel(a.Label)
	if aerr != nil {
		return nil, aerr
	}
	found := false
	c.store.Update(func(st *state.State) error {
		for i := range st.Keyring {
			if st.Keyring[i].ID == a.ID {
				st.Keyring[i].Label, found = label, true
			}
		}
		return nil
	})
	if !found {
		return nil, api.NotFound("network")
	}
	c.keyringChanged()
	return nil, nil
}

func (c *core) keyringRemove(args []byte) (any, *api.Error) {
	a, aerr := decode[struct {
		ID string `json:"id"`
	}](args)
	if aerr != nil {
		return nil, aerr
	}
	if _, ok := c.keyEntry(a.ID); !ok {
		return nil, api.NotFound("network")
	}
	st := c.store.Get()
	if st.Gateway != nil && st.Gateway.Enabled && st.Gateway.NetworkID == a.ID {
		return nil, api.Errf(api.CodeInUse, http.StatusConflict, "this gateway serves that network; turn gateway mode off or switch its network first")
	}
	c.mu.Lock()
	s := c.sess
	c.mu.Unlock()
	if s != nil && s.netID == a.ID {
		c.clientDisconnect()
	}
	c.store.Update(func(st *state.State) error {
		kr := st.Keyring[:0]
		for _, k := range st.Keyring {
			if k.ID != a.ID {
				kr = append(kr, k)
			}
		}
		st.Keyring = kr
		if st.Gateway != nil && st.Gateway.NetworkID == a.ID {
			st.Gateway.NetworkID = ""
		}
		for i := range st.ManualGateways {
			if st.ManualGateways[i].NetworkID == a.ID {
				st.ManualGateways[i].NetworkID = ""
			}
		}
		return nil
	})
	c.mu.Lock()
	delete(c.subkeys, a.ID)
	c.mu.Unlock()
	c.keyringChanged()
	return nil, nil
}

func (c *core) keyringReveal(args []byte) (any, *api.Error) {
	a, aerr := decode[struct {
		ID string `json:"id"`
	}](args)
	if aerr != nil {
		return nil, aerr
	}
	k, ok := c.keyEntry(a.ID)
	if !ok {
		return nil, api.NotFound("network")
	}
	var key netkey.Key
	copy(key[:], k.Key)
	return map[string]any{"key_text": key.Text(), "label": k.Label}, nil
}
