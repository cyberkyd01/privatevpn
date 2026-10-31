package engine

import (
	"math"
	"net/netip"
	"time"

	"github.com/cyberkyd01/privatevpn/core/api"
	"github.com/cyberkyd01/privatevpn/core/state"
	"github.com/cyberkyd01/privatevpn/core/sysinfo"
)

func init() {
	handle(api.StatusGet, func(c *core, _ []byte) (any, *api.Error) { return c.statusDoc(), nil })
	handle(api.SettingsGet, func(c *core, _ []byte) (any, *api.Error) { return c.settingsDoc(), nil })
	handle(api.SettingsSet, (*core).settingsSet)
	handle(api.LogGet, func(c *core, _ []byte) (any, *api.Error) {
		return map[string]any{"lines": c.log.Lines()}, nil
	})
	handle(api.AppQuit, func(c *core, _ []byte) (any, *api.Error) {
		go func() {
			c.quit()
			if q := c.e.opts.Platform.Quit; q != nil {
				q()
			}
		}()
		return nil, nil
	})
	handle(api.SysNetworkChanged, func(c *core, _ []byte) (any, *api.Error) {
		go c.networkChanged()
		return nil, nil
	})
}

func (c *core) statusDoc() map[string]any {
	st := c.store.Get()
	c.mu.Lock()
	s, lastErr, resuming := c.sess, c.lastErr, c.resuming
	c.mu.Unlock()

	// resume_pending: the restart resume is still trying (or its own attempt
	// is in flight). Once it gave up — prompt declined, tunnel refused — it
	// is false, so the UI never promises a reconnect that will not happen.
	resumePending := resuming && st.Client != nil && st.Client.AutoReconnect && st.Client.ResumeGatewayID != "" &&
		(s == nil || s.gwID == st.Client.ResumeGatewayID)
	client := map[string]any{"state": "idle", "gateway_id": "", "gateway_name": "", "network_label": "",
		"assigned_ip": "", "since": 0, "rx": 0, "tx": 0, "handshake_age_sec": -1, "degraded_since": 0, "error": "",
		"protected": false, "kill_switch": killSwitchMode(st), "resume_pending": resumePending}
	lastMsg, lastCode := "", ""
	if lastErr != nil {
		client["error"] = lastErr.Message
		client["error_code"] = lastErr.Code
		lastMsg, lastCode = lastErr.Message, lastErr.Code
	}
	sessState, sessProblem := "", ""
	var warnings []string
	if s == nil && !isAndroid && st.Client != nil && st.Client.KillSwitchEngaged {
		client["state"] = "blocked"
	}
	if s != nil {
		s.mu.Lock()
		sessState = s.state
		if s.problem != nil {
			sessProblem = s.problem.Message
			client["error"], client["error_code"] = s.problem.Message, s.problem.Code
		}
		warnings = append(warnings, s.st.Warnings...)
		client["kill_switch_active"] = s.st.KillSwitchActive
		if s.tunUp {
			client["kill_switch"] = map[bool]string{true: "on", false: "off"}[s.ks]
			if isAndroid {
				client["kill_switch"] = "os"
			}
		}
		client["protected"] = s.state == "connected" && len(s.st.Warnings) == 0
		client["state"] = s.state
		client["gateway_id"] = s.gwID
		client["gateway_name"] = s.name
		client["network_label"] = s.netLabel
		if s.resp.Assigned.IsValid() {
			client["assigned_ip"] = s.resp.Assigned.String()
		}
		client["since"] = s.since.Unix()
		client["rx"] = s.st.RxBytes
		client["tx"] = s.st.TxBytes
		client["handshake_age_sec"] = s.st.HandshakeAgeSec
		if !s.degradedSince.IsZero() {
			client["degraded_since"] = s.degradedSince.Unix()
		}
		s.mu.Unlock()
	}
	doc := map[string]any{
		"version":     c.e.opts.AppVersion,
		"os":          sysinfo.OSName(),
		"device_name": st.DeviceName,
		"keyring":     map[string]any{"count": len(st.Keyring)},
		"client":      client,
	}
	problems := c.clientProblems(st, sessState, sessProblem, lastMsg, lastCode, warnings, client["kill_switch"] == "on")
	if st.Gateway != nil {
		g := c.gatewayStatus(st)
		doc["gateway"] = g
		doc["dual_role"] = s != nil && g["enabled"] == true
		problems = append(problems, c.gatewayProblems(g)...)
	} else {
		doc["gateway"] = map[string]any{"enabled": false, "network": nil, "clients": 0, "supported": false}
		doc["dual_role"] = false
	}
	problems = append(problems, c.discoveryProblems()...)
	if problems == nil {
		problems = []problem{}
	}
	doc["problems"] = problems
	return doc
}

// killSwitchMode: "on"/"off" on desktop, "os" on Android (the system's
// "Block connections without VPN" setting is the kill switch there).
func killSwitchMode(st state.State) string {
	if isAndroid {
		return "os"
	}
	if st.Client != nil && st.Client.KillSwitch {
		return "on"
	}
	return "off"
}

type geoManualDoc struct {
	Country string   `json:"country"`
	Region  string   `json:"region"`
	City    string   `json:"city"`
	Lat     *float64 `json:"lat"`
	Lon     *float64 `json:"lon"`
	TZName  string   `json:"tz_name"`
}

func (c *core) settingsDoc() map[string]any {
	st := c.store.Get()
	doc := map[string]any{"ui": st.UI}
	if st.Client != nil {
		doc["client"] = map[string]any{"kill_switch": st.Client.KillSwitch, "allow_lan": st.Client.AllowLAN,
			"auto_reconnect": st.Client.AutoReconnect}
	}
	if !isAndroid {
		doc["device_name"] = st.DeviceName
	}
	if g := st.Gateway; g != nil {
		dns := g.DNSUpstream
		if dns == nil {
			dns = []string{}
		}
		doc["gateway"] = map[string]any{"wg_port": g.WGPort, "ctrl_port": g.CtrlPort, "subnet": g.Subnet,
			"lan_access": g.LANAccess, "dns_upstream": dns,
			"geo": map[string]any{"enabled": g.Geo.Enabled, "manual": g.Geo.Manual}}
	}
	return doc
}

func (c *core) settingsSet(args []byte) (any, *api.Error) {
	a, aerr := decode[struct {
		DeviceName *string `json:"device_name"`
		Gateway    *struct {
			WGPort      *int      `json:"wg_port"`
			CtrlPort    *int      `json:"ctrl_port"`
			Subnet      *string   `json:"subnet"`
			LANAccess   *bool     `json:"lan_access"`
			DNSUpstream *[]string `json:"dns_upstream"`
			Geo         *struct {
				Enabled *bool         `json:"enabled"`
				Manual  *geoManualDoc `json:"manual"`
				Clear   bool          `json:"clear_manual"`
			} `json:"geo"`
		} `json:"gateway"`
		Client *struct {
			KillSwitch    *bool `json:"kill_switch"`
			AllowLAN      *bool `json:"allow_lan"`
			AutoReconnect *bool `json:"auto_reconnect"`
		} `json:"client"`
		UI *struct {
			Port      *int    `json:"port"`
			Autostart *bool   `json:"autostart"`
			Theme     *string `json:"theme"`
		} `json:"ui"`
	}](args)
	if aerr != nil {
		return nil, aerr
	}
	restart := false
	var lan *bool
	var autostart *bool
	err := c.store.Update(func(st *state.State) error {
		if a.DeviceName != nil {
			if isAndroid {
				return api.Unsupported()
			}
			n := clean(*a.DeviceName, 32)
			if n == "" {
				return api.BadRequest("device name must not be empty")
			}
			st.DeviceName = n
		}
		if g := a.Gateway; g != nil {
			if st.Gateway == nil {
				return api.Unsupported()
			}
			if g.WGPort != nil {
				if !validPort(*g.WGPort) {
					return api.BadRequest("ports must be 1024–65535")
				}
				restart = restart || st.Gateway.WGPort != *g.WGPort
				st.Gateway.WGPort = *g.WGPort
			}
			if g.CtrlPort != nil {
				if !validPort(*g.CtrlPort) {
					return api.BadRequest("ports must be 1024–65535")
				}
				restart = restart || st.Gateway.CtrlPort != *g.CtrlPort
				st.Gateway.CtrlPort = *g.CtrlPort
			}
			if st.Gateway.WGPort == st.Gateway.CtrlPort || st.Gateway.WGPort == 51822 || st.Gateway.CtrlPort == 51822 {
				return api.BadRequest("WireGuard, control and discovery (51822) ports must differ")
			}
			if g.Subnet != nil {
				s := *g.Subnet
				if s != "" {
					p, err := netip.ParsePrefix(s)
					if err != nil || p.Bits() != 24 || !p.Addr().Is4() || !p.Addr().IsPrivate() {
						return api.BadRequest("subnet must be a private /24, e.g. 10.77.42.0/24")
					}
					s = p.Masked().String()
				}
				restart = restart || st.Gateway.Subnet != s
				st.Gateway.Subnet = s
			}
			if g.LANAccess != nil {
				st.Gateway.LANAccess = *g.LANAccess
				lan = g.LANAccess
			}
			if g.DNSUpstream != nil {
				var dns []string
				for _, s := range *g.DNSUpstream {
					ip, err := netip.ParseAddr(s)
					if err != nil || len(dns) >= 4 {
						return api.BadRequest("DNS servers must be up to 4 IP addresses")
					}
					dns = append(dns, ip.String())
				}
				st.Gateway.DNSUpstream = dns
			}
			if ge := g.Geo; ge != nil {
				if ge.Enabled != nil {
					st.Gateway.Geo.Enabled = *ge.Enabled
				}
				if ge.Clear {
					st.Gateway.Geo.Manual = nil
				} else if m := ge.Manual; m != nil {
					if (m.Lat == nil) != (m.Lon == nil) ||
						(m.Lat != nil && (math.IsNaN(*m.Lat) || *m.Lat < -90 || *m.Lat > 90 || math.IsNaN(*m.Lon) || *m.Lon < -180 || *m.Lon > 180)) {
						return api.BadRequest("latitude/longitude out of range")
					}
					if m.TZName != "" && !tzNameRE.MatchString(m.TZName) {
						return api.BadRequest("invalid time zone name")
					}
					st.Gateway.Geo.Manual = &state.GeoManual{Country: clean(m.Country, 64), Region: clean(m.Region, 64),
						City: clean(m.City, 64), Lat: m.Lat, Lon: m.Lon, TZName: m.TZName}
				}
			}
		}
		if cl := a.Client; cl != nil {
			if isAndroid {
				return api.Unsupported() // Android: use the system's always-on / block setting
			}
			if st.Client == nil {
				st.Client = &state.Client{KillSwitch: true, AllowLAN: true}
			}
			if cl.KillSwitch != nil {
				st.Client.KillSwitch = *cl.KillSwitch
			}
			if cl.AllowLAN != nil {
				st.Client.AllowLAN = *cl.AllowLAN
			}
			if cl.AutoReconnect != nil {
				st.Client.AutoReconnect = *cl.AutoReconnect
			}
		}
		if u := a.UI; u != nil {
			if u.Port != nil {
				if !validPort(*u.Port) {
					return api.BadRequest("ports must be 1024–65535")
				}
				st.UI.Port = *u.Port
			}
			if u.Theme != nil {
				switch *u.Theme {
				case "system", "light", "dark":
					st.UI.Theme = *u.Theme
				default:
					return api.BadRequest("theme must be system, light or dark")
				}
			}
			if u.Autostart != nil {
				st.UI.Autostart = *u.Autostart
				autostart = u.Autostart
			}
		}
		return nil
	})
	if err != nil {
		if ae, ok := err.(*api.Error); ok {
			return nil, ae
		}
		return nil, api.Internal(err)
	}
	if autostart != nil && c.e.opts.Platform.SetAutostart != nil {
		if err := c.e.opts.Platform.SetAutostart(*autostart); err != nil {
			c.log.Printf("app", "autostart: %s", errClass(err))
		}
	}
	if lan != nil {
		c.applyLANAccess(*lan)
	}
	if restart {
		if aerr := c.restartGateway(); aerr != nil {
			return nil, aerr
		}
	}
	c.emitStatus()
	c.gatewaysChanged()
	return c.settingsDoc(), nil
}

func validPort(p int) bool { return p >= 1024 && p <= 65535 }

var _ = time.Second
