package engine

import "github.com/cyberkyd01/privatevpn/core/state"

// problem is one entry of status.problems: everything the user should know
// is wrong, in plain words, with a suggested action for the UI.
type problem struct {
	Code     string `json:"code"`
	Severity string `json:"severity"` // error | warning | info
	Message  string `json:"message"`
	Action   string `json:"action,omitempty"` // disconnect | reconnect | add_firewall | settings
}

// tunnelWarnings maps tunnel.Status.Warnings codes to user-facing problems.
var tunnelWarnings = map[string]problem{
	"ipv6_not_blocked": {Severity: "error", Action: "disconnect",
		Message: "IPv6 traffic could not be blocked on this device — websites that support IPv6 may see your real IPv6 address. Disable IPv6 on your network adapter or disconnect."},
	"dns_not_set": {Severity: "error", Action: "disconnect",
		Message: "System DNS could not be pointed at the VPN — name lookups may go to your Internet provider instead of through the gateway."},
	"kill_switch_failed": {Severity: "error", Action: "reconnect",
		Message: "The kill switch could not be installed — if the VPN drops, traffic would use your real IP. Reconnect to try again."},
	"kill_switch_not_persistent": {Severity: "warning",
		Message: "The kill switch works now but could not be set up to survive a restart — right after rebooting, apps could use your real IP until PrivateVPN reconnects."},
	"lan_not_blocked": {Severity: "info",
		Message: "Devices on your local network stay reachable while the kill switch blocks the Internet (this system cannot block the local network)."},
	"dns_not_blocked": {Severity: "warning",
		Message: "This system is too old to confine DNS while the VPN is down — if the connection drops, name lookups could reach your local router."},
}

// clientProblems describes the client role. sessState is "" without a session.
// ks reports whether the kill switch protects the current session (or, with
// no session, whether it is enabled).
func (c *core) clientProblems(st state.State, sessState string, sessProblem, lastErr string, lastCode string, warnings []string, ks bool) []problem {
	var out []problem
	switch sessState {
	case "":
		engaged := !isAndroid && st.Client != nil && st.Client.KillSwitchEngaged
		if engaged {
			out = append(out, problem{Code: "kill_switch_engaged", Severity: "error", Action: "disconnect",
				Message: "Internet access is blocked by the kill switch because the previous VPN session ended unexpectedly. Reconnect to a gateway, or Disconnect to restore direct Internet access."})
		}
		if lastErr != "" {
			tail := " Your traffic is not going through the VPN."
			if engaged {
				tail = " Internet access stays blocked until you reconnect or disconnect."
			}
			out = append(out, problem{Code: lastCode, Severity: "error", Action: "reconnect",
				Message: "Could not connect: " + lastErr + "." + tail})
		}
	case "blocked":
		out = append(out, problem{Code: "blocked", Severity: "error", Action: "reconnect", Message: firstNonEmpty(sessProblem,
			"The VPN connection failed. Your traffic stays blocked to protect your real IP; Reconnect, or Disconnect to use the Internet without the VPN.")})
	case "degraded":
		msg := firstNonEmpty(sessProblem, "Lost contact with the gateway — traffic is held in the tunnel; reconnecting automatically.")
		if !ks && !isAndroid {
			msg += " (Kill switch is off.)"
		}
		out = append(out, problem{Code: "degraded", Severity: "error", Action: "disconnect", Message: msg})
	}
	if sessState != "" {
		dnsConfined := ks && !isAndroid && !hasWarning(warnings, "dns_not_blocked")
		for _, w := range warnings {
			if p, ok := tunnelWarnings[w]; ok {
				p.Code = w
				if w == "dns_not_set" && dnsConfined {
					// The kill switch blocks every other resolver: lookups
					// fail rather than leak.
					p.Message = "System DNS could not be pointed at the VPN. The kill switch blocks name lookups to any other resolver, so websites will not resolve (nothing leaks to your Internet provider). Reconnect to try again, or disconnect."
					p.Action = "reconnect"
				}
				out = append(out, p)
			}
		}
		if !isAndroid && !ks {
			out = append(out, problem{Code: "kill_switch_off", Severity: "warning", Action: "settings",
				Message: "Kill switch is off: if the VPN connection drops, apps will use your real IP address."})
		}
	}
	return out
}

// gatewayProblems describes the gateway role from its status document.
func (c *core) gatewayProblems(g map[string]any) []problem {
	var out []problem
	if g == nil || g["enabled"] != true {
		return out
	}
	switch g["firewall_rule"] {
	case "missing":
		out = append(out, problem{Code: "firewall_missing", Severity: "error", Action: "add_firewall",
			Message: "Windows Firewall is blocking incoming VPN connections, so other devices cannot connect. Click \"Add firewall rule\" (needs administrator approval)."})
	case "unknown":
		out = append(out, problem{Code: "firewall_unknown", Severity: "warning", Action: "add_firewall",
			Message: "Could not check the Windows Firewall rule. If devices cannot connect, click \"Add firewall rule\"."})
	}
	if g["nat"] == "cgnat" {
		out = append(out, problem{Code: "cgnat", Severity: "info",
			Message: "This network uses carrier-grade NAT: the gateway is reachable on this LAN only."})
	}
	return out
}

func (c *core) discoveryProblems() []problem {
	c.mu.Lock()
	ok := c.recv != nil
	c.mu.Unlock()
	if ok {
		return nil
	}
	return []problem{{Code: "discovery_unavailable", Severity: "warning",
		Message: "Gateway discovery is not working (UDP port 51822 is in use or blocked), so gateways on your network cannot be listed automatically. Use \"Add gateway by address\"."}}
}

func hasWarning(ws []string, code string) bool {
	for _, w := range ws {
		if w == code {
			return true
		}
	}
	return false
}

func firstNonEmpty(a ...string) string {
	for _, s := range a {
		if s != "" {
			return s
		}
	}
	return ""
}
