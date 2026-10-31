//go:build android

package engine

import (
	"context"
	"encoding/json"
	"net"
	"net/netip"
	"sync/atomic"

	"github.com/cyberkyd01/privatevpn/core/api"
	"github.com/cyberkyd01/privatevpn/core/state"
	"github.com/cyberkyd01/privatevpn/core/sysinfo"
)

// Android is client-only (ARCHITECTURE D26): no gateway role exists.
type gatewayRole struct{ subnet netip.Prefix }

func (r *gatewayRole) refreshPolicy()  {}
func (r *gatewayRole) networkChanged() {}

func init() {
	for _, m := range []string{api.GatewayEnable, api.GatewayDisable, api.GatewaySetNetwork, api.GatewayResetKey, api.FirewallAdd} {
		handle(m, func(c *core, _ []byte) (any, *api.Error) { return nil, api.Unsupported() })
	}
}

func (c *core) gatewayEnable() *api.Error  { return api.Unsupported() }
func (c *core) gatewayStop()               {}
func (c *core) selfItem() *gwItem          { return nil }
func (c *core) applyLANAccess(bool)        {}
func (c *core) restartGateway() *api.Error { return nil }
func (c *core) gatewayStatus(state.State) map[string]any {
	return map[string]any{"enabled": false, "network": nil, "clients": 0, "supported": false}
}

var mobileDNS atomic.Value // []string

// applyMobileInfo pulls OS details and the underlying network's resolvers
// from Kotlin; Go's resolver cannot read them itself on Android (§11.2).
func (c *core) applyMobileInfo() {
	fn := c.e.opts.Platform.MobileSystemInfo
	if fn == nil {
		return
	}
	var si struct {
		OSVersion string   `json:"os_version"`
		Model     string   `json:"model"`
		TZ        string   `json:"tz"`
		DNS       []string `json:"dns"`
	}
	if json.Unmarshal([]byte(fn()), &si) != nil {
		return
	}
	var dns []string
	for _, s := range si.DNS {
		if ip, err := netip.ParseAddr(s); err == nil && len(dns) < 4 {
			dns = append(dns, netip.AddrPortFrom(ip, 53).String())
		}
	}
	if len(dns) == 0 {
		dns = []string{"1.1.1.1:53", "9.9.9.9:53"}
	}
	sysinfo.SetMobileInfo(clean(si.OSVersion, 32), clean(si.Model, 32), clean(si.TZ, 64), si.DNS)
	mobileDNS.Store(dns)
	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			list, _ := mobileDNS.Load().([]string)
			var d net.Dialer
			var lastErr error
			for _, s := range list {
				conn, err := d.DialContext(ctx, network, s)
				if err == nil {
					return conn, nil
				}
				lastErr = err
			}
			return nil, lastErr
		},
	}
}
