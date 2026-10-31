package tunnel

import (
	"errors"
	"net/netip"
	"sort"
)

// Endpoint exclusion and dual-role host routes (§7.4, §9.2, §9.3).
//
// While the tunnel is up, its 0.0.0.0/1 + 128.0.0.0/1 routes capture all
// IPv4 traffic, including WireGuard's own packets to the gateway endpoint
// and the replies of this device's gateway role to off-LAN clients. Every
// such destination gets a /32 via the physical network, unless the routing
// table already has a more specific route for it (on-link LAN, corporate
// route), in which case nothing is added.
//
// The OS-specific code supplies the routing table (with our own tunnel
// interface and our own host routes removed) and add/delete primitives;
// everything else is pure and unit tested.

// rtEntry is one IPv4 routing table row.
type rtEntry struct {
	Dst     netip.Prefix
	Gateway netip.Addr // invalid or unspecified = on-link / interface route
	IfIndex uint64     // LUID on Windows, interface index on macOS
	IfName  string     // macOS (for "-interface" routes)
	Metric  uint32     // effective metric (route + interface) on Windows; 0 on macOS
}

// hostRoute is a /32 we install via the physical network.
type hostRoute struct {
	Dst     netip.Addr
	Gateway netip.Addr // invalid = interface route
	IfIndex uint64
	IfName  string
}

var errNoPhysicalRoute = errors.New("tunnel: no physical route to the gateway (offline?)")

// bestRoute returns the row the OS would use for dst: longest prefix, then
// lowest metric, then lowest interface index (deterministic tie-break).
func bestRoute(table []rtEntry, dst netip.Addr) (rtEntry, bool) {
	var best rtEntry
	found := false
	for _, e := range table {
		if !e.Dst.IsValid() || !e.Dst.Contains(dst) {
			continue
		}
		switch {
		case !found,
			e.Dst.Bits() > best.Dst.Bits(),
			e.Dst.Bits() == best.Dst.Bits() && e.Metric < best.Metric,
			e.Dst.Bits() == best.Dst.Bits() && e.Metric == best.Metric && e.IfIndex < best.IfIndex:
			best, found = e, true
		}
	}
	return best, found
}

// exclusionFor decides whether dst needs a /32 to bypass the tunnel's /1
// routes, and which one. need=false means the table already has a route
// more specific than /1 for dst.
func exclusionFor(table []rtEntry, dst netip.Addr) (r hostRoute, need bool, err error) {
	best, ok := bestRoute(table, dst)
	if !ok {
		return hostRoute{}, false, errNoPhysicalRoute
	}
	if best.Dst.Bits() > 1 {
		return hostRoute{}, false, nil
	}
	gw := best.Gateway
	if gw.IsValid() && gw.IsUnspecified() {
		gw = netip.Addr{}
	}
	return hostRoute{Dst: dst, Gateway: gw, IfIndex: best.IfIndex, IfName: best.IfName}, true, nil
}

// planHostRoutes computes the route changes that make installed match what
// wanted needs under table. Destinations without any physical route are
// reported in unreachable and their installed route (if any) is kept.
func planHostRoutes(table []rtEntry, wanted []netip.Addr, installed map[netip.Addr]hostRoute) (add, del []hostRoute, unreachable []netip.Addr) {
	want := make(map[netip.Addr]bool, len(wanted))
	for _, dst := range wanted {
		if want[dst] {
			continue
		}
		want[dst] = true
		cur, have := installed[dst]
		r, need, err := exclusionFor(table, dst)
		switch {
		case err != nil:
			unreachable = append(unreachable, dst)
		case !need:
			if have {
				del = append(del, cur)
			}
		case have && cur == r:
		default:
			if have {
				del = append(del, cur)
			}
			add = append(add, r)
		}
	}
	for dst, cur := range installed {
		if !want[dst] {
			del = append(del, cur)
		}
	}
	sortRoutes(add)
	sortRoutes(del)
	return add, del, unreachable
}

func sortRoutes(rs []hostRoute) {
	sort.Slice(rs, func(i, j int) bool { return rs[i].Dst.Less(rs[j].Dst) })
}

// routeOps is the OS-specific part of host route management.
type routeOps interface {
	// table returns the IPv4 routing table without our tunnel interface's
	// routes and without host routes we installed.
	table() ([]rtEntry, error)
	add(r hostRoute) error
	del(r hostRoute) error
}

// hostRoutes tracks wanted and installed host routes. Not goroutine-safe:
// the owning tunnel serialises access with its mutex.
type hostRoutes struct {
	ops       routeOps
	hosts     map[netip.Addr]struct{} // dual-role destinations (RouteAdd)
	endpoint  netip.Addr              // valid while the tunnel is up
	active    bool                    // tunnel up: routes are wanted
	installed map[netip.Addr]hostRoute
	epOK      bool
}

func newHostRoutes(ops routeOps) *hostRoutes {
	return &hostRoutes{ops: ops, hosts: map[netip.Addr]struct{}{}, installed: map[netip.Addr]hostRoute{}}
}

func (h *hostRoutes) addHost(dst netip.Addr) error {
	if _, ok := h.hosts[dst]; !ok && len(h.hosts) >= MaxHostRoutes {
		return errTooManyHost
	}
	h.hosts[dst] = struct{}{}
	return h.reconcile()
}

func (h *hostRoutes) delHost(dst netip.Addr) error {
	delete(h.hosts, dst)
	return h.reconcile()
}

// start makes routes wanted for endpoint ep and the known hosts.
func (h *hostRoutes) start(ep netip.Addr) error {
	h.active, h.endpoint = true, ep
	return h.reconcile()
}

func (h *hostRoutes) setEndpoint(ep netip.Addr) error {
	h.endpoint = ep
	return h.reconcile()
}

// stop removes every installed route; the host set is kept for the next start.
func (h *hostRoutes) stop() error {
	h.active, h.endpoint, h.epOK = false, netip.Addr{}, false
	return h.reconcile()
}

func (h *hostRoutes) endpointOK() bool { return h.active && h.epOK }

// reconcile applies the plan. It keeps going after individual failures and
// returns the first error. Errors contain no addresses.
func (h *hostRoutes) reconcile() error {
	var wanted []netip.Addr
	var table []rtEntry
	if h.active {
		if h.endpoint.IsValid() {
			wanted = append(wanted, h.endpoint)
		}
		for dst := range h.hosts {
			wanted = append(wanted, dst)
		}
		var err error
		if table, err = h.ops.table(); err != nil {
			h.epOK = false
			return err
		}
	}
	add, del, unreachable := planHostRoutes(table, wanted, h.installed)
	var first error
	for _, r := range del {
		if err := h.ops.del(r); err != nil && first == nil {
			first = err
		}
		// Forget it even on failure: retrying a delete of a route that
		// is gone is pointless, and a stale one is swept at next start.
		delete(h.installed, r.Dst)
	}
	for _, r := range add {
		if err := h.ops.add(r); err != nil {
			if first == nil {
				first = err
			}
			continue
		}
		h.installed[r.Dst] = r
	}
	if h.active && h.endpoint.IsValid() {
		h.epOK = true
		for _, u := range unreachable {
			if u == h.endpoint {
				h.epOK = false
				if first == nil {
					first = errNoPhysicalRoute
				}
			}
		}
		for _, r := range add {
			if _, ok := h.installed[r.Dst]; !ok && r.Dst == h.endpoint {
				h.epOK = false
			}
		}
	}
	return first
}
