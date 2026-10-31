//go:build darwin

package netbind

import (
	"net"
	"syscall"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

func control(network, address string, c syscall.RawConn) error {
	t, bind := classify(network, address)
	if !bind {
		return nil
	}
	p := phys.Load()
	if p == nil {
		return errNoPhysical
	}
	if (t.v6 && p.index6 == 0 && !t.dual) || (!t.v6 && p.index4 == 0) {
		return errNoPhysical
	}
	var opErr error
	err := c.Control(func(fd uintptr) {
		if t.v6 {
			// IPV6_BOUND_IF also scopes IPv4 traffic on a dual-stack socket.
			idx := p.index6
			if idx == 0 {
				idx = p.index4
			}
			opErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF, int(idx))
			return
		}
		opErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_BOUND_IF, int(p.index4))
	})
	if err != nil {
		return err
	}
	return opErr
}

// defaultInterfaces reads the routing table. macOS has no route metrics: the
// unscoped default route is the primary one; interface-scoped defaults on
// non-point-to-point interfaces are a fallback (system utuns carry scoped
// IPv6 defaults that lead nowhere).
func defaultInterfaces(exclude string) (uint32, uint32, error) {
	rib, err := route.FetchRIB(syscall.AF_UNSPEC, route.RIBTypeRoute, 0)
	if err != nil {
		return 0, 0, err
	}
	msgs, err := route.ParseRIB(route.RIBTypeRoute, rib)
	if err != nil {
		return 0, 0, err
	}
	var best4, best6, scoped4, scoped6 uint32
	for _, m := range msgs {
		rm, ok := m.(*route.RouteMessage)
		if !ok || rm.Flags&unix.RTF_UP == 0 || rm.Flags&unix.RTF_HOST != 0 || len(rm.Addrs) <= unix.RTAX_NETMASK {
			continue
		}
		v6, ok := isDefault(rm.Addrs[unix.RTAX_DST], rm.Addrs[unix.RTAX_NETMASK])
		if !ok || rm.Index <= 0 {
			continue
		}
		ifc, err := net.InterfaceByIndex(rm.Index)
		if err != nil || ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 || (exclude != "" && ifc.Name == exclude) {
			continue
		}
		idx := uint32(rm.Index)
		scoped := rm.Flags&unix.RTF_IFSCOPE != 0
		if scoped && ifc.Flags&net.FlagPointToPoint != 0 {
			continue
		}
		switch {
		case !v6 && !scoped && best4 == 0:
			best4 = idx
		case !v6 && scoped && scoped4 == 0:
			scoped4 = idx
		case v6 && !scoped && best6 == 0:
			best6 = idx
		case v6 && scoped && scoped6 == 0:
			scoped6 = idx
		}
	}
	if best4 == 0 {
		best4 = scoped4
	}
	if best6 == 0 {
		best6 = scoped6
	}
	if best4 == 0 && best6 == 0 {
		return 0, 0, errNoPhysical
	}
	return best4, best6, nil
}

// isDefault reports whether dst/mask is 0.0.0.0/0 or ::/0, and its family.
func isDefault(dst, mask route.Addr) (v6, ok bool) {
	zeroMask := func(want int) bool {
		switch m := mask.(type) {
		case nil:
			return true
		case *route.Inet4Addr:
			return want == 4 && m.IP == [4]byte{}
		case *route.Inet6Addr:
			return want == 6 && m.IP == [16]byte{}
		}
		return false
	}
	switch a := dst.(type) {
	case *route.Inet4Addr:
		return false, a.IP == [4]byte{} && zeroMask(4)
	case *route.Inet6Addr:
		return true, a.IP == [16]byte{} && zeroMask(6)
	}
	return false, false
}
