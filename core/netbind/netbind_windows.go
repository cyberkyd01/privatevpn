//go:build windows

package netbind

import (
	"encoding/binary"
	"errors"
	"syscall"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

const (
	ipUnicastIf   = 31 // IP_UNICAST_IF
	ipv6UnicastIf = 31 // IPV6_UNICAST_IF
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
		h := windows.Handle(fd)
		if t.v6 {
			if p.index6 != 0 {
				opErr = windows.SetsockoptInt(h, windows.IPPROTO_IPV6, ipv6UnicastIf, int(p.index6))
			}
			if t.dual && p.index4 != 0 {
				// Best effort: covers IPv4 traffic on a dual-stack socket.
				_ = windows.SetsockoptInt(h, windows.IPPROTO_IP, ipUnicastIf, int(netOrder(p.index4)))
			}
			return
		}
		opErr = windows.SetsockoptInt(h, windows.IPPROTO_IP, ipUnicastIf, int(netOrder(p.index4)))
	})
	if err != nil {
		return err
	}
	return opErr
}

// netOrder converts an interface index to the network byte order that
// IP_UNICAST_IF expects for IPv4 (as in wireguard-go conn/bind_windows.go).
func netOrder(idx uint32) uint32 {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], idx)
	return binary.NativeEndian.Uint32(b[:])
}

func defaultInterfaces(exclude string) (uint32, uint32, error) {
	i4, err4 := defaultIndex(windows.AF_INET, exclude)
	i6, err6 := defaultIndex(windows.AF_INET6, exclude)
	if i4 == 0 && i6 == 0 {
		return 0, 0, errors.Join(errNoPhysical, err4, err6)
	}
	return i4, i6, nil
}

// defaultIndex returns the interface index of the lowest-metric default
// route of family that is up and not named exclude (cf. wireguard-windows
// tunnel/defaultroutemonitor.go).
func defaultIndex(family winipcfg.AddressFamily, exclude string) (uint32, error) {
	rows, err := winipcfg.GetIPForwardTable2(family)
	if err != nil {
		return 0, err
	}
	best, idx := ^uint32(0), uint32(0)
	for i := range rows {
		r := &rows[i]
		if r.DestinationPrefix.PrefixLength != 0 {
			continue
		}
		ifrow, err := r.InterfaceLUID.Interface()
		if err != nil || ifrow.OperStatus != winipcfg.IfOperStatusUp {
			continue
		}
		if exclude != "" && ifrow.Alias() == exclude {
			continue
		}
		ipif, err := r.InterfaceLUID.IPInterface(family)
		if err != nil {
			continue
		}
		if m := r.Metric + ipif.Metric; m < best {
			best, idx = m, r.InterfaceIndex
		}
	}
	return idx, nil
}
