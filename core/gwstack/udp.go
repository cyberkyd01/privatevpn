package gwstack

import (
	"errors"
	"net"
	"net/netip"

	"github.com/cyberkyd01/private-vpn-pro/core/netbind"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const (
	udpBufSize      = 65535
	udpMaxTransient = 8 // consecutive soft errors (e.g. ICMP-induced) before a direction gives up
)

// handleUDP runs on the packet path for the first datagram of a new
// association (§8.4). Returning false drops it silently (ICMP errors are
// disabled on the stack).
func (d *Device) handleUDP(r *udp.ForwarderRequest) bool {
	id := r.ID()
	c := d.lookup(addrOf(id.RemoteAddress))
	if c == nil {
		return false
	}
	dst := netip.AddrPortFrom(addrOf(id.LocalAddress), id.LocalPort)
	v := d.policy.Check(dst)
	if v == Deny {
		return false
	}
	f := d.admit(c, true)
	if f == nil {
		return false
	}
	var wq waiter.Queue
	ep, err := r.CreateEndpoint(&wq)
	if err != nil {
		f.close()
		return true // CreateEndpoint consumed the packet
	}
	in := gonet.NewUDPConn(&wq, ep)
	if v == LocalDNS {
		if f.attach(d.cfg.Limits.DNSIdle, in) {
			go d.serveDNSUDP(f, c, in)
		}
		return true
	}
	go d.forwardUDP(f, c, in, dst)
	return true
}

func (d *Device) forwardUDP(f *flow, c *Client, in *gonet.UDPConn, dst netip.AddrPort) {
	out, err := netbind.Dialer(0).DialContext(c.ctx, "udp4", d.target(dst))
	if err != nil {
		in.Close()
		f.close()
		return
	}
	idle := d.cfg.Limits.UDPIdle
	if dst.Port() == 53 {
		idle = d.cfg.Limits.DNSIdle
	}
	if !f.attach(idle, in, out) {
		return
	}
	go copyDatagrams(f, out, in)
	copyDatagrams(f, in, out)
	f.close()
}

// copyDatagrams relays datagrams src→dst until the flow closes. Connected UDP
// sockets report ICMP errors on later calls; those are tolerated.
func copyDatagrams(f *flow, dst, src net.Conn) {
	buf := make([]byte, udpBufSize)
	soft := 0
	for {
		n, err := src.Read(buf)
		if err != nil {
			if f.isClosed() || errors.Is(err, net.ErrClosed) || soft >= udpMaxTransient {
				f.close()
				return
			}
			soft++
			continue
		}
		soft = 0
		f.touch()
		if _, err := dst.Write(buf[:n]); err != nil && (f.isClosed() || errors.Is(err, net.ErrClosed)) {
			f.close()
			return
		}
	}
}
