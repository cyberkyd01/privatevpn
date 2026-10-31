package gwstack

import (
	"io"
	"net"
	"net/netip"
	"sync"

	"github.com/cyberkyd01/privatevpn/core/netbind"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const tcpBufSize = 32 << 10

// handleTCP runs in its own goroutine per SYN (§8.3). Every path completes r
// exactly once; refusals send RST.
func (d *Device) handleTCP(r *tcp.ForwarderRequest) {
	id := r.ID()
	c := d.lookup(addrOf(id.RemoteAddress))
	if c == nil {
		r.Complete(true)
		return
	}
	dst := netip.AddrPortFrom(addrOf(id.LocalAddress), id.LocalPort)
	v := d.policy.Check(dst)
	if v == Deny {
		r.Complete(true)
		return
	}
	f := d.admit(c, false)
	if f == nil {
		r.Complete(true)
		return
	}
	var out net.Conn
	if v == Forward {
		var err error
		out, err = netbind.Dialer(d.cfg.Limits.TCPDialTimeout).DialContext(c.ctx, "tcp4", d.target(dst))
		if err != nil {
			f.close()
			r.Complete(true)
			return
		}
	}
	var wq waiter.Queue
	ep, terr := r.CreateEndpoint(&wq)
	if terr != nil {
		if out != nil {
			out.Close()
		}
		f.close()
		r.Complete(true)
		return
	}
	r.Complete(false)
	in := gonet.NewTCPConn(&wq, ep)

	if v == LocalDNS {
		if f.attach(d.cfg.Limits.DNSIdle, in) {
			d.serveDNSTCP(f, c, in)
		}
		return
	}
	tc, ok := out.(*net.TCPConn)
	if !ok {
		in.Close()
		out.Close()
		f.close()
		return
	}
	tc.SetKeepAlive(true)
	if f.attach(d.cfg.Limits.TCPIdle, in, tc) {
		splice(f, in, tc)
	}
}

type halfCloser interface {
	io.ReadWriter
	CloseWrite() error
}

// splice copies both directions, propagating half-close, until both ends
// are done or either fails.
func splice(f *flow, a, b halfCloser) {
	var wg sync.WaitGroup
	wg.Add(2)
	cp := func(dst, src halfCloser) {
		defer wg.Done()
		buf := make([]byte, tcpBufSize)
		_, err := io.CopyBuffer(writerOnly{dst}, activityReader{src, f}, buf)
		if err != nil {
			f.close()
			return
		}
		dst.CloseWrite()
	}
	go cp(b, a)
	cp(a, b)
	wg.Wait()
	f.close()
}

// activityReader records activity for the idle timer; with writerOnly it
// hides WriterTo/ReaderFrom so io.CopyBuffer uses the bounded buffer.
type activityReader struct {
	r io.Reader
	f *flow
}

func (a activityReader) Read(p []byte) (int, error) {
	n, err := a.r.Read(p)
	if n > 0 {
		a.f.touch()
	}
	return n, err
}

type writerOnly struct{ io.Writer }
