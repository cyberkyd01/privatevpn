package gwstack

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"io"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/cyberkyd01/private-vpn-pro/core/netbind"
	"golang.org/x/net/dns/dnsmessage"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
)

// DNS forwarder (§8.6): no cache, no logging, fresh upstream socket and
// random transaction ID per query.
const (
	dnsMinLen     = 12
	dnsMaxQuery   = 1232
	dnsMaxResp    = 4096
	dnsClassicUDP = 512
	dnsStagger    = time.Second // delay before also asking the next upstream
)

var fallbackUpstreams = []netip.AddrPort{
	netip.MustParseAddrPort("1.1.1.1:53"),
	netip.MustParseAddrPort("9.9.9.9:53"),
}

type dnsForwarder struct {
	upstreams func() []netip.AddrPort
	timeout   time.Duration
}

// query is a validated client query to forward. String() is redacted.
type query struct {
	msg     []byte
	hdr     dnsmessage.Header
	q       dnsmessage.Question
	udpSize int // client's UDP payload limit (EDNS0, else 512)
}

func (*query) String() string { return "<redacted>" }

// parseQuery validates a client message. It returns either a query to
// forward, or a response to send as is (FORMERR, AAAA, ANY); both nil means
// drop (too short to answer, or not a query).
func parseQuery(msg []byte) (*query, []byte) {
	if len(msg) < dnsMinLen {
		return nil, nil
	}
	var p dnsmessage.Parser
	h, err := p.Start(msg)
	if err != nil || h.Response {
		return nil, nil
	}
	if len(msg) > dnsMaxQuery || h.OpCode != 0 {
		return nil, reply(h, nil, dnsmessage.RCodeFormatError)
	}
	qs, err := p.AllQuestions()
	if err != nil || len(qs) != 1 {
		return nil, reply(h, nil, dnsmessage.RCodeFormatError)
	}
	if p.SkipAllAnswers() != nil || p.SkipAllAuthorities() != nil {
		return nil, reply(h, nil, dnsmessage.RCodeFormatError)
	}
	size := dnsClassicUDP
	for {
		rh, err := p.AdditionalHeader()
		if err == dnsmessage.ErrSectionDone {
			break
		}
		if err != nil || p.SkipAdditional() != nil {
			return nil, reply(h, nil, dnsmessage.RCodeFormatError)
		}
		if rh.Type == dnsmessage.TypeOPT {
			size = min(max(int(rh.Class), dnsClassicUDP), dnsMaxResp)
		}
	}
	q := qs[0]
	switch q.Type {
	case dnsmessage.TypeAAAA: // D14: IPv6 is sunk, answer "no addresses"
		return nil, reply(h, &q, dnsmessage.RCodeSuccess)
	case dnsmessage.TypeALL:
		return nil, reply(h, &q, dnsmessage.RCodeNotImplemented)
	}
	return &query{msg: slices.Clone(msg), hdr: h, q: q, udpSize: size}, nil
}

// reply builds a locally generated response with no records.
func reply(h dnsmessage.Header, q *dnsmessage.Question, rc dnsmessage.RCode) []byte {
	b := dnsmessage.NewBuilder(make([]byte, 0, 512), dnsmessage.Header{
		ID:                 h.ID,
		Response:           true,
		OpCode:             h.OpCode,
		RecursionDesired:   h.RecursionDesired,
		RecursionAvailable: true,
		CheckingDisabled:   h.CheckingDisabled,
		RCode:              rc,
	})
	b.EnableCompression()
	if q != nil {
		if b.StartQuestions() != nil || b.Question(*q) != nil {
			return nil
		}
	}
	out, err := b.Finish()
	if err != nil {
		return nil
	}
	return out
}

// resolve forwards q and returns the response for the client (its ID
// restored), at most limit bytes unless only a truncated answer exists, or
// SERVFAIL. Upstreams are tried in order, the next one joining after
// dnsStagger or on failure; the first good answer wins.
func (f *dnsForwarder) resolve(ctx context.Context, q *query, limit int) []byte {
	var ups []netip.AddrPort
	if f.upstreams != nil {
		ups = f.upstreams()
	}
	if len(ups) == 0 {
		ups = fallbackUpstreams
	}
	ctx, cancel := context.WithTimeout(ctx, f.timeout)
	defer cancel()
	results := make(chan []byte, len(ups))
	next, pending := 0, 0
	launch := func() {
		up := ups[next]
		next++
		pending++
		go func() { results <- f.exchange(ctx, up, q, limit) }()
	}
	launch()
	stagger := time.NewTimer(dnsStagger)
	defer stagger.Stop()
	var soft []byte // SERVFAIL/REFUSED, used only if nothing better arrives
wait:
	for pending > 0 {
		select {
		case r := <-results:
			pending--
			if r != nil && !softFailure(r) {
				return r
			}
			if r != nil && soft == nil {
				soft = r
			}
			if next < len(ups) {
				launch()
			}
		case <-stagger.C:
			if next < len(ups) {
				launch()
				stagger.Reset(dnsStagger)
			}
		case <-ctx.Done():
			break wait
		}
	}
	if soft != nil {
		return soft
	}
	return reply(q.hdr, &q.q, dnsmessage.RCodeServerFailure)
}

// exchange asks one upstream over UDP, retrying over TCP when truncated.
func (f *dnsForwarder) exchange(ctx context.Context, up netip.AddrPort, q *query, limit int) []byte {
	var idb [2]byte
	rand.Read(idb[:])
	id := binary.BigEndian.Uint16(idb[:])
	out := slices.Clone(q.msg)
	binary.BigEndian.PutUint16(out, id)
	resp := exchangeUDP(ctx, up, out, id, q.q)
	if resp == nil {
		return nil
	}
	if resp[2]&0x02 != 0 { // TC
		if full := exchangeTCP(ctx, up, out, id, q.q); full != nil && len(full) <= limit {
			resp = full
		}
	}
	binary.BigEndian.PutUint16(resp, q.hdr.ID)
	return resp
}

func exchangeUDP(ctx context.Context, up netip.AddrPort, out []byte, id uint16, q dnsmessage.Question) []byte {
	c, err := netbind.Dialer(0).DialContext(ctx, "udp", up.String())
	if err != nil {
		return nil
	}
	defer c.Close()
	defer context.AfterFunc(ctx, func() { c.Close() })()
	if dl, ok := ctx.Deadline(); ok {
		c.SetDeadline(dl)
	}
	if _, err := c.Write(out); err != nil {
		return nil
	}
	buf := make([]byte, dnsMaxResp+1)
	for {
		n, err := c.Read(buf)
		if err != nil {
			return nil
		}
		if n <= dnsMaxResp && matches(buf[:n], id, q) {
			return slices.Clone(buf[:n])
		}
	}
}

func exchangeTCP(ctx context.Context, up netip.AddrPort, out []byte, id uint16, q dnsmessage.Question) []byte {
	c, err := netbind.Dialer(0).DialContext(ctx, "tcp", up.String())
	if err != nil {
		return nil
	}
	defer c.Close()
	defer context.AfterFunc(ctx, func() { c.Close() })()
	if dl, ok := ctx.Deadline(); ok {
		c.SetDeadline(dl)
	}
	msg := binary.BigEndian.AppendUint16(make([]byte, 0, 2+len(out)), uint16(len(out)))
	if _, err := c.Write(append(msg, out...)); err != nil {
		return nil
	}
	var lb [2]byte
	if _, err := io.ReadFull(c, lb[:]); err != nil {
		return nil
	}
	n := int(binary.BigEndian.Uint16(lb[:]))
	if n < dnsMinLen || n > dnsMaxResp {
		return nil
	}
	resp := make([]byte, n)
	if _, err := io.ReadFull(c, resp); err != nil || !matches(resp, id, q) {
		return nil
	}
	return resp
}

// matches checks that resp answers our rewritten query.
func matches(resp []byte, id uint16, q dnsmessage.Question) bool {
	var p dnsmessage.Parser
	h, err := p.Start(resp)
	if err != nil || !h.Response || h.ID != id {
		return false
	}
	qs, err := p.AllQuestions()
	if err != nil {
		return false
	}
	if len(qs) == 0 {
		return h.RCode != dnsmessage.RCodeSuccess
	}
	return len(qs) == 1 && qs[0].Type == q.Type && qs[0].Class == q.Class &&
		strings.EqualFold(qs[0].Name.String(), q.Name.String())
}

func softFailure(resp []byte) bool {
	rc := dnsmessage.RCode(resp[3] & 0x0f)
	return rc == dnsmessage.RCodeServerFailure || rc == dnsmessage.RCodeRefused
}

// serveDNSUDP answers queries on one client UDP association to .1:53.
func (d *Device) serveDNSUDP(f *flow, c *Client, in *gonet.UDPConn) {
	defer f.close()
	buf := make([]byte, dnsMaxQuery+1)
	for {
		n, err := in.Read(buf)
		if err != nil {
			return
		}
		f.touch()
		if !c.dnsRate.Allow() {
			continue
		}
		q, resp := parseQuery(buf[:n])
		if resp != nil {
			in.Write(resp)
			continue
		}
		if q == nil {
			continue
		}
		select {
		case c.dnsSem <- struct{}{}:
		default:
			continue // too many queries in flight for this client
		}
		go func() {
			defer func() { <-c.dnsSem }()
			if r := d.dns.resolve(c.ctx, q, q.udpSize); r != nil {
				f.touch()
				in.Write(r)
			}
		}()
	}
}

// serveDNSTCP answers length-prefixed queries on one client TCP connection
// to .1:53, sequentially, until idle.
func (d *Device) serveDNSTCP(f *flow, c *Client, conn *gonet.TCPConn) {
	defer f.close()
	idle := d.cfg.Limits.DNSIdle
	for {
		conn.SetReadDeadline(time.Now().Add(idle))
		var lb [2]byte
		if _, err := io.ReadFull(conn, lb[:]); err != nil {
			return
		}
		msg := make([]byte, binary.BigEndian.Uint16(lb[:]))
		if _, err := io.ReadFull(conn, msg); err != nil {
			return
		}
		f.touch()
		if !c.dnsRate.Allow() {
			return
		}
		q, resp := parseQuery(msg)
		if q != nil {
			select {
			case c.dnsSem <- struct{}{}:
			default:
				return
			}
			resp = d.dns.resolve(c.ctx, q, dnsMaxResp)
			<-c.dnsSem
		}
		if resp == nil {
			return
		}
		out := binary.BigEndian.AppendUint16(make([]byte, 0, 2+len(resp)), uint16(len(resp)))
		conn.SetWriteDeadline(time.Now().Add(idle))
		if _, err := conn.Write(append(out, resp...)); err != nil {
			return
		}
		f.touch()
	}
}
