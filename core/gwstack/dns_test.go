package gwstack

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func testLimits() Limits {
	return Limits{
		TCPPerClient: 16, TCPGlobal: 64, UDPPerClient: 16, UDPGlobal: 64,
		FlowRate: 1000, FlowBurst: 1000, TCPMaxInFlight: 16,
		TCPDialTimeout: 2 * time.Second, TCPIdle: time.Minute,
		UDPIdle: 10 * time.Second, DNSIdle: 5 * time.Second,
		DNSRate: 1000, DNSBurst: 1000, DNSTimeout: 2 * time.Second, DNSInFlight: 8,
	}
}

func buildQuery(t testing.TB, id uint16, name string, typ dnsmessage.Type, edns int) []byte {
	t.Helper()
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: id, RecursionDesired: true})
	b.StartQuestions()
	if err := b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName(name), Type: typ, Class: dnsmessage.ClassINET}); err != nil {
		t.Fatal(err)
	}
	if edns > 0 {
		b.StartAdditionals()
		var rh dnsmessage.ResourceHeader
		rh.SetEDNS0(edns, dnsmessage.RCodeSuccess, false)
		b.OPTResource(rh, dnsmessage.OPTResource{})
	}
	msg, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return msg
}

func parseResp(t testing.TB, msg []byte) (dnsmessage.Header, []dnsmessage.Question, []dnsmessage.Resource) {
	t.Helper()
	var p dnsmessage.Parser
	h, err := p.Start(msg)
	if err != nil {
		t.Fatalf("parse response: %v", err)
	}
	qs, err := p.AllQuestions()
	if err != nil {
		t.Fatal(err)
	}
	ans, err := p.AllAnswers()
	if err != nil {
		t.Fatal(err)
	}
	return h, qs, ans
}

func TestParseQueryLocal(t *testing.T) {
	// AAAA → NOERROR, empty, RA=1, question copied (D14).
	q, resp := parseQuery(buildQuery(t, 0x1234, "example.com.", dnsmessage.TypeAAAA, 0))
	if q != nil || resp == nil {
		t.Fatal("AAAA not answered locally")
	}
	h, qs, ans := parseResp(t, resp)
	if h.ID != 0x1234 || !h.Response || !h.RecursionAvailable || !h.RecursionDesired || h.RCode != dnsmessage.RCodeSuccess || len(ans) != 0 {
		t.Fatalf("AAAA response %+v answers=%d", h, len(ans))
	}
	if len(qs) != 1 || qs[0].Type != dnsmessage.TypeAAAA || qs[0].Name.String() != "example.com." {
		t.Fatalf("AAAA question %+v", qs)
	}

	// ANY → NOTIMP.
	_, resp = parseQuery(buildQuery(t, 7, "example.com.", dnsmessage.TypeALL, 0))
	if h, _, _ := parseResp(t, resp); h.RCode != dnsmessage.RCodeNotImplemented || h.ID != 7 {
		t.Fatalf("ANY: %+v", h)
	}

	// A → forwarded, EDNS size picked up.
	q, resp = parseQuery(buildQuery(t, 9, "example.com.", dnsmessage.TypeA, 1232))
	if q == nil || resp != nil || q.udpSize != 1232 || q.String() != "<redacted>" {
		t.Fatalf("A: q=%v resp=%v", q, resp)
	}
	if q, _ := parseQuery(buildQuery(t, 9, "example.com.", dnsmessage.TypeA, 0)); q.udpSize != 512 {
		t.Fatalf("no EDNS: size %d", q.udpSize)
	}

	formerr := func(name string, msg []byte, id uint16) {
		t.Helper()
		q, resp := parseQuery(msg)
		if q != nil || resp == nil {
			t.Fatalf("%s: not answered locally", name)
		}
		if h, _, _ := parseResp(t, resp); h.RCode != dnsmessage.RCodeFormatError || h.ID != id || !h.Response {
			t.Fatalf("%s: %+v", name, h)
		}
	}
	good := buildQuery(t, 0x4242, "example.com.", dnsmessage.TypeA, 0)
	two := append([]byte{}, good...)
	binary.BigEndian.PutUint16(two[4:], 2) // QDCOUNT=2, only one present
	formerr("qdcount", two, 0x4242)
	zero := append([]byte{}, good[:12]...)
	binary.BigEndian.PutUint16(zero[4:], 0)
	formerr("no question", zero, 0x4242)
	formerr("garbage", append(append([]byte{}, good[:12]...), 0xff, 0xff, 0xff), 0x4242)
	op := append([]byte{}, good...)
	op[2] |= 2 << 3 // OPCODE=2 (STATUS)
	formerr("opcode", op, 0x4242)
	big := append(append([]byte{}, good...), make([]byte, 1300)...)
	formerr("oversize", big, 0x4242)

	// Dropped: too short, or a response.
	if q, resp := parseQuery(good[:11]); q != nil || resp != nil {
		t.Fatal("short message answered")
	}
	r := append([]byte{}, good...)
	r[2] |= 0x80
	if q, resp := parseQuery(r); q != nil || resp != nil {
		t.Fatal("response answered")
	}
}

// fakeUpstream is a DNS server on 127.0.0.1 answering A queries with
// 192.0.2.53. With truncate set, UDP answers carry TC and no records; TCP
// answers are complete.
type fakeUpstream struct {
	udp      *net.UDPConn
	tcp      net.Listener
	truncate bool
	mu       sync.Mutex
	ids      []uint16
}

func newFakeUpstream(t *testing.T, truncate bool) *fakeUpstream {
	t.Helper()
	u, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp4", u.LocalAddr().String())
	if err != nil {
		u.Close()
		t.Skipf("TCP port pairing: %v", err)
	}
	f := &fakeUpstream{udp: u, tcp: l, truncate: truncate}
	t.Cleanup(func() { u.Close(); l.Close() })
	go func() {
		buf := make([]byte, 4096)
		for {
			n, from, err := u.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if resp := f.answer(buf[:n], f.truncate); resp != nil {
				u.WriteToUDP(resp, from)
			}
		}
	}()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				var lb [2]byte
				if _, err := io.ReadFull(c, lb[:]); err != nil {
					return
				}
				msg := make([]byte, binary.BigEndian.Uint16(lb[:]))
				if _, err := io.ReadFull(c, msg); err != nil {
					return
				}
				resp := f.answer(msg, false)
				c.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(resp))), resp...))
			}()
		}
	}()
	return f
}

func (f *fakeUpstream) addr() netip.AddrPort {
	return f.udp.LocalAddr().(*net.UDPAddr).AddrPort()
}

func (f *fakeUpstream) answer(msg []byte, truncate bool) []byte {
	var p dnsmessage.Parser
	h, err := p.Start(msg)
	if err != nil {
		return nil
	}
	q, err := p.Question()
	if err != nil {
		return nil
	}
	f.mu.Lock()
	f.ids = append(f.ids, h.ID)
	f.mu.Unlock()
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: h.ID, Response: true, RecursionDesired: h.RecursionDesired, RecursionAvailable: true, Truncated: truncate})
	b.StartQuestions()
	b.Question(q)
	if !truncate {
		b.StartAnswers()
		b.AResource(dnsmessage.ResourceHeader{Name: q.Name, Class: dnsmessage.ClassINET, TTL: 60}, dnsmessage.AResource{A: [4]byte{192, 0, 2, 53}})
	}
	out, _ := b.Finish()
	return out
}

func checkA(t *testing.T, resp []byte, id uint16) {
	t.Helper()
	h, _, ans := parseResp(t, resp)
	if h.ID != id || h.RCode != dnsmessage.RCodeSuccess || h.Truncated || len(ans) != 1 {
		t.Fatalf("response %+v answers=%d", h, len(ans))
	}
	if a, ok := ans[0].Body.(*dnsmessage.AResource); !ok || a.A != [4]byte{192, 0, 2, 53} {
		t.Fatalf("answer %v", ans[0].Body)
	}
}

func resolveVia(t *testing.T, ups []netip.AddrPort, timeout time.Duration, id uint16) []byte {
	t.Helper()
	f := &dnsForwarder{upstreams: func() []netip.AddrPort { return ups }, timeout: timeout}
	q, _ := parseQuery(buildQuery(t, id, "example.com.", dnsmessage.TypeA, 1232))
	return f.resolve(context.Background(), q, q.udpSize)
}

func TestDNSForward(t *testing.T) {
	up := newFakeUpstream(t, false)
	checkA(t, resolveVia(t, []netip.AddrPort{up.addr()}, 2*time.Second, 0xbeef), 0xbeef)
	up.mu.Lock()
	n := len(up.ids)
	up.mu.Unlock()
	if n != 1 {
		t.Fatalf("upstream saw %d queries", n)
	}
}

func TestDNSTruncatedRetriesTCP(t *testing.T) {
	up := newFakeUpstream(t, true)
	checkA(t, resolveVia(t, []netip.AddrPort{up.addr()}, 2*time.Second, 77), 77)
}

func TestDNSFailover(t *testing.T) {
	dead, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	deadAddr := dead.LocalAddr().(*net.UDPAddr).AddrPort()
	dead.Close() // nothing listens: ICMP refused or silence
	up := newFakeUpstream(t, false)
	start := time.Now()
	checkA(t, resolveVia(t, []netip.AddrPort{deadAddr, up.addr()}, 3*time.Second, 5), 5)
	if time.Since(start) > 2*time.Second {
		t.Fatalf("failover took %v", time.Since(start))
	}
}

func TestDNSServfail(t *testing.T) {
	dead, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer dead.Close() // bound but never answers
	resp := resolveVia(t, []netip.AddrPort{dead.LocalAddr().(*net.UDPAddr).AddrPort()}, 300*time.Millisecond, 9)
	if h, qs, _ := parseResp(t, resp); h.RCode != dnsmessage.RCodeServerFailure || h.ID != 9 || len(qs) != 1 {
		t.Fatalf("servfail: %+v", h)
	}
}
