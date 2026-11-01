package gateway

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cyberkyd01/private-vpn-pro/core/eventlog"
	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

func newKey(t testing.TB) (priv, pub [32]byte) {
	t.Helper()
	sk, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	copy(priv[:], sk.Bytes())
	copy(pub[:], sk.PublicKey().Bytes())
	return
}

func freeUDPPort(t testing.TB) int {
	t.Helper()
	c, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).Port
}

// startGateway starts a gateway on a free port; mut adjusts the config.
func startGateway(t *testing.T, mut func(*Config)) *Gateway {
	t.Helper()
	priv, _ := newKey(t)
	var psk [32]byte
	rand.Read(psk[:])
	var last error
	for range 5 {
		cfg := Config{PrivateKey: priv, PresharedKey: psk, ListenPort: freeUDPPort(t), Log: eventlog.New(200)}
		if mut != nil {
			mut(&cfg)
		}
		g, err := Start(cfg)
		if err == nil {
			t.Cleanup(func() { g.Close() })
			return g
		}
		last = err
	}
	t.Fatalf("start gateway: %v", last)
	return nil
}

type testClient struct {
	pub   [32]byte
	lease Lease
	dev   *device.Device
	tnet  *netstack.Net
	http  *http.Client
}

// connectClient joins g and brings up an in-process WireGuard client with a
// netstack TUN, routing 0.0.0.0/0 to the gateway.
func connectClient(t *testing.T, g *Gateway) *testClient {
	t.Helper()
	priv, pub := newKey(t)
	lease, err := g.Join(pub, 0)
	if err != nil {
		t.Fatalf("join: %v", err)
	}
	tdev, tnet, err := netstack.CreateNetTUN([]netip.Addr{lease.IP}, []netip.Addr{lease.GatewayIP}, lease.MTU)
	if err != nil {
		t.Fatal(err)
	}
	dev := device.NewDevice(tdev, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	gwPub, psk := g.PublicKey(), g.cfg.PresharedKey
	uapi := fmt.Sprintf("private_key=%s\npublic_key=%s\npreshared_key=%s\nendpoint=127.0.0.1:%d\nallowed_ip=0.0.0.0/0\n",
		hex.EncodeToString(priv[:]), hex.EncodeToString(gwPub[:]), hex.EncodeToString(psk[:]), g.ListenPort())
	if err := dev.IpcSet(uapi); err != nil {
		t.Fatal(err)
	}
	if err := dev.Up(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(dev.Close)
	return &testClient{
		pub: pub, lease: lease, dev: dev, tnet: tnet,
		http: &http.Client{Transport: &http.Transport{DialContext: tnet.DialContext}, Timeout: 10 * time.Second},
	}
}

func (c *testClient) get(url string) (string, error) {
	resp, err := c.http.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	return string(b), err
}

// dialRefused asserts that a TCP connect through the tunnel is reset quickly
// (policy denial → RST), not timed out.
func (c *testClient) dialRefused(t *testing.T, dst netip.AddrPort) {
	t.Helper()
	start := time.Now()
	if err := c.dial(dst, 5*time.Second); err == nil {
		t.Fatalf("dial %v succeeded, want refused", dst)
	} else if time.Since(start) > 3*time.Second {
		t.Fatalf("dial %v: %v after %v, want a quick RST", dst, err, time.Since(start))
	}
}

// dialFails asserts that a TCP connect does not succeed (dropped or reset).
func (c *testClient) dialFails(t *testing.T, dst netip.AddrPort) {
	t.Helper()
	if err := c.dial(dst, time.Second); err == nil {
		t.Fatalf("dial %v succeeded, want failure", dst)
	}
}

func (c *testClient) dial(dst netip.AddrPort, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cn, err := c.tnet.DialContextTCPAddrPort(ctx, dst)
	if err == nil {
		cn.Close()
	}
	return err
}

func dnsQuery(t testing.TB, id uint16, name string, typ dnsmessage.Type) []byte {
	t.Helper()
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: id, RecursionDesired: true})
	b.StartQuestions()
	b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName(name), Type: typ, Class: dnsmessage.ClassINET})
	msg, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return msg
}

// fakeDNS answers every A query with 192.0.2.53 on 127.0.0.1 (UDP).
func fakeDNS(t *testing.T) netip.AddrPort {
	t.Helper()
	u, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { u.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := u.ReadFromUDP(buf)
			if err != nil {
				return
			}
			var p dnsmessage.Parser
			h, err := p.Start(buf[:n])
			if err != nil {
				continue
			}
			q, err := p.Question()
			if err != nil {
				continue
			}
			b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: h.ID, Response: true, RecursionDesired: h.RecursionDesired, RecursionAvailable: true})
			b.StartQuestions()
			b.Question(q)
			b.StartAnswers()
			b.AResource(dnsmessage.ResourceHeader{Name: q.Name, Class: dnsmessage.ClassINET, TTL: 60}, dnsmessage.AResource{A: [4]byte{192, 0, 2, 53}})
			out, _ := b.Finish()
			u.WriteToUDP(out, from)
		}
	}()
	return u.LocalAddr().(*net.UDPAddr).AddrPort()
}

func checkDNSAnswer(t *testing.T, resp []byte, id uint16, wantA bool) {
	t.Helper()
	var p dnsmessage.Parser
	h, err := p.Start(resp)
	if err != nil {
		t.Fatal(err)
	}
	p.SkipAllQuestions()
	ans, err := p.AllAnswers()
	if err != nil {
		t.Fatal(err)
	}
	if h.ID != id || !h.Response || h.RCode != dnsmessage.RCodeSuccess {
		t.Fatalf("DNS header %+v", h)
	}
	if !wantA {
		if len(ans) != 0 {
			t.Fatalf("want empty answer, got %d", len(ans))
		}
		return
	}
	if len(ans) != 1 || ans[0].Body.(*dnsmessage.AResource).A != [4]byte{192, 0, 2, 53} {
		t.Fatalf("DNS answers %v", ans)
	}
}

func TestIntegration(t *testing.T) {
	setRedirect(t)
	upstream := fakeDNS(t)
	g := startGateway(t, func(c *Config) {
		c.DNSUpstreams = func() []netip.AddrPort { return []netip.AddrPort{upstream} }
	})
	c := connectClient(t, g)
	gwDNS := netip.AddrPortFrom(c.lease.GatewayIP, 53)

	if c.lease.GatewayIP != g.Subnet().Addr().Next() || !g.Subnet().Contains(c.lease.IP) || c.lease.MTU != 1280 || c.lease.LeaseSec != 120 {
		t.Fatalf("lease %+v", []any{c.lease.IP, c.lease.GatewayIP, c.lease.MTU, c.lease.LeaseSec})
	}
	if again, err := g.Join(c.pub, 0); err != nil || again.IP != c.lease.IP || again.Token != c.lease.Token {
		t.Fatalf("Join not idempotent: %v", err)
	}

	big := bytes.Repeat([]byte("0123456789abcdef"), 1<<16) // 1 MiB
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/big":
			w.Write(big)
		case "/upload":
			b, _ := io.ReadAll(r.Body)
			sum := sha256.Sum256(b)
			io.WriteString(w, hex.EncodeToString(sum[:]))
		default:
			io.WriteString(w, "hello through the tunnel")
		}
	}))
	defer srv.Close()
	srvURL := "http://" + viaTestNet(srv.Listener.Addr()).String()

	t.Run("HTTP", func(t *testing.T) {
		body, err := c.get(srvURL)
		if err != nil || body != "hello through the tunnel" {
			t.Fatalf("GET: %q, %v", body, err)
		}
		body, err = c.get(srvURL + "/big")
		if err != nil || body != string(big) {
			t.Fatalf("GET /big: %d bytes, %v", len(body), err)
		}
		up := bytes.Repeat([]byte{0xa5}, 300<<10)
		resp, err := c.http.Post(srvURL+"/upload", "application/octet-stream", bytes.NewReader(up))
		if err != nil {
			t.Fatal(err)
		}
		got, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if sum := sha256.Sum256(up); string(got) != hex.EncodeToString(sum[:]) {
			t.Fatal("upload corrupted")
		}
	})

	t.Run("UDPEcho", func(t *testing.T) {
		echo, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		defer echo.Close()
		go func() {
			buf := make([]byte, 65535)
			for {
				n, from, err := echo.ReadFromUDP(buf)
				if err != nil {
					return
				}
				echo.WriteToUDP(buf[:n], from)
			}
		}()
		uc, err := c.tnet.DialUDPAddrPort(netip.AddrPort{}, viaTestNet(echo.LocalAddr()))
		if err != nil {
			t.Fatal(err)
		}
		defer uc.Close()
		uc.SetDeadline(time.Now().Add(5 * time.Second))
		for i, size := range []int{4, 1000, 3000} { // 3000 exercises fragmentation both ways
			msg := bytes.Repeat([]byte{byte(i + 1)}, size)
			if _, err := uc.Write(msg); err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, 65535)
			n, err := uc.Read(buf)
			if err != nil || !bytes.Equal(buf[:n], msg) {
				t.Fatalf("echo %d bytes: got %d, %v", size, n, err)
			}
		}
	})

	t.Run("DNS", func(t *testing.T) {
		uc, err := c.tnet.DialUDPAddrPort(netip.AddrPort{}, gwDNS)
		if err != nil {
			t.Fatal(err)
		}
		defer uc.Close()
		uc.SetDeadline(time.Now().Add(5 * time.Second))
		buf := make([]byte, 4096)
		for _, tc := range []struct {
			id    uint16
			typ   dnsmessage.Type
			wantA bool
		}{{0x1111, dnsmessage.TypeA, true}, {0x2222, dnsmessage.TypeAAAA, false}} {
			if _, err := uc.Write(dnsQuery(t, tc.id, "example.test.", tc.typ)); err != nil {
				t.Fatal(err)
			}
			n, err := uc.Read(buf)
			if err != nil {
				t.Fatalf("DNS read: %v", err)
			}
			checkDNSAnswer(t, buf[:n], tc.id, tc.wantA)
		}

		// TCP to .1:53, length-prefixed.
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		tc, err := c.tnet.DialContextTCPAddrPort(ctx, gwDNS)
		if err != nil {
			t.Fatal(err)
		}
		defer tc.Close()
		q := dnsQuery(t, 0x3333, "example.test.", dnsmessage.TypeA)
		tc.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(q))), q...))
		tc.SetReadDeadline(time.Now().Add(5 * time.Second))
		var lb [2]byte
		if _, err := io.ReadFull(tc, lb[:]); err != nil {
			t.Fatal(err)
		}
		resp := make([]byte, binary.BigEndian.Uint16(lb[:]))
		if _, err := io.ReadFull(tc, resp); err != nil {
			t.Fatal(err)
		}
		checkDNSAnswer(t, resp, 0x3333, true)
	})

	t.Run("ICMP", func(t *testing.T) {
		ping := func(dst netip.Addr) error {
			pc, err := c.tnet.DialPingAddr(netip.Addr{}, dst)
			if err != nil {
				return err
			}
			defer pc.Close()
			msg, _ := (&icmp.Message{Type: ipv4.ICMPTypeEcho, Body: &icmp.Echo{ID: 7, Seq: 1, Data: []byte("pvp")}}).Marshal(nil)
			pc.SetDeadline(time.Now().Add(time.Second))
			if _, err := pc.Write(msg); err != nil {
				return err
			}
			buf := make([]byte, 1500)
			n, err := pc.Read(buf)
			if err != nil {
				return err
			}
			if m, err := icmp.ParseMessage(1, buf[:n]); err != nil || m.Type != ipv4.ICMPTypeEchoReply {
				return errors.New("not an echo reply")
			}
			return nil
		}
		if err := ping(c.lease.GatewayIP); err != nil {
			t.Fatalf("ping gateway: %v", err)
		}
		if err := ping(netip.MustParseAddr("8.8.8.8")); err == nil {
			t.Fatal("ping 8.8.8.8 answered; only the gateway address may reply")
		}
	})

	t.Run("Denied", func(t *testing.T) {
		c.dialRefused(t, netip.MustParseAddrPort("169.254.169.254:80"))
		c.dialRefused(t, netip.MustParseAddrPort("192.168.77.77:80")) // LAN access off
		c.dialRefused(t, netip.AddrPortFrom(c.lease.GatewayIP, 22))
		c.dialFails(t, netip.MustParseAddrPort("224.0.0.1:80")) // multicast: dropped, no RST possible
		// UDP to a denied destination is dropped silently.
		uc, err := c.tnet.DialUDPAddrPort(netip.AddrPort{}, netip.MustParseAddrPort("169.254.169.254:53"))
		if err != nil {
			t.Fatal(err)
		}
		defer uc.Close()
		uc.Write(dnsQuery(t, 1, "x.test.", dnsmessage.TypeA))
		uc.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		if _, err := uc.Read(make([]byte, 512)); err == nil {
			t.Fatal("reply from denied UDP destination")
		}
	})

	t.Run("ClientIsolation", func(t *testing.T) {
		b := connectClient(t, g)
		if b.lease.IP == c.lease.IP {
			t.Fatal("duplicate address")
		}
		if body, err := b.get(srvURL); err != nil || body != "hello through the tunnel" {
			t.Fatalf("second client GET: %v", err)
		}
		ln, err := c.tnet.ListenTCPAddrPort(netip.AddrPortFrom(c.lease.IP, 7000))
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		accepted := make(chan struct{}, 1)
		go func() {
			if cn, err := ln.Accept(); err == nil {
				cn.Close()
				accepted <- struct{}{}
			}
		}()
		b.dialRefused(t, netip.AddrPortFrom(c.lease.IP, 7000))
		ul, err := c.tnet.ListenUDPAddrPort(netip.AddrPortFrom(c.lease.IP, 7001))
		if err != nil {
			t.Fatal(err)
		}
		defer ul.Close()
		bu, err := b.tnet.DialUDPAddrPort(netip.AddrPort{}, netip.AddrPortFrom(c.lease.IP, 7001))
		if err != nil {
			t.Fatal(err)
		}
		bu.Write([]byte("hi"))
		bu.Close()
		ul.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		if _, err := ul.Read(make([]byte, 16)); err == nil {
			t.Fatal("UDP reached another client")
		}
		select {
		case <-accepted:
			t.Fatal("TCP reached another client")
		default:
		}
		if err := g.Leave(b.pub, b.lease.Token); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("EndpointLearned", func(t *testing.T) {
		if ep := g.peerEndpoints()[c.pub]; ep != netip.MustParseAddr("127.0.0.1") {
			t.Fatalf("learned endpoint %v", ep)
		}
		if g.offLink(netip.MustParseAddr("127.0.0.1")) {
			t.Fatal("loopback endpoint would get a route")
		}
	})

	t.Run("Stats", func(t *testing.T) {
		s := g.Stats()
		if s.Clients != 1 || s.RxBytes == 0 || s.TxBytes < uint64(len(big)) {
			t.Fatalf("stats %+v", s)
		}
	})

	t.Run("Leave", func(t *testing.T) {
		// Hold a connection open so there is a flow to tear down.
		hold, err := c.tnet.DialContextTCPAddrPort(context.Background(), viaTestNet(srv.Listener.Addr()))
		if err != nil {
			t.Fatal(err)
		}
		defer hold.Close()
		waitFor(t, "TCP flow", func() bool { return g.Stats().TCPFlows > 0 })

		if err := g.Leave(c.pub, [16]byte{}); err != ErrUnknownLease {
			t.Fatalf("Leave with wrong token: %v", err)
		}
		if err := g.Leave(c.pub, c.lease.Token); err != nil {
			t.Fatal(err)
		}
		if g.peerKeys()[c.pub] || len(g.peerKeys()) != 0 {
			t.Fatal("peer still configured after Leave")
		}
		if g.ClientCount() != 0 {
			t.Fatal("lease still present")
		}
		waitFor(t, "flows closed", func() bool { s := g.Stats(); return s.TCPFlows == 0 && s.UDPFlows == 0 })
		if _, err := g.Renew(c.pub, c.lease.Token); err != ErrUnknownLease {
			t.Fatalf("Renew after Leave: %v", err)
		}
		c.http.Timeout = 2 * time.Second
		if _, err := c.get(srvURL); err == nil {
			t.Fatal("traffic still flows after Leave")
		}
	})

	t.Run("NoLeaks", func(t *testing.T) {
		// The event log must not contain client addresses or keys (§12.1).
		lines := strings.Join(g.log.Lines(), "\n")
		if lines == "" {
			t.Fatal("no log lines")
		}
		for _, s := range []string{c.lease.IP.String(), hex.EncodeToString(c.pub[:]), hex.EncodeToString(c.pub[:4]),
			strconv.Itoa(srv.Listener.Addr().(*net.TCPAddr).Port), "example.test", testNet.String()} {
			if strings.Contains(lines, s) {
				t.Errorf("log leaks %q:\n%s", s, lines)
			}
		}
	})
}

// TestLoopbackDenied: loopback (the host's own services, e.g. the web UI) is
// unreachable even with the test redirect installed. gVisor drops such
// packets as martians before the policy's RST, so only failure is asserted.
func TestLoopbackDenied(t *testing.T) {
	setRedirect(t)
	g := startGateway(t, nil)
	c := connectClient(t, g)
	c.http.Timeout = time.Second
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		if cn, err := ln.Accept(); err == nil {
			cn.Close()
			t.Error("loopback service reached")
		}
	}()
	c.dialFails(t, ln.Addr().(*net.TCPAddr).AddrPort())
	if body, err := c.get("http://" + ln.Addr().String()); err == nil {
		t.Fatalf("HTTP to loopback: %q", body)
	}
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if cond() {
			return
		}
	}
	t.Fatalf("timed out waiting for %s", what)
}
