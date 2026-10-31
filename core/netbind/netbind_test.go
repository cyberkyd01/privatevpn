package netbind

import (
	"net"
	"net/netip"
	"runtime"
	"testing"
	"time"
)

func TestClassify(t *testing.T) {
	phys.Store(&physical{index4: 1, onLink: []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}})
	defer phys.Store(nil)
	cases := []struct {
		network, addr  string
		bind, v6, dual bool
	}{
		{"udp4", "1.1.1.1:53", true, false, false},
		{"tcp4", "93.184.216.34:443", true, false, false},
		{"tcp4", "192.168.1.10:80", false, false, false},
		{"tcp4", "10.77.5.1:53", false, false, false},
		{"tcp4", "172.20.0.1:80", false, false, false},
		{"tcp4", "169.254.1.1:80", false, false, false},
		{"tcp4", "127.0.0.1:47771", false, false, false},
		{"tcp4", "203.0.113.9:80", false, false, false}, // on-link public subnet
		{"udp4", "0.0.0.0:0", true, false, false},
		{"udp6", "[::]:0", true, true, true},
		{"tcp6", "[2606:4700::1111]:443", true, true, false},
		{"tcp6", "[fd00::1]:443", false, true, false},
		{"tcp6", "[fe80::1%en0]:443", false, true, false},
		{"udp6", "[::ffff:1.1.1.1]:53", true, true, true},
	}
	for _, c := range cases {
		tg, bind := classify(c.network, c.addr)
		if bind != c.bind || tg.v6 != c.v6 || tg.dual != c.dual {
			t.Errorf("classify(%s, %s) = %+v, %v; want v6=%v dual=%v bind=%v", c.network, c.addr, tg, bind, c.v6, c.dual, c.bind)
		}
	}
}

func TestCanMark(t *testing.T) {
	ok := CanMark()
	if runtime.GOOS != "linux" && !ok {
		t.Fatal("CanMark must be true where no mark is needed")
	}
	if ok != CanMark() {
		t.Fatal("CanMark not stable")
	}
}

func TestControlNoBypass(t *testing.T) {
	SetBypass(false)
	ln, err := ListenConfig().Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	c, err := Dialer(time.Second).Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
}

func TestBypassLoopbackAndPublic(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("SO_MARK needs CAP_NET_ADMIN")
	}
	if err := RefreshPhysical(""); err != nil {
		t.Skipf("no physical default route: %v", err)
	}
	SetBypass(true)
	defer SetBypass(false)
	// Loopback is never bound.
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	c, err := Dialer(time.Second).Dial("udp4", pc.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	// A public destination is bound to the physical interface; UDP connect
	// sends nothing.
	c, err = Dialer(time.Second).Dial("udp4", "192.0.2.1:9")
	if err != nil {
		t.Fatalf("bound dial: %v", err)
	}
	c.Close()
	if p := phys.Load(); p == nil || p.index4 == 0 && p.index6 == 0 {
		t.Fatal("no physical index recorded")
	}
}
