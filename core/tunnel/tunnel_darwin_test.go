//go:build darwin

package tunnel

import (
	"encoding/binary"
	"net/netip"
	"reflect"
	"syscall"
	"testing"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

// TestLiveRIB parses this machine's routing table (a read-only sysctl) and
// checks the endpoint-exclusion logic finds a physical default route.
func TestLiveRIB(t *testing.T) {
	msgs, err := fetchRIB4()
	if err != nil {
		t.Fatalf("fetchRIB4: %v", err)
	}
	tab, err := darwinRouteOps{}.table()
	if err != nil {
		t.Fatalf("table: %v", err)
	}
	t.Logf("%d RIB messages, %d usable rows", len(msgs), len(tab))
	for _, e := range tab {
		if e.IfName == "" || e.IfName[:2] == "lo" || (len(e.IfName) >= 4 && e.IfName[:4] == "utun") {
			t.Errorf("row on excluded interface: %+v", e)
		}
	}
	if !hasDefault(tab) {
		t.Skip("no default route on this machine (offline?)")
	}
	r, need, err := exclusionFor(tab, netip.MustParseAddr("203.0.113.9"))
	if err != nil || !need || (!r.Gateway.IsValid() && r.IfName == "") {
		t.Errorf("public destination: %+v need=%v err=%v", r, need, err)
	}
	t.Logf("would add: route %q", hostRouteArgs("add", r))
}

func TestRibToTable(t *testing.T) {
	names := map[int]string{4: "en0", 9: "utun3", 1: "lo0"}
	ifName := func(i int) string { return names[i] }
	in4 := func(s string) *route.Inet4Addr { return &route.Inet4Addr{IP: netip.MustParseAddr(s).As4()} }
	msgs := []*route.RouteMessage{
		{Flags: unix.RTF_UP | unix.RTF_GATEWAY | unix.RTF_STATIC, Index: 4, Addrs: []route.Addr{in4("0.0.0.0"), in4("192.168.1.1"), in4("0.0.0.0")}},
		{Flags: unix.RTF_UP | unix.RTF_GATEWAY | unix.RTF_IFSCOPE, Index: 4, Addrs: []route.Addr{in4("0.0.0.0"), in4("192.168.1.1"), in4("0.0.0.0")}},
		{Flags: unix.RTF_UP, Index: 4, Addrs: []route.Addr{in4("192.168.1.0"), &route.LinkAddr{Index: 4}, in4("255.255.255.0")}},
		{Flags: unix.RTF_UP | unix.RTF_HOST | unix.RTF_LLINFO | unix.RTF_WASCLONED, Index: 4, Addrs: []route.Addr{in4("192.168.1.10"), &route.LinkAddr{Index: 4}}},
		{Flags: unix.RTF_UP | unix.RTF_HOST | unix.RTF_GATEWAY | unix.RTF_WASCLONED, Index: 4, Addrs: []route.Addr{in4("203.0.113.9"), in4("192.168.1.1")}},
		{Flags: unix.RTF_UP | unix.RTF_HOST | unix.RTF_GATEWAY | unix.RTF_STATIC | ourRouteFlag, Index: 4, Addrs: []route.Addr{in4("198.51.100.7"), in4("192.168.1.1")}},
		{Flags: unix.RTF_UP, Index: 9, Addrs: []route.Addr{in4("0.0.0.0"), &route.LinkAddr{Index: 9}, in4("128.0.0.0")}},
		{Flags: unix.RTF_UP | unix.RTF_HOST, Index: 1, Addrs: []route.Addr{in4("127.0.0.1"), in4("127.0.0.1")}},
		{Flags: unix.RTF_UP, Index: 4, Addrs: []route.Addr{in4("10.0.0.0"), &route.LinkAddr{Index: 4}, in4("255.0.255.0")}}, // non-contiguous
	}
	got := ribToTable(msgs, ifName, false)
	want := []rtEntry{
		{Dst: netip.MustParsePrefix("0.0.0.0/0"), Gateway: netip.MustParseAddr("192.168.1.1"), IfIndex: 4, IfName: "en0"},
		{Dst: netip.MustParsePrefix("192.168.1.0/24"), IfIndex: 4, IfName: "en0"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ribToTable:\n got %+v\nwant %+v", got, want)
	}
	if n := len(ribToTable(msgs, ifName, true)); n != 3 {
		t.Errorf("with scoped routes: %d rows, want 3", n)
	}
}

func TestHostRouteArgs(t *testing.T) {
	r := hostRoute{Dst: netip.MustParseAddr("203.0.113.9"), Gateway: netip.MustParseAddr("192.168.1.1"), IfName: "en0"}
	if got := hostRouteArgs("add", r); !reflect.DeepEqual(got, []string{"-q", "-n", "add", "-inet", "-proto2", "-host", "203.0.113.9", "192.168.1.1"}) {
		t.Errorf("add: %q", got)
	}
	r.Gateway = netip.Addr{}
	if got := hostRouteArgs("delete", r); !reflect.DeepEqual(got, []string{"-q", "-n", "delete", "-inet", "-host", "203.0.113.9", "-interface", "en0"}) {
		t.Errorf("delete: %q", got)
	}
}

func TestRouteMsgInteresting(t *testing.T) {
	msg := func(typ int, flags int) []byte {
		b := make([]byte, 92)
		binary.NativeEndian.PutUint16(b[0:], 92)
		b[2] = syscall.RTM_VERSION
		b[3] = byte(typ)
		binary.NativeEndian.PutUint32(b[8:], uint32(int32(flags)))
		return b
	}
	cases := []struct {
		b    []byte
		want bool
	}{
		{msg(unix.RTM_ADD, unix.RTF_UP|unix.RTF_GATEWAY|unix.RTF_STATIC), true},
		{msg(unix.RTM_DELETE, unix.RTF_UP|unix.RTF_GATEWAY), true},
		{msg(unix.RTM_ADD, unix.RTF_UP|unix.RTF_HOST|unix.RTF_WASCLONED), false},
		{msg(unix.RTM_ADD, unix.RTF_UP|unix.RTF_HOST|unix.RTF_LLINFO), false},
		{msg(unix.RTM_ADD, unix.RTF_UP|unix.RTF_HOST|ourRouteFlag), false},
		{msg(unix.RTM_IFINFO, 0), true},
		{msg(unix.RTM_NEWADDR, 0), true},
		{msg(unix.RTM_MISS, 0), false},
		{[]byte{1, 2}, false},
	}
	for i, c := range cases {
		if got := routeMsgInteresting(c.b); got != c.want {
			t.Errorf("case %d: got %v", i, got)
		}
	}
}

func TestIsElevatedDarwin(t *testing.T) {
	if IsElevated() {
		t.Skip("running as root")
	}
	if _, err := NewNative(nil); err != ErrNotElevated {
		t.Fatalf("NewNative unelevated: %v", err)
	}
}
