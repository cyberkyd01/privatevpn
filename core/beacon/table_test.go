package beacon

import (
	"net/netip"
	"testing"
	"time"

	"github.com/cyberkyd01/private-vpn-pro/core/wire"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func newTestTable() (*Table, *clock) {
	c := &clock{t: time.Unix(1_800_000_000, 0)}
	t := NewTable()
	t.now = c.now
	return t, c
}

func mk(pub byte, ctr uint32, ts time.Time, k [32]byte) []byte {
	b := wire.Beacon{TS: uint64(ts.Unix()), InstanceID: 1, Counter: ctr, WGPort: 51820, CtrlPort: 51821, Name: "gw"}
	b.GatewayPub[0] = pub
	return b.Seal(k)
}

var (
	ip1  = netip.MustParseAddr("192.168.1.10")
	ip2  = netip.MustParseAddr("192.168.1.20")
	home = KeyRef{ID: "home", KBeacon: [32]byte{1}}
)

func TestVerifiedAndReplay(t *testing.T) {
	tb, c := newTestTable()
	d := mk(1, 1, c.t, home.KBeacon)
	if !tb.Handle(d, ip1, []KeyRef{home}) {
		t.Fatal("first beacon rejected")
	}
	if tb.Handle(d, ip1, []KeyRef{home}) {
		t.Fatal("replay accepted")
	}
	e, _ := tb.Get([32]byte{1})
	if !e.Verified || e.NetworkID != "home" || len(e.Endpoints) != 1 {
		t.Fatalf("entry %+v", e)
	}
}

func TestUnverifiedCannotDowngradeOnlineMember(t *testing.T) {
	tb, c := newTestTable()
	tb.Handle(mk(1, 1, c.t, home.KBeacon), ip1, []KeyRef{home})
	c.t = c.t.Add(time.Second)
	if tb.Handle(mk(1, 99, c.t, [32]byte{9}), ip1, []KeyRef{home}) {
		t.Fatal("spoofed unverified beacon downgraded an online member")
	}
	// After verified beacons stop (key reset), the next unverified one locks it.
	c.t = c.t.Add(OnlineWindow + time.Second)
	if !tb.Handle(mk(1, 100, c.t, [32]byte{9}), ip1, []KeyRef{home}) {
		t.Fatal("key-reset path not accepted")
	}
	if e, _ := tb.Get([32]byte{1}); e.Verified {
		t.Fatal("entry still verified after key reset")
	}
}

func TestSpoofCannotTakeOverOfflineMember(t *testing.T) {
	tb, c := newTestTable()
	tb.Handle(mk(1, 1, c.t, home.KBeacon), ip1, []KeyRef{home})
	c.t = c.t.Add(OnlineWindow + time.Second)
	// The member is offline; a forgery from another address must not turn
	// its entry locked or replace its endpoints.
	if tb.Handle(mk(1, 50, c.t, [32]byte{9}), ip2, []KeyRef{home}) {
		t.Fatal("forged beacon from a new source took over an offline member")
	}
	e, _ := tb.Get([32]byte{1})
	if !e.Verified || len(e.Endpoints) != 1 || e.Endpoints[0].IP != ip1 {
		t.Fatalf("entry changed: %+v", e)
	}
	// From the address it was verified at (key reset on the same host) it does.
	if !tb.Handle(mk(1, 51, c.t, [32]byte{9}), ip1, []KeyRef{home}) {
		t.Fatal("key-reset path from the known address rejected")
	}
	if e, _ := tb.Get([32]byte{1}); e.Verified {
		t.Fatal("entry still verified after key reset")
	}
}

func TestReverifyDropsForgedEndpoints(t *testing.T) {
	tb, c := newTestTable()
	// Without the key, the real gateway (ip1) and a forgery for its public
	// key (ip2) both land in the locked entry.
	tb.Handle(mk(1, 1, c.t, home.KBeacon), ip1, nil)
	c.t = c.t.Add(time.Second)
	tb.Handle(mk(1, 2, c.t, [32]byte{9}), ip2, nil)
	if e, _ := tb.Get([32]byte{1}); e.Verified || len(e.Endpoints) != 2 {
		t.Fatalf("setup: %+v", e)
	}
	if !tb.Reverify([]KeyRef{home}) {
		t.Fatal("reverify reported no change")
	}
	e, _ := tb.Get([32]byte{1})
	if !e.Verified || len(e.Endpoints) != 1 || e.Endpoints[0].IP != ip1 || !e.Endpoints[0].Verified {
		t.Fatalf("forged endpoint survived verification: %+v", e)
	}
}

func TestStaleTimestampRejected(t *testing.T) {
	tb, c := newTestTable()
	if tb.Handle(mk(1, 1, c.t.Add(-5*time.Minute), home.KBeacon), ip1, []KeyRef{home}) {
		t.Fatal("stale beacon accepted")
	}
}

func TestUnverifiedSpamLimits(t *testing.T) {
	tb, c := newTestTable()
	// One source cannot create more than MaxUnverifiedPerIP entries.
	n := 0
	for i := 1; i <= 10; i++ {
		c.t = c.t.Add(time.Second)
		if tb.Handle(mk(byte(i), 1, c.t, [32]byte{9}), ip1, nil) {
			n++
		}
	}
	if n != MaxUnverifiedPerIP {
		t.Fatalf("source created %d unverified entries, want %d", n, MaxUnverifiedPerIP)
	}
	// Unverified entries never evict verified ones.
	tb2, c2 := newTestTable()
	for i := 0; i < MaxEntries; i++ {
		c2.t = c2.t.Add(time.Millisecond)
		src := netip.AddrFrom4([4]byte{10, 0, byte(i / 200), byte(i%200 + 1)})
		b := wire.Beacon{TS: uint64(c2.t.Unix()), InstanceID: 1, Counter: 1, WGPort: 1, CtrlPort: 2}
		b.GatewayPub[0], b.GatewayPub[1] = byte(i), 0xAA
		if !tb2.Handle(b.Seal(home.KBeacon), src, []KeyRef{home}) {
			t.Fatalf("verified %d rejected", i)
		}
	}
	if tb2.Handle(mk(200, 1, c2.t, [32]byte{9}), ip2, nil) {
		t.Fatal("unverified entry evicted a verified one")
	}
}

func TestReverifyAfterKeyAdded(t *testing.T) {
	tb, c := newTestTable()
	tb.Handle(mk(1, 1, c.t, home.KBeacon), ip1, nil)
	if e, _ := tb.Get([32]byte{1}); e.Verified {
		t.Fatal("verified without key")
	}
	if !tb.Reverify([]KeyRef{home}) {
		t.Fatal("reverify reported no change")
	}
	if e, _ := tb.Get([32]byte{1}); !e.Verified || e.NetworkID != "home" {
		t.Fatal("reverify did not verify")
	}
}

func TestSelfIgnoredAndExpire(t *testing.T) {
	tb, c := newTestTable()
	tb.SetSelf([32]byte{1})
	if tb.Handle(mk(1, 1, c.t, home.KBeacon), ip1, []KeyRef{home}) {
		t.Fatal("own beacon accepted")
	}
	tb.Handle(mk(2, 1, c.t, home.KBeacon), ip1, []KeyRef{home})
	c.t = c.t.Add(ExpireAfter + time.Second)
	if !tb.Expire() || len(tb.Snapshot()) != 0 {
		t.Fatal("entry not expired")
	}
}
