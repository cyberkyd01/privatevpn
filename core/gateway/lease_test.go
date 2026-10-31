package gateway

import (
	"crypto/rand"
	"fmt"
	"net/netip"
	"testing"
	"time"
)

func TestPoolOrder(t *testing.T) {
	p := newPool(netip.MustParsePrefix("10.77.42.0/24"))
	ip := func(last byte) netip.Addr { return netip.AddrFrom4([4]byte{10, 77, 42, last}) }
	for want := 2; want <= 10; want++ {
		got, ok := p.get()
		if !ok || got != ip(byte(want)) {
			t.Fatalf("get = %v, want %v", got, ip(byte(want)))
		}
	}
	// A released address is not reused while never-used ones remain.
	p.put(ip(5))
	p.put(ip(3))
	if got, _ := p.get(); got != ip(11) {
		t.Fatalf("after release got %v, want .11", got)
	}
	n := 0
	var last netip.Addr
	for {
		a, ok := p.get()
		if !ok {
			break
		}
		n++
		if n == 244 { // .12–.254 = 243 fresh, then the released ones in release order
			if a != ip(5) {
				t.Fatalf("first reuse %v, want .5", a)
			}
		}
		last = a
	}
	if n != 245 || last != ip(3) {
		t.Fatalf("drained %d, last %v", n, last)
	}
}

func TestLeaseTable(t *testing.T) {
	tb := newLeaseTable(netip.MustParsePrefix("10.77.42.0/24"))
	var keys [][32]byte
	for i := 0; i < poolSize; i++ {
		var k [32]byte
		rand.Read(k[:])
		l, err := tb.add(k)
		if err != nil {
			t.Fatalf("add %d: %v", i, err)
		}
		l.expires = time.Unix(int64(1000+i), 0)
		keys = append(keys, k)
	}
	var k [32]byte
	rand.Read(k[:])
	if _, err := tb.add(k); err != ErrPoolFull {
		t.Fatalf("254th add: %v", err)
	}
	exp := tb.expired(time.Unix(1009, 1))
	if len(exp) != 10 {
		t.Fatalf("expired %d, want 10", len(exp))
	}
	for _, l := range exp {
		tb.remove(l)
	}
	if len(tb.byKey) != poolSize-10 || len(tb.pool.free) != 10 {
		t.Fatalf("after expiry: %d leases, %d free", len(tb.byKey), len(tb.pool.free))
	}
	if _, err := tb.add(k); err != nil {
		t.Fatalf("add after expiry: %v", err)
	}
}

func TestRedacted(t *testing.T) {
	l := &lease{ip: netip.MustParseAddr("10.77.1.2"), token: [16]byte{1}}
	for _, v := range []any{l, *l, Lease{IP: l.ip, Token: l.token}, &Lease{}} {
		if s := fmt.Sprintf("%v|%s|%+v", v, v, v); s != "<redacted>|<redacted>|<redacted>" {
			t.Errorf("%T formats as %q", v, s)
		}
	}
}

func TestDeriveSubnet(t *testing.T) {
	// Known answers (Python hashlib): SHA-256("pvn1 subnet"||key)[0] = 171, 11.
	var pub [32]byte
	if got := DeriveSubnet(pub); got != netip.MustParsePrefix("10.77.172.0/24") {
		t.Fatalf("zero key: %v", got)
	}
	for i := range pub {
		pub[i] = byte(i)
	}
	if got := DeriveSubnet(pub); got != netip.MustParsePrefix("10.77.12.0/24") {
		t.Fatalf("0..31 key: %v", got)
	}
	seen := map[byte]bool{}
	for i := 0; i < 5000; i++ {
		rand.Read(pub[:])
		h := DeriveSubnet(pub).Addr().As4()[2]
		if h < 1 || h > 254 {
			t.Fatalf("H=%d out of range", h)
		}
		seen[h] = true
	}
	if len(seen) < 200 {
		t.Fatalf("poor spread: %d distinct", len(seen))
	}
}
