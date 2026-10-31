package wire

import (
	"bytes"
	"crypto/rand"
	"net/netip"
	"testing"
)

func testKey(t testing.TB) [32]byte {
	var k [32]byte
	if _, err := rand.Read(k[:]); err != nil {
		t.Fatal(err)
	}
	return k
}

func TestJoinRoundTrip(t *testing.T) {
	a := NewAEAD(testKey(t))
	req := JoinReq{TS: 1761900000, MTUHint: 1280}
	req.ClientPub[0] = 7
	dgram, reqNonce, err := Seal(a, TypeJoinReq, req.Marshal(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(dgram) != 176 {
		t.Fatalf("join req datagram = %d bytes, want 176", len(dgram))
	}
	typ, n, pt, err := Open(a, dgram, nil)
	if err != nil || typ != TypeJoinReq || n != reqNonce {
		t.Fatalf("open: %v %v", typ, err)
	}
	got, err := ParseJoinReq(pt)
	if err != nil || got != req {
		t.Fatalf("parse: %+v %v", got, err)
	}

	resp := JoinResp{
		TS: 1, Assigned: netip.MustParseAddr("10.77.42.2"), PrefixLen: 24,
		GatewayIP: netip.MustParseAddr("10.77.42.1"), DNS: netip.MustParseAddr("10.77.42.1"),
		WGPort: 51820, MTU: 1280, Keepalive: 25, LeaseSec: 120,
	}
	resp.LeaseToken[3] = 9
	rd, _, err := Seal(a, TypeJoinResp, resp.Marshal(), &reqNonce)
	if err != nil {
		t.Fatal(err)
	}
	if len(rd) > len(dgram) {
		t.Fatalf("amplification: response %d > request %d", len(rd), len(dgram))
	}
	_, _, rpt, err := Open(a, rd, &reqNonce)
	if err != nil {
		t.Fatal(err)
	}
	gotResp, err := ParseJoinResp(rpt)
	if err != nil || gotResp != resp {
		t.Fatalf("resp: %+v %v", gotResp, err)
	}
}

func TestResponseBoundToRequestNonce(t *testing.T) {
	a := NewAEAD(testKey(t))
	_, n1, _ := Seal(a, TypeInfoReq, InfoReq{TS: 1}.Marshal(), nil)
	_, n2, _ := Seal(a, TypeInfoReq, InfoReq{TS: 1}.Marshal(), nil)
	body, _ := InfoResp{TS: 1, JSON: []byte(`{"v":1}`)}.Marshal()
	resp, _, err := Seal(a, TypeInfoResp, body, &n1)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := Open(a, resp, &n2); err != ErrAuth {
		t.Fatalf("replayed response accepted for another request: %v", err)
	}
	if _, _, _, err := Open(a, resp, &n1); err != nil {
		t.Fatal(err)
	}
}

func TestWrongKeyAndTamper(t *testing.T) {
	a, b := NewAEAD(testKey(t)), NewAEAD(testKey(t))
	d, _, _ := Seal(a, TypeRenewReq, LeaseReq{TS: 5}.Marshal(), nil)
	if _, _, _, err := Open(b, d, nil); err != ErrAuth {
		t.Fatalf("wrong key: %v", err)
	}
	d[3] = byte(TypeLeave) // header is authenticated
	if _, _, _, err := Open(a, d, nil); err != ErrAuth {
		t.Fatalf("tampered type: %v", err)
	}
}

func TestAmplificationBound(t *testing.T) {
	a := NewAEAD(testKey(t))
	var n Nonce
	req, _, _ := Seal(a, TypeInfoReq, InfoReq{}.Marshal(), nil)
	body, err := InfoResp{JSON: bytes.Repeat([]byte("x"), MaxInfoJSON)}.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	resp, _, _ := Seal(a, TypeInfoResp, body, &n)
	if len(resp) > len(req) || len(req) > MaxDatagram {
		t.Fatalf("info resp %d, req %d", len(resp), len(req))
	}
	if _, err := (InfoResp{JSON: make([]byte, MaxInfoJSON+1)}).Marshal(); err == nil {
		t.Fatal("oversized info accepted")
	}
}

func TestPreCheckRejectsJunk(t *testing.T) {
	cases := [][]byte{nil, make([]byte, 43), make([]byte, 1201), bytes.Repeat([]byte{0x50}, 200)}
	for i, c := range cases {
		if _, ok := PreCheck(c); ok {
			t.Errorf("case %d accepted", i)
		}
	}
}

func FuzzOpen(f *testing.F) {
	k := [32]byte{1}
	a := NewAEAD(k)
	d, _, _ := Seal(a, TypeJoinReq, JoinReq{}.Marshal(), nil)
	f.Add(d)
	f.Add([]byte("PV\x01\x10"))
	f.Fuzz(func(t *testing.T, b []byte) {
		var n Nonce
		_, _, _, _ = Open(a, b, nil)
		_, _, _, _ = Open(a, b, &n)
	})
}

func FuzzParsers(f *testing.F) {
	f.Add(make([]byte, 132))
	f.Add(make([]byte, 10))
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = ParseJoinReq(b)
		_, _ = ParseJoinResp(b)
		_, _ = ParseLeaseReq(b)
		_, _ = ParseRenewResp(b)
		_, _ = ParseInfoReq(b)
		_, _ = ParseInfoResp(b)
		_, _ = ParseErrorMsg(b)
	})
}
