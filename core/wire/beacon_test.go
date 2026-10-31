package wire

import (
	"strings"
	"testing"
)

func TestBeaconRoundTripAndTag(t *testing.T) {
	k := [32]byte{1}
	b := Beacon{TS: 10, InstanceID: 7, Counter: 3, WGPort: 51820, CtrlPort: 51821,
		Flags: BeaconAccepting | BeaconDetails, OS: OSWindows, ClientCount: 2,
		AppVersion: [3]byte{1, 0, 0}, Name: "PC-1A2B"}
	b.GatewayPub[0] = 9
	d := b.Seal(k)
	if len(d) != BeaconLen {
		t.Fatalf("len %d", len(d))
	}
	got, ok := ParseBeacon(d)
	if !ok || got != b {
		t.Fatalf("parse: %+v", got)
	}
	if !VerifyBeacon(d, k) || VerifyBeacon(d, [32]byte{2}) {
		t.Fatal("tag verification wrong")
	}
	d[70] ^= 1 // tamper with the name
	if VerifyBeacon(d, k) {
		t.Fatal("tampered beacon verified")
	}
	if _, ok := PreCheck(d); ok {
		t.Fatal("beacon must not pass control PreCheck")
	}
}

func TestBeaconNameTruncation(t *testing.T) {
	b := Beacon{WGPort: 1, CtrlPort: 2, Name: strings.Repeat("é", 40)}
	b.GatewayPub[0] = 1
	got, ok := ParseBeacon(b.Seal([32]byte{}))
	if !ok || len(got.Name) > 32 || !strings.HasPrefix(got.Name, "é") {
		t.Fatalf("name %q", got.Name)
	}
}

func FuzzParseBeacon(f *testing.F) {
	b := Beacon{WGPort: 1, CtrlPort: 2, Name: "x"}
	b.GatewayPub[0] = 1
	f.Add(b.Seal([32]byte{}))
	f.Fuzz(func(t *testing.T, d []byte) {
		if bc, ok := ParseBeacon(d); ok && len(bc.Name) > 32 {
			t.Fatal("name too long")
		}
		VerifyBeacon(d, [32]byte{})
	})
}
