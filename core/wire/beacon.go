package wire

import (
	"crypto/hmac"
	"crypto/sha256"
	"unicode/utf8"
)

// BeaconLen is the exact size of a BEACON datagram (§6.2).
const BeaconLen = 116

const (
	beaconBodyEnd = 100 // header(4) + body(96); the tag covers [0:100]
	beaconNameMax = 32
)

// Beacon flag bits.
const (
	BeaconAccepting = 1 << 0
	BeaconLANAccess = 1 << 1
	BeaconDetails   = 1 << 2
	BeaconDualRole  = 1 << 3
)

// OS codes carried in beacons.
const (
	OSWindows = 1
	OSMacOS   = 2
	OSLinux   = 3
)

// Beacon is the public body of a gateway announcement. Every field is
// cleartext and therefore untrusted until the tag verifies.
type Beacon struct {
	GatewayPub  [32]byte
	TS          uint64
	InstanceID  uint64
	Counter     uint32
	WGPort      uint16
	CtrlPort    uint16
	Flags       uint16
	OS          byte
	ClientCount byte
	AppVersion  [3]byte
	Name        string
}

// Seal encodes the beacon and appends the membership tag under kBeacon.
func (b Beacon) Seal(kBeacon [32]byte) []byte {
	d := make([]byte, BeaconLen)
	d[0], d[1], d[2], d[3] = Magic0, Magic1, Version, byte(TypeBeacon)
	copy(d[4:36], b.GatewayPub[:])
	be.PutUint64(d[36:], b.TS)
	be.PutUint64(d[44:], b.InstanceID)
	be.PutUint32(d[52:], b.Counter)
	be.PutUint16(d[56:], b.WGPort)
	be.PutUint16(d[58:], b.CtrlPort)
	be.PutUint16(d[60:], b.Flags)
	d[62] = b.OS
	d[63] = b.ClientCount
	copy(d[64:67], b.AppVersion[:])
	name := truncUTF8(b.Name, beaconNameMax)
	d[67] = byte(len(name))
	copy(d[68:100], name)
	copy(d[beaconBodyEnd:], beaconTag(d[:beaconBodyEnd], kBeacon))
	return d
}

// ParseBeacon decodes a BEACON datagram without verifying its tag.
func ParseBeacon(d []byte) (Beacon, bool) {
	var b Beacon
	if len(d) != BeaconLen || d[0] != Magic0 || d[1] != Magic1 || d[2] != Version || Type(d[3]) != TypeBeacon {
		return b, false
	}
	copy(b.GatewayPub[:], d[4:36])
	b.TS = be.Uint64(d[36:])
	b.InstanceID = be.Uint64(d[44:])
	b.Counter = be.Uint32(d[52:])
	b.WGPort = be.Uint16(d[56:])
	b.CtrlPort = be.Uint16(d[58:])
	b.Flags = be.Uint16(d[60:])
	b.OS = d[62]
	b.ClientCount = d[63]
	copy(b.AppVersion[:], d[64:67])
	n := int(d[67])
	if n > beaconNameMax {
		return b, false
	}
	b.Name = truncUTF8(string(d[68:68+n]), beaconNameMax)
	if b.GatewayPub == [32]byte{} || b.WGPort == 0 || b.CtrlPort == 0 {
		return b, false
	}
	return b, true
}

// VerifyBeacon reports whether d carries a valid tag under kBeacon.
func VerifyBeacon(d []byte, kBeacon [32]byte) bool {
	if len(d) != BeaconLen {
		return false
	}
	return hmac.Equal(d[beaconBodyEnd:], beaconTag(d[:beaconBodyEnd], kBeacon))
}

func beaconTag(covered []byte, k [32]byte) []byte {
	m := hmac.New(sha256.New, k[:])
	m.Write(covered)
	return m.Sum(nil)[:TagLen]
}

// truncUTF8 cuts s to at most max bytes without splitting a rune and drops
// invalid UTF-8.
func truncUTF8(s string, max int) string {
	if !utf8.ValidString(s) {
		s = string([]rune(s)) // replaces invalid bytes with U+FFFD
	}
	for len(s) > max {
		_, size := utf8.DecodeLastRuneInString(s)
		s = s[:len(s)-size]
	}
	return s
}
