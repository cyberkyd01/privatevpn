package wire

import (
	"encoding/binary"
	"net/netip"
)

var be = binary.BigEndian

// JoinReq is sent by a client to obtain a lease (§6.3). It carries nothing
// identifying: an ephemeral key, a timestamp and an MTU hint.
type JoinReq struct {
	ClientPub [32]byte
	TS        uint64
	MTUHint   uint16
	Flags     uint16
}

// Marshal returns the 132-byte plaintext.
func (m JoinReq) Marshal() []byte {
	b := make([]byte, joinReqLen)
	copy(b[0:32], m.ClientPub[:])
	be.PutUint64(b[32:], m.TS)
	be.PutUint16(b[40:], m.MTUHint)
	be.PutUint16(b[42:], m.Flags)
	return b
}

// ParseJoinReq decodes a JoinReq plaintext.
func ParseJoinReq(b []byte) (JoinReq, error) {
	var m JoinReq
	if len(b) != joinReqLen {
		return m, ErrMalformed
	}
	copy(m.ClientPub[:], b[0:32])
	m.TS = be.Uint64(b[32:])
	m.MTUHint = be.Uint16(b[40:])
	m.Flags = be.Uint16(b[42:])
	return m, nil
}

// JoinResp flag bits.
const (
	JoinFlagLANAccess = 1 << 0
)

// JoinResp answers a JoinReq (§6.4).
type JoinResp struct {
	Status     byte
	Flags      byte
	TS         uint64
	Assigned   netip.Addr
	PrefixLen  byte
	GatewayIP  netip.Addr
	DNS        netip.Addr
	GatewayPub [32]byte
	WGPort     uint16
	MTU        uint16
	Keepalive  uint16
	LeaseSec   uint32
	LeaseToken [16]byte
}

// Marshal returns the 132-byte plaintext.
func (m JoinResp) Marshal() []byte {
	b := make([]byte, joinRespLen)
	b[0] = m.Status
	b[1] = m.Flags
	be.PutUint64(b[2:], m.TS)
	put4(b[10:], m.Assigned)
	b[14] = m.PrefixLen
	put4(b[15:], m.GatewayIP)
	put4(b[19:], m.DNS)
	copy(b[23:55], m.GatewayPub[:])
	be.PutUint16(b[55:], m.WGPort)
	be.PutUint16(b[57:], m.MTU)
	be.PutUint16(b[59:], m.Keepalive)
	be.PutUint32(b[61:], m.LeaseSec)
	copy(b[65:81], m.LeaseToken[:])
	return b
}

// ParseJoinResp decodes a JoinResp plaintext (no semantic validation).
func ParseJoinResp(b []byte) (JoinResp, error) {
	var m JoinResp
	if len(b) != joinRespLen {
		return m, ErrMalformed
	}
	m.Status = b[0]
	m.Flags = b[1]
	m.TS = be.Uint64(b[2:])
	m.Assigned = get4(b[10:])
	m.PrefixLen = b[14]
	m.GatewayIP = get4(b[15:])
	m.DNS = get4(b[19:])
	copy(m.GatewayPub[:], b[23:55])
	m.WGPort = be.Uint16(b[55:])
	m.MTU = be.Uint16(b[57:])
	m.Keepalive = be.Uint16(b[59:])
	m.LeaseSec = be.Uint32(b[61:])
	copy(m.LeaseToken[:], b[65:81])
	return m, nil
}

// LeaseReq is the body of RENEW_REQ and LEAVE (§6.5).
type LeaseReq struct {
	ClientPub  [32]byte
	TS         uint64
	LeaseToken [16]byte
}

// Marshal returns the 64-byte plaintext.
func (m LeaseReq) Marshal() []byte {
	b := make([]byte, renewLen)
	copy(b[0:32], m.ClientPub[:])
	be.PutUint64(b[32:], m.TS)
	copy(b[40:56], m.LeaseToken[:])
	return b
}

// ParseLeaseReq decodes a RENEW_REQ / LEAVE plaintext.
func ParseLeaseReq(b []byte) (LeaseReq, error) {
	var m LeaseReq
	if len(b) != renewLen {
		return m, ErrMalformed
	}
	copy(m.ClientPub[:], b[0:32])
	m.TS = be.Uint64(b[32:])
	copy(m.LeaseToken[:], b[40:56])
	return m, nil
}

// RenewResp answers a RENEW_REQ (§6.5).
type RenewResp struct {
	Status   byte
	Flags    byte
	TS       uint64
	LeaseSec uint32
}

// Marshal returns the 64-byte plaintext.
func (m RenewResp) Marshal() []byte {
	b := make([]byte, renewLen)
	b[0] = m.Status
	b[1] = m.Flags
	be.PutUint64(b[2:], m.TS)
	be.PutUint32(b[10:], m.LeaseSec)
	return b
}

// ParseRenewResp decodes a RENEW_RESP plaintext.
func ParseRenewResp(b []byte) (RenewResp, error) {
	var m RenewResp
	if len(b) != renewLen {
		return m, ErrMalformed
	}
	m.Status = b[0]
	m.Flags = b[1]
	m.TS = be.Uint64(b[2:])
	m.LeaseSec = be.Uint32(b[10:])
	return m, nil
}

// InfoReq asks a gateway for its details (§6.6). It is padded so that no
// response can be larger than the request.
type InfoReq struct{ TS uint64 }

// Marshal returns the 1156-byte plaintext.
func (m InfoReq) Marshal() []byte {
	b := make([]byte, infoReqLen)
	be.PutUint64(b[0:], m.TS)
	return b
}

// ParseInfoReq decodes an INFO_REQ plaintext.
func ParseInfoReq(b []byte) (InfoReq, error) {
	if len(b) != infoReqLen {
		return InfoReq{}, ErrMalformed
	}
	return InfoReq{TS: be.Uint64(b[0:])}, nil
}

// InfoResp carries the gateway's details JSON (§10.5).
type InfoResp struct {
	TS   uint64
	JSON []byte
}

// Marshal returns the plaintext; JSON must be ≤ MaxInfoJSON bytes.
func (m InfoResp) Marshal() ([]byte, error) {
	if len(m.JSON) > MaxInfoJSON {
		return nil, ErrMalformed
	}
	b := make([]byte, infoRespMin+len(m.JSON))
	be.PutUint64(b[0:], m.TS)
	be.PutUint16(b[8:], uint16(len(m.JSON)))
	copy(b[10:], m.JSON)
	return b, nil
}

// ParseInfoResp decodes an INFO_RESP plaintext.
func ParseInfoResp(b []byte) (InfoResp, error) {
	var m InfoResp
	if len(b) < infoRespMin {
		return m, ErrMalformed
	}
	m.TS = be.Uint64(b[0:])
	n := int(be.Uint16(b[8:]))
	if n > MaxInfoJSON || infoRespMin+n != len(b) {
		return m, ErrMalformed
	}
	m.JSON = append([]byte(nil), b[10:]...)
	return m, nil
}

// ErrCode is the code carried by an ERROR message (§6.6).
type ErrCode byte

// Error codes.
const (
	ErrNone         ErrCode = 0
	ErrPoolFull     ErrCode = 1
	ErrNotAccepting ErrCode = 2
	ErrUnknownLease ErrCode = 3
	ErrBadRequest   ErrCode = 4
	ErrRateLimited  ErrCode = 5
	ErrSubnet       ErrCode = 6
)

func (c ErrCode) String() string {
	switch c {
	case ErrPoolFull:
		return "pool_full"
	case ErrNotAccepting:
		return "not_accepting"
	case ErrUnknownLease:
		return "unknown_lease"
	case ErrBadRequest:
		return "bad_request"
	case ErrRateLimited:
		return "rate_limited"
	case ErrSubnet:
		return "subnet_conflict"
	}
	return "error"
}

// ErrorMsg is the ERROR message plaintext.
type ErrorMsg struct {
	Code ErrCode
	TS   uint64
}

// Marshal returns the 16-byte plaintext.
func (m ErrorMsg) Marshal() []byte {
	b := make([]byte, errorLen)
	b[0] = byte(m.Code)
	be.PutUint64(b[1:], m.TS)
	return b
}

// ParseErrorMsg decodes an ERROR plaintext.
func ParseErrorMsg(b []byte) (ErrorMsg, error) {
	if len(b) != errorLen {
		return ErrorMsg{}, ErrMalformed
	}
	return ErrorMsg{Code: ErrCode(b[0]), TS: be.Uint64(b[1:])}, nil
}

func put4(b []byte, a netip.Addr) {
	if a.Is4() {
		v := a.As4()
		copy(b[:4], v[:])
	}
}

func get4(b []byte) netip.Addr {
	return netip.AddrFrom4([4]byte(b[:4]))
}
