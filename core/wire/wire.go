// Package wire implements the PrivateVPN datagram formats (ARCHITECTURE §6).
//
// Every control message is one UDP datagram:
//
//	magic(2) "PV" | version(1) | type(1) | nonce(24) | XChaCha20-Poly1305 ciphertext
//
// Requests authenticate the 28-byte header as associated data; responses
// authenticate the header followed by the nonce of the request they answer.
package wire

import (
	"crypto/cipher"
	"crypto/rand"
	"errors"

	"golang.org/x/crypto/chacha20poly1305"
)

// Envelope constants.
const (
	Magic0      = 0x50 // 'P'
	Magic1      = 0x56 // 'V'
	Version     = 0x01
	NonceLen    = chacha20poly1305.NonceSizeX // 24
	HeaderLen   = 4 + NonceLen                // 28
	TagLen      = chacha20poly1305.Overhead   // 16
	MinDatagram = HeaderLen + TagLen          // 44
	MaxDatagram = 1200
	MaxInfoJSON = 1100
)

// Type identifies a message.
type Type byte

// Message types (§6.1).
const (
	TypeBeacon    Type = 0x01
	TypeJoinReq   Type = 0x10
	TypeJoinResp  Type = 0x11
	TypeRenewReq  Type = 0x12
	TypeRenewResp Type = 0x13
	TypeLeave     Type = 0x14
	TypeInfoReq   Type = 0x20
	TypeInfoResp  Type = 0x21
	TypeError     Type = 0x7F
)

// Fixed plaintext sizes; TypeInfoResp is variable (see IsResponse/plainBounds).
const (
	joinReqLen   = 132
	joinRespLen  = 132
	renewLen     = 64
	infoReqLen   = 1156
	infoRespMin  = 10
	errorLen     = 16
	infoRespMaxP = infoRespMin + MaxInfoJSON
)

var (
	// ErrMalformed is returned for datagrams that fail the cheap pre-checks.
	ErrMalformed = errors.New("wire: malformed datagram")
	// ErrAuth is returned when AEAD authentication fails.
	ErrAuth = errors.New("wire: authentication failed")
)

// plainBounds returns the allowed plaintext length range for t.
func plainBounds(t Type) (lo, hi int, ok bool) {
	switch t {
	case TypeJoinReq:
		return joinReqLen, joinReqLen, true
	case TypeJoinResp:
		return joinRespLen, joinRespLen, true
	case TypeRenewReq, TypeRenewResp, TypeLeave:
		return renewLen, renewLen, true
	case TypeInfoReq:
		return infoReqLen, infoReqLen, true
	case TypeInfoResp:
		return infoRespMin, infoRespMaxP, true
	case TypeError:
		return errorLen, errorLen, true
	}
	return 0, 0, false
}

// IsResponse reports whether t is answered-to (AD includes request nonce).
func IsResponse(t Type) bool {
	switch t {
	case TypeJoinResp, TypeRenewResp, TypeInfoResp, TypeError:
		return true
	}
	return false
}

// PreCheck performs the cheap, allocation-free checks of §6.1 and returns the
// message type. It never inspects ciphertext.
func PreCheck(b []byte) (Type, bool) {
	if len(b) < MinDatagram || len(b) > MaxDatagram {
		return 0, false
	}
	if b[0] != Magic0 || b[1] != Magic1 || b[2] != Version {
		return 0, false
	}
	t := Type(b[3])
	lo, hi, ok := plainBounds(t)
	if !ok {
		return 0, false
	}
	n := len(b) - HeaderLen - TagLen
	if n < lo || n > hi {
		return 0, false
	}
	return t, true
}

// NewAEAD returns the XChaCha20-Poly1305 AEAD for a 32-byte key.
func NewAEAD(key [32]byte) cipher.AEAD {
	a, err := chacha20poly1305.NewX(key[:])
	if err != nil {
		panic("wire: " + err.Error()) // impossible: key length is fixed
	}
	return a
}

// Nonce is a 24-byte envelope nonce.
type Nonce [NonceLen]byte

// Seal encrypts plaintext as a message of type t. For responses, reqNonce is
// the nonce of the request being answered; for requests it must be nil.
func Seal(aead cipher.AEAD, t Type, plaintext []byte, reqNonce *Nonce) ([]byte, Nonce, error) {
	var n Nonce
	lo, hi, ok := plainBounds(t)
	if !ok || len(plaintext) < lo || len(plaintext) > hi {
		return nil, n, ErrMalformed
	}
	if IsResponse(t) != (reqNonce != nil) {
		return nil, n, errors.New("wire: request nonce required exactly for responses")
	}
	if _, err := rand.Read(n[:]); err != nil {
		return nil, n, err
	}
	out := make([]byte, HeaderLen, HeaderLen+len(plaintext)+TagLen)
	out[0], out[1], out[2], out[3] = Magic0, Magic1, Version, byte(t)
	copy(out[4:], n[:])
	out = aead.Seal(out, n[:], plaintext, ad(out[:HeaderLen], reqNonce))
	return out, n, nil
}

// Open authenticates and decrypts b. reqNonce must be the nonce of the
// request this datagram answers (for responses) or nil (for requests).
func Open(aead cipher.AEAD, b []byte, reqNonce *Nonce) (Type, Nonce, []byte, error) {
	var n Nonce
	t, ok := PreCheck(b)
	if !ok {
		return 0, n, nil, ErrMalformed
	}
	if IsResponse(t) != (reqNonce != nil) {
		return 0, n, nil, ErrMalformed
	}
	copy(n[:], b[4:HeaderLen])
	pt, err := aead.Open(nil, n[:], b[HeaderLen:], ad(b[:HeaderLen], reqNonce))
	if err != nil {
		return 0, n, nil, ErrAuth
	}
	return t, n, pt, nil
}

func ad(header []byte, reqNonce *Nonce) []byte {
	if reqNonce == nil {
		return header
	}
	a := make([]byte, 0, HeaderLen+NonceLen)
	a = append(a, header...)
	return append(a, reqNonce[:]...)
}
