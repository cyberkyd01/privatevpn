// Package netkey implements the Network Key (ARCHITECTURE §5.1, §5.2):
// generation, the PVN1 text form, and HKDF-derived subkeys.
package netkey

import (
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"errors"
	"strings"
)

// Size is the length of a Network Key in bytes.
const Size = 32

const (
	textPrefix = "PVN1"
	checkLabel = "pvn1 key check"
	hkdfSalt   = "PrivateVPN-v1"
)

// HKDF info labels (§5.2).
const (
	labelBeacon      = "pvn1 beacon"
	labelControl     = "pvn1 control"
	labelPSK         = "pvn1 wg psk"
	labelDirectory   = "pvn1 directory"
	labelDirectoryID = "pvn1 directory id"
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// ErrInvalidKey is returned for malformed key text.
var ErrInvalidKey = errors.New("invalid network key")

// Key is a Network Key. String() never reveals it.
type Key [Size]byte

// String hides the key so it cannot leak through %v.
func (Key) String() string { return "<network key>" }

// Generate returns a fresh random key.
func Generate() (Key, error) {
	var k Key
	_, err := rand.Read(k[:])
	return k, err
}

func check(k Key) [2]byte {
	h := sha256.Sum256(append([]byte(checkLabel), k[:]...))
	return [2]byte{h[0], h[1]}
}

// Text returns the PVN1 text form, e.g. "PVN1-K7Q2M-ZB3XW-…" (70 chars).
func (k Key) Text() string {
	c := check(k)
	raw := append(append([]byte{}, k[:]...), c[:]...)
	body := b32.EncodeToString(raw) // 55 chars
	var sb strings.Builder
	sb.WriteString(textPrefix)
	for i := 0; i < len(body); i += 5 {
		sb.WriteByte('-')
		sb.WriteString(body[i:min(i+5, len(body))])
	}
	return sb.String()
}

// Parse decodes the PVN1 text form. Whitespace and '-' are ignored and the
// input is case-insensitive.
func Parse(text string) (Key, error) {
	var k Key
	if len(text) > 256 {
		return k, ErrInvalidKey
	}
	s := strings.Map(func(r rune) rune {
		switch r {
		case ' ', '\t', '\n', '\r', '-':
			return -1
		}
		return r
	}, strings.ToUpper(text))
	if !strings.HasPrefix(s, textPrefix) {
		return k, ErrInvalidKey
	}
	s = s[len(textPrefix):]
	if len(s) != 55 {
		return k, ErrInvalidKey
	}
	raw, err := b32.DecodeString(s)
	if err != nil || len(raw) != Size+2 {
		return k, ErrInvalidKey
	}
	copy(k[:], raw[:Size])
	c := check(k)
	if subtle.ConstantTimeCompare(c[:], raw[Size:]) != 1 {
		return Key{}, ErrInvalidKey
	}
	return k, nil
}

// Subkeys are the HKDF-derived keys of one network.
type Subkeys struct {
	Beacon      [32]byte
	Control     [32]byte
	PSK         [32]byte
	Directory   [32]byte
	DirectoryID [16]byte
}

// String hides the keys.
func (Subkeys) String() string { return "<subkeys>" }

// Derive computes all subkeys of k.
func (k Key) Derive() Subkeys {
	var s Subkeys
	derive(k, labelBeacon, s.Beacon[:])
	derive(k, labelControl, s.Control[:])
	derive(k, labelPSK, s.PSK[:])
	derive(k, labelDirectory, s.Directory[:])
	derive(k, labelDirectoryID, s.DirectoryID[:])
	return s
}

func derive(k Key, label string, out []byte) {
	b, err := hkdf.Key(sha256.New, k[:], []byte(hkdfSalt), label, len(out))
	if err != nil {
		panic("netkey: hkdf: " + err.Error()) // impossible for these lengths
	}
	copy(out, b)
}
