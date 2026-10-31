package netkey

import (
	"strings"
	"testing"
)

func TestTextRoundTrip(t *testing.T) {
	k, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	txt := k.Text()
	if len(txt) != 70 || !strings.HasPrefix(txt, "PVN1-") {
		t.Fatalf("text form %q (%d chars)", txt, len(txt))
	}
	got, err := Parse(" " + strings.ToLower(txt) + "\n")
	if err != nil || got != k {
		t.Fatalf("parse: %v", err)
	}
}

func TestParseRejects(t *testing.T) {
	k, _ := Generate()
	txt := k.Text()
	// Flip one character of the body: checksum must catch it.
	b := []byte(txt)
	if b[10] == 'A' {
		b[10] = 'B'
	} else {
		b[10] = 'A'
	}
	for _, s := range []string{"", "PVN1", "PVN2" + txt[4:], string(b), txt + "AAAAA", strings.Repeat("A", 300)} {
		if _, err := Parse(s); err == nil {
			t.Errorf("accepted %q", s)
		}
	}
}

func TestDeriveDistinct(t *testing.T) {
	k, _ := Generate()
	s := k.Derive()
	if s.Beacon == s.Control || s.Control == s.PSK || s.Beacon == s.PSK {
		t.Fatal("subkeys not domain-separated")
	}
	if k.Derive() != s {
		t.Fatal("derivation not deterministic")
	}
	if k.String() == txtOf(k) || s.String() != "<subkeys>" {
		t.Fatal("String leaks")
	}
}

func txtOf(k Key) string { return k.Text() }
