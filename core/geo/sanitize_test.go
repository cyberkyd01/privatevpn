package geo

import (
	"math"
	"math/rand/v2"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestSanitize(t *testing.T) {
	cases := []struct {
		name, in string
		max      int
		want     string
	}{
		{"plain", "Munich", 64, "Munich"},
		{"trim", "  Munich \t", 64, "Munich"},
		{"c0", "Mu\x00ni\nch\r\x1b[31m", 64, "Munich[31m"},
		{"del and c1", "a\x7fb\u0085c\u009bd", 64, "abcd"},
		{"bidi override", "evil\u202egnp.exe", 64, "evilgnp.exe"},
		{"bidi all", "\u202aa\u202bb\u202cc\u202dd\u202ee", 64, "abcde"},
		{"isolates", "\u2066x\u2067y\u2068z\u2069", 64, "xyz"},
		{"marks", "\u200eL\u200fR\u061cA", 64, "LRA"},
		{"invalid utf8", "ab\xff\xfecd", 64, "abcd"},
		{"inner controls then trim", "\u202e  x  \u202c", 64, "x"},
		{"exact length kept", strings.Repeat("a", 64), 64, strings.Repeat("a", 64)},
		{"truncate", strings.Repeat("a", 65), 64, strings.Repeat("a", 63) + "…"},
		{"truncate multibyte", "ééééé", 3, "éé…"},
		{"truncate drops trailing space", "ab cd", 4, "ab…"},
		{"max 1", "abc", 1, "…"},
		{"max 0", "abc", 0, ""},
		{"max negative", "abc", -5, ""},
		{"empty", "", 10, ""},
		{"only controls", "\x00\u202e\u2066", 10, ""},
		{"non-latin kept", "München 東京", 64, "München 東京"},
	}
	for _, c := range cases {
		if got := Sanitize(c.in, c.max); got != c.want {
			t.Errorf("%s: Sanitize(%q, %d) = %q, want %q", c.name, c.in, c.max, got, c.want)
		}
	}
}

// TestSanitizeProperties checks invariants on random input.
func TestSanitizeProperties(t *testing.T) {
	alphabet := []rune{'a', ' ', '\n', 0, 0x7f, 0x85, 0x202e, 0x2066, 0x200f, 'é', '東', 0xfffd, '\t'}
	r := rand.New(rand.NewPCG(1, 2))
	for i := 0; i < 2000; i++ {
		var b strings.Builder
		n := r.IntN(100)
		for j := 0; j < n; j++ {
			if r.IntN(20) == 0 {
				b.WriteByte(0xff) // invalid UTF-8
				continue
			}
			b.WriteRune(alphabet[r.IntN(len(alphabet))])
		}
		max := r.IntN(70)
		out := Sanitize(b.String(), max)
		if !utf8.ValidString(out) {
			t.Fatalf("invalid UTF-8 output %q", out)
		}
		if c := utf8.RuneCountInString(out); c > max {
			t.Fatalf("Sanitize(%q, %d) has %d runes", b.String(), max, c)
		}
		for _, ru := range out {
			if isStripped(ru) {
				t.Fatalf("Sanitize(%q) kept %U", b.String(), ru)
			}
		}
		if out != strings.TrimSpace(out) && !strings.HasSuffix(out, "…") {
			t.Fatalf("Sanitize(%q) not trimmed: %q", b.String(), out)
		}
	}
}

func TestValidCoords(t *testing.T) {
	ok := [][2]float64{{0, 0}, {90, 180}, {-90, -180}, {48.14, 11.58}}
	bad := [][2]float64{{91, 0}, {0, 181}, {-90.0001, 0}, {math.NaN(), 0}, {0, math.Inf(1)}, {math.Inf(-1), 0}}
	for _, c := range ok {
		if !validCoords(c[0], c[1]) {
			t.Errorf("validCoords(%v) = false", c)
		}
	}
	for _, c := range bad {
		if validCoords(c[0], c[1]) {
			t.Errorf("validCoords(%v) = true", c)
		}
	}
}

func TestParseUTCOffset(t *testing.T) {
	cases := []struct {
		in   string
		want int
		ok   bool
	}{
		{"+00:00", 0, true}, {"+0000", 0, true}, {"-05:00", -18000, true}, {"+05:45", 20700, true},
		{"+0530", 19800, true}, {"+01", 3600, true}, {"Z", 0, true}, {"-12:00", -43200, true},
		{"+16:00", 57600, true}, {"+16:01", 0, false}, {"+99:00", 0, false}, {"+01:60", 0, false},
		{"0100", 0, false}, {"+1:00", 0, false}, {"+ab:cd", 0, false}, {"", 0, false}, {"+", 0, false},
	}
	for _, c := range cases {
		got, ok := parseUTCOffset(c.in)
		if got != c.want || ok != c.ok {
			t.Errorf("parseUTCOffset(%q) = %d, %v; want %d, %v", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestNormalizeASNAndSplitOrg(t *testing.T) {
	for in, want := range map[string]string{
		"AS212238": "AS212238", "as3320": "AS3320", "212238": "AS212238", " AS1 ": "AS1",
		"": "", "AS": "", "ASX": "", "AS12345678901": "", "Datacamp": "", "AS1 2": "",
	} {
		if got := normalizeASN(in); got != want {
			t.Errorf("normalizeASN(%q) = %q, want %q", in, got, want)
		}
	}
	asn, isp := splitOrg("AS212238 Datacamp Limited")
	if asn != "AS212238" || isp != "Datacamp Limited" {
		t.Errorf("splitOrg = %q, %q", asn, isp)
	}
	asn, isp = splitOrg("Some ISP")
	if asn != "" || isp != "Some ISP" {
		t.Errorf("splitOrg(no asn) = %q, %q", asn, isp)
	}
}

func TestApplyManual(t *testing.T) {
	base := Result{Source: "geoip", Provider: "ipwho.is", Country: "United Kingdom", CountryCode: "GB",
		City: "London", Lat: 51.5, Lon: -0.12, HasCoords: true, AccuracyKm: 25, ISP: "ISP", ASN: "AS1",
		TZName: "Europe/London", HasOffset: true}
	got := applyManual(base, &Manual{Country: " Narnia\u202e ", Region: "North", City: "Cair Paravel",
		Lat: 10, Lon: 20, HasCoords: true, TZName: "UTC"})
	if got.Source != "manual" || got.AccuracyKm != 0 || got.Country != "Narnia" || got.CountryCode != "" ||
		got.Region != "North" || got.City != "Cair Paravel" || !got.HasCoords || got.Lat != 10 || got.Lon != 20 {
		t.Errorf("applyManual location = %+v", got)
	}
	if got.ISP != "ISP" || got.ASN != "AS1" || got.Provider != "ipwho.is" {
		t.Errorf("applyManual dropped network fields: %+v", got)
	}
	if got.TZName != "UTC" || !got.HasOffset || got.UTCOffsetSec != 0 {
		t.Errorf("applyManual tz = %q %v %d", got.TZName, got.HasOffset, got.UTCOffsetSec)
	}
	got = applyManual(base, &Manual{City: "X", Lat: 100, Lon: 0, HasCoords: true, TZName: "bad tz!"})
	if got.HasCoords || got.TZName != "Europe/London" {
		t.Errorf("applyManual invalid coords/tz = %+v", got)
	}
}
