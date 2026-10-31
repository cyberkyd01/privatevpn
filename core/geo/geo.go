// Package geo learns the gateway's public IP address and approximate
// location from public GeoIP providers (ARCHITECTURE §10.2, §10.3) and
// sanitises untrusted strings (§10.6).
//
// Requests are bare GETs carrying only a User-Agent header; nothing about
// clients is ever sent. Results are kept in memory only (§10.7) and logged at
// no finer granularity than "geo: updated via <provider>" (§12.1).
package geo

import (
	"math"
	"net/netip"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Field caps (§10.5).
const (
	capString   = 64 // country, region, city, isp
	capASN      = 16
	capProvider = 32
	capTZName   = 64

	geoipAccuracyKm = 25
	maxOffsetSec    = 16 * 3600
)

// Source values.
const (
	sourceGeoIP  = "geoip"
	sourceManual = "manual"
	sourceNone   = "none"
)

var (
	reCountryCode = regexp.MustCompile(`^[A-Z]{2}$`)
	reTZName      = regexp.MustCompile(`^[A-Za-z0-9_+\-/]{1,64}$`)
	reASN         = regexp.MustCompile(`^AS[0-9]{1,10}$`)
)

// Result is the gateway's public address and approximate location. All
// strings are sanitised and capped; addresses are valid or the zero Addr.
type Result struct {
	Source       string // "geoip" | "manual" | "none"
	Provider     string
	Country      string
	CountryCode  string
	Region       string
	City         string
	Lat, Lon     float64
	HasCoords    bool
	AccuracyKm   int // 25 for geoip, 0 manual
	ISP, ASN     string
	PublicIP     netip.Addr // IPv4
	PublicIP6    netip.Addr // IPv6, often absent
	TZName       string     // IANA, from the provider (Windows has no other source)
	UTCOffsetSec int
	HasOffset    bool // UTCOffsetSec came from the provider
	CheckedAt    time.Time
}

// Manual is the user's location override (settings gateway.geo.manual).
type Manual struct {
	Country, Region, City string
	Lat, Lon              float64
	HasCoords             bool
	TZName                string
}

// Sanitize trims s, removes invalid UTF-8, C0/C1 control characters and the
// bidi controls U+202A–U+202E, U+2066–U+2069, U+200E, U+200F (and U+061C),
// and truncates the result to at most max runes; a truncated string ends in
// "…", which counts towards max. max ≤ 0 yields "".
func Sanitize(s string, max int) string {
	if max <= 0 {
		return ""
	}
	s = strings.ToValidUTF8(s, "")
	s = strings.Map(func(r rune) rune {
		if isStripped(r) {
			return -1
		}
		return r
	}, s)
	s = strings.TrimSpace(s)
	if utf8.RuneCountInString(s) <= max {
		return s
	}
	n := 0
	for i := range s {
		if n == max-1 {
			s = s[:i]
			break
		}
		n++
	}
	return strings.TrimRightFunc(s, unicode.IsSpace) + "…"
}

func isStripped(r rune) bool {
	switch {
	case r < 0x20, r == 0x7f, r >= 0x80 && r <= 0x9f: // C0, DEL, C1
		return true
	case r >= 0x202a && r <= 0x202e, r >= 0x2066 && r <= 0x2069: // bidi embeddings/isolates
		return true
	case r == 0x200e, r == 0x200f, r == 0x061c: // LRM, RLM, ALM
		return true
	}
	return false
}

// validCoords reports whether lat/lon are finite and in range.
func validCoords(lat, lon float64) bool {
	if math.IsNaN(lat) || math.IsNaN(lon) || math.IsInf(lat, 0) || math.IsInf(lon, 0) {
		return false
	}
	return lat >= -90 && lat <= 90 && lon >= -180 && lon <= 180
}

// validTZName reports whether s is acceptable as tz.name (§10.5).
func validTZName(s string) bool {
	return reTZName.MatchString(s) && !strings.Contains(s, "..")
}

// applyManual overlays the manual location on res: source "manual",
// accuracy 0, location and (when given) time zone from m. The public
// addresses, ISP/ASN and CheckedAt of the last lookup are kept.
func applyManual(res Result, m *Manual) Result {
	res.Source = sourceManual
	res.Country = Sanitize(m.Country, capString)
	res.CountryCode = ""
	res.Region = Sanitize(m.Region, capString)
	res.City = Sanitize(m.City, capString)
	res.Lat, res.Lon, res.HasCoords = 0, 0, false
	if m.HasCoords && validCoords(m.Lat, m.Lon) {
		res.Lat, res.Lon, res.HasCoords = m.Lat, m.Lon, true
	}
	res.AccuracyKm = 0
	if tz := strings.TrimSpace(m.TZName); validTZName(tz) {
		res.TZName = tz
		res.UTCOffsetSec, res.HasOffset = 0, false
		if loc, err := time.LoadLocation(tz); err == nil {
			_, off := time.Now().In(loc).Zone()
			res.UTCOffsetSec, res.HasOffset = off, true
		}
	}
	return res
}
