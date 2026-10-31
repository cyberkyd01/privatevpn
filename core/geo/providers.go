package geo

import (
	"bytes"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
)

// provider is one GeoIP service (§10.2).
type provider struct {
	name  string
	url   string
	parse func(body []byte) (raw, error)
}

// providers are tried in order; first valid response wins. Tests replace
// the URLs with httptest servers.
var providers = []provider{
	{name: "ipwho.is", url: "https://ipwho.is/", parse: parseIPWhoIs},
	{name: "ipinfo.io", url: "https://ipinfo.io/json", parse: parseIPInfo},
	{name: "ipapi.co", url: "https://ipapi.co/json/", parse: parseIPAPI},
}

// raw is a provider response mapped onto common fields, not yet validated.
type raw struct {
	IP                   string
	Country, CountryCode string
	Region, City         string
	Lat, Lon             *float64
	ISP, ASN             string
	TZName               string
	UTCOffset            string // "+01:00" or "+0100"
	OffsetSec            *int64 // seconds, when the provider gives a number
}

var errProviderError = errors.New("provider reported an error")

// flexString decodes a JSON string or number (e.g. an ASN given as 212238
// or "AS212238"); null leaves it empty.
type flexString string

func (f *flexString) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if len(b) == 0 || string(b) == "null" {
		return nil
	}
	if b[0] == '"' {
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
		*f = flexString(s)
		return nil
	}
	var n json.Number
	if err := json.Unmarshal(b, &n); err != nil {
		return err
	}
	*f = flexString(n.String())
	return nil
}

// decodeObject decodes a JSON object into v and rejects trailing data.
func decodeObject(body []byte, v any) error {
	body = bytes.TrimSpace(body)
	if len(body) == 0 || body[0] != '{' {
		return errors.New("not a JSON object")
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("trailing data")
	}
	return nil
}

// ipwho.is: {"ip","success":true,"country","country_code","region","city",
// "latitude","longitude","connection":{"asn":212238,"isp"},
// "timezone":{"id","utc":"+00:00","offset":0}}
func parseIPWhoIs(body []byte) (raw, error) {
	var v struct {
		IP          string   `json:"ip"`
		Success     *bool    `json:"success"`
		Country     string   `json:"country"`
		CountryCode string   `json:"country_code"`
		Region      string   `json:"region"`
		City        string   `json:"city"`
		Latitude    *float64 `json:"latitude"`
		Longitude   *float64 `json:"longitude"`
		Connection  struct {
			ASN flexString `json:"asn"`
			ISP string     `json:"isp"`
		} `json:"connection"`
		Timezone struct {
			ID     string `json:"id"`
			UTC    string `json:"utc"`
			Offset *int64 `json:"offset"`
		} `json:"timezone"`
	}
	if err := decodeObject(body, &v); err != nil {
		return raw{}, err
	}
	if v.Success != nil && !*v.Success {
		return raw{}, errProviderError
	}
	return raw{
		IP: v.IP, Country: v.Country, CountryCode: v.CountryCode,
		Region: v.Region, City: v.City, Lat: v.Latitude, Lon: v.Longitude,
		ISP: v.Connection.ISP, ASN: string(v.Connection.ASN),
		TZName: v.Timezone.ID, UTCOffset: v.Timezone.UTC, OffsetSec: v.Timezone.Offset,
	}, nil
}

// ipinfo.io: {"ip","city","region","country":"GB","loc":"51.5,-0.12",
// "org":"AS212238 Datacamp Limited","timezone"}. country is a code only; it
// is used as the country name too.
func parseIPInfo(body []byte) (raw, error) {
	var v struct {
		IP       string `json:"ip"`
		City     string `json:"city"`
		Region   string `json:"region"`
		Country  string `json:"country"`
		Loc      string `json:"loc"`
		Org      string `json:"org"`
		Timezone string `json:"timezone"`
		Bogon    bool   `json:"bogon"`
	}
	if err := decodeObject(body, &v); err != nil {
		return raw{}, err
	}
	if v.Bogon {
		return raw{}, errProviderError
	}
	r := raw{
		IP: v.IP, Country: v.Country, CountryCode: v.Country,
		Region: v.Region, City: v.City, TZName: v.Timezone,
	}
	if loc := strings.TrimSpace(v.Loc); loc != "" {
		a, b, ok := strings.Cut(loc, ",")
		if !ok {
			return raw{}, errors.New("bad loc")
		}
		lat, err1 := strconv.ParseFloat(strings.TrimSpace(a), 64)
		lon, err2 := strconv.ParseFloat(strings.TrimSpace(b), 64)
		if err1 != nil || err2 != nil {
			return raw{}, errors.New("bad loc")
		}
		r.Lat, r.Lon = &lat, &lon
	}
	r.ASN, r.ISP = splitOrg(v.Org)
	return r, nil
}

// splitOrg splits "AS212238 Datacamp Limited" into ASN and ISP.
func splitOrg(org string) (asn, isp string) {
	org = strings.TrimSpace(org)
	first, rest, _ := strings.Cut(org, " ")
	if reASN.MatchString(first) {
		return first, strings.TrimSpace(rest)
	}
	return "", org
}

// ipapi.co: {"ip","city","region","country_name","country_code","latitude",
// "longitude","timezone","utc_offset":"+0000","asn":"AS212238","org"}
func parseIPAPI(body []byte) (raw, error) {
	var v struct {
		IP          string     `json:"ip"`
		Error       bool       `json:"error"`
		City        string     `json:"city"`
		Region      string     `json:"region"`
		CountryName string     `json:"country_name"`
		CountryCode string     `json:"country_code"`
		Latitude    *float64   `json:"latitude"`
		Longitude   *float64   `json:"longitude"`
		Timezone    string     `json:"timezone"`
		UTCOffset   string     `json:"utc_offset"`
		ASN         flexString `json:"asn"`
		Org         string     `json:"org"`
	}
	if err := decodeObject(body, &v); err != nil {
		return raw{}, err
	}
	if v.Error {
		return raw{}, errProviderError
	}
	return raw{
		IP: v.IP, Country: v.CountryName, CountryCode: v.CountryCode,
		Region: v.Region, City: v.City, Lat: v.Latitude, Lon: v.Longitude,
		ISP: v.Org, ASN: string(v.ASN), TZName: v.Timezone, UTCOffset: v.UTCOffset,
	}, nil
}

// parseUTCOffset parses "+01:00", "-0530", "+05:45", "Z"/"+00" style
// offsets into seconds.
func parseUTCOffset(s string) (int, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, false
	}
	if s == "Z" {
		return 0, true
	}
	sign := 1
	switch s[0] {
	case '+':
	case '-':
		sign = -1
	default:
		return 0, false
	}
	s = strings.ReplaceAll(s[1:], ":", "")
	if len(s) != 2 && len(s) != 4 {
		return 0, false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
	}
	h, _ := strconv.Atoi(s[:2])
	m := 0
	if len(s) == 4 {
		m, _ = strconv.Atoi(s[2:])
	}
	if m >= 60 {
		return 0, false
	}
	off := sign * (h*3600 + m*60)
	if off < -maxOffsetSec || off > maxOffsetSec {
		return 0, false
	}
	return off, true
}

// normalizeASN accepts "AS212238", "as212238" or "212238" and returns
// "AS212238", or "" when the value is not an AS number.
func normalizeASN(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && strings.EqualFold(s[:2], "AS") {
		s = s[2:]
	}
	s = "AS" + s
	if len(s) > capASN || !reASN.MatchString(s) {
		return ""
	}
	return s
}
