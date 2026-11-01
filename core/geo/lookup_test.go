package geo

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"
)

// --- fixtures (shapes verified against the live providers) ---

func ipwhoBase() map[string]any {
	return map[string]any{
		"ip": "203.0.113.7", "success": true, "type": "IPv4", "continent": "Europe",
		"country": "United Kingdom", "country_code": "GB", "region": "England", "city": "London",
		"latitude": 51.5074, "longitude": -0.1278, "is_eu": false,
		"connection": map[string]any{"asn": 212238, "org": "Datacamp Limited", "isp": "Datacamp Limited", "domain": "datacamp.co.uk"},
		"timezone":   map[string]any{"id": "Europe/London", "abbr": "GMT", "is_dst": false, "offset": 0, "utc": "+00:00"},
	}
}

func ipinfoBase() map[string]any {
	return map[string]any{
		"ip": "203.0.113.7", "city": "London", "region": "England", "country": "GB",
		"loc": "51.5085,-0.1257", "org": "AS212238 Datacamp Limited", "postal": "E1W",
		"timezone": "Europe/London", "readme": "https://ipinfo.io/missingauth",
	}
}

func ipapiBase() map[string]any {
	return map[string]any{
		"ip": "203.0.113.7", "network": "203.0.113.0/24", "version": "IPv4", "city": "London",
		"region": "England", "region_code": "ENG", "country": "GB", "country_name": "United Kingdom",
		"country_code": "GB", "country_code_iso3": "GBR", "in_eu": false, "postal": "EC1A",
		"latitude": 51.5085, "longitude": -0.1257, "timezone": "Europe/London", "utc_offset": "+0000",
		"country_calling_code": "+44", "currency": "GBP", "asn": "AS212238", "org": "Datacamp Limited",
	}
}

func mustJSON(t *testing.T, m map[string]any, mod func(map[string]any)) string {
	t.Helper()
	if mod != nil {
		mod(m)
	}
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// resp is one canned HTTP response.
type resp struct {
	status   int
	ctype    string
	body     string
	location string // redirect target; "self:<path>" = same server
}

func okJSON(body string) resp {
	return resp{status: 200, ctype: "application/json; charset=utf-8", body: body}
}

var failResp = resp{status: 503, ctype: "application/json", body: `{"ip":"203.0.113.9"}`}

// fakeServer is an httptest TLS server serving canned responses per path and
// recording request headers.
type fakeServer struct {
	*httptest.Server
	mu      sync.Mutex
	routes  map[string]resp
	headers []http.Header
	methods []string
	hits    map[string]int
}

func newFakeServer(t *testing.T, routes map[string]resp) *fakeServer {
	t.Helper()
	fs := &fakeServer{routes: routes, hits: map[string]int{}}
	fs.Server = httptest.NewTLSServer(http.HandlerFunc(fs.serve))
	t.Cleanup(fs.Close)
	return fs
}

func (fs *fakeServer) serve(w http.ResponseWriter, r *http.Request) {
	fs.mu.Lock()
	fs.headers = append(fs.headers, r.Header.Clone())
	fs.methods = append(fs.methods, r.Method)
	fs.hits[r.URL.Path]++
	rs, ok := fs.routes[r.URL.Path]
	fs.mu.Unlock()
	if !ok {
		http.NotFound(w, r)
		return
	}
	if rs.location != "" {
		loc := rs.location
		if p, ok := strings.CutPrefix(loc, "self:"); ok {
			loc = fs.URL + p
		}
		w.Header().Set("Location", loc)
	}
	if rs.ctype != "" {
		w.Header().Set("Content-Type", rs.ctype)
	}
	w.WriteHeader(rs.status)
	_, _ = w.Write([]byte(rs.body))
}

func (fs *fakeServer) hitCount(path string) int {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	return fs.hits[path]
}

// useProviders points the package providers at srv for the test.
func useProviders(t *testing.T, base string) {
	t.Helper()
	old := providers
	providers = []provider{
		{name: "ipwho.is", url: base + "/ipwho", parse: parseIPWhoIs},
		{name: "ipinfo.io", url: base + "/ipinfo", parse: parseIPInfo},
		{name: "ipapi.co", url: base + "/ipapi", parse: parseIPAPI},
	}
	t.Cleanup(func() { providers = old })
}

// testClient is NewHTTPClient(dial) trusting the given test servers.
func testClient(t *testing.T, dial func(ctx context.Context, network, addr string) (net.Conn, error), srvs ...*fakeServer) *http.Client {
	t.Helper()
	c := NewHTTPClient(dial)
	pool := x509.NewCertPool()
	for _, s := range srvs {
		pool.AddCert(s.Certificate())
	}
	c.Transport.(*http.Transport).TLSClientConfig.RootCAs = pool
	return c
}

// v4Only refuses forced-tcp6 dials (as on a host without IPv6).
func v4Only(ctx context.Context, network, addr string) (net.Conn, error) {
	if network == "tcp6" {
		return nil, errors.New("no ipv6 in test")
	}
	var d net.Dialer
	return d.DialContext(ctx, "tcp", addr)
}

const ua = "PrivateVPNPro/1.0.0"

func lookup(t *testing.T, c *http.Client) (Result, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	return Lookup(ctx, c, ua)
}

// --- tests ---

func TestLookupIPWhoIs(t *testing.T) {
	fs := newFakeServer(t, map[string]resp{"/ipwho": okJSON(mustJSON(t, ipwhoBase(), nil))})
	useProviders(t, fs.URL)
	before := time.Now()
	res, err := lookup(t, testClient(t, v4Only, fs))
	if err != nil {
		t.Fatal(err)
	}
	want := Result{
		Source: "geoip", Provider: "ipwho.is", Country: "United Kingdom", CountryCode: "GB",
		Region: "England", City: "London", Lat: 51.5074, Lon: -0.1278, HasCoords: true, AccuracyKm: 25,
		ISP: "Datacamp Limited", ASN: "AS212238", PublicIP: netip.MustParseAddr("203.0.113.7"),
		TZName: "Europe/London", UTCOffsetSec: 0, HasOffset: true,
	}
	if res.CheckedAt.Before(before) || res.CheckedAt.After(time.Now()) {
		t.Errorf("CheckedAt = %v", res.CheckedAt)
	}
	res.CheckedAt = time.Time{}
	if res != want {
		t.Errorf("got  %+v\nwant %+v", res, want)
	}
	// The request is a bare GET with only User-Agent (Connection: close is
	// added by the transport because keep-alives are off).
	fs.mu.Lock()
	defer fs.mu.Unlock()
	if len(fs.headers) != 1 || fs.methods[0] != http.MethodGet {
		t.Fatalf("requests = %d %v", len(fs.headers), fs.methods)
	}
	for k, v := range fs.headers[0] {
		switch k {
		case "User-Agent":
			if len(v) != 1 || v[0] != ua {
				t.Errorf("User-Agent = %q", v)
			}
		case "Connection":
		default:
			t.Errorf("unexpected request header %s: %q", k, v)
		}
	}
}

func TestLookupFallsBackInOrder(t *testing.T) {
	fs := newFakeServer(t, map[string]resp{
		"/ipwho":  {status: 500, ctype: "application/json", body: mustJSON(t, ipwhoBase(), nil)},
		"/ipinfo": {status: 200, ctype: "text/html", body: mustJSON(t, ipinfoBase(), nil)},
		"/ipapi":  okJSON(mustJSON(t, ipapiBase(), nil)),
	})
	useProviders(t, fs.URL)
	res, err := lookup(t, testClient(t, v4Only, fs))
	if err != nil {
		t.Fatal(err)
	}
	if res.Provider != "ipapi.co" || res.Country != "United Kingdom" || res.CountryCode != "GB" ||
		res.City != "London" || res.Region != "England" || res.Lat != 51.5085 || res.Lon != -0.1257 ||
		res.ASN != "AS212238" || res.ISP != "Datacamp Limited" || res.TZName != "Europe/London" ||
		!res.HasOffset || res.UTCOffsetSec != 0 || res.PublicIP != netip.MustParseAddr("203.0.113.7") {
		t.Errorf("ipapi.co mapping: %+v", res)
	}
	for _, p := range []string{"/ipwho", "/ipinfo", "/ipapi"} {
		if n := fs.hitCount(p); n != 1 {
			t.Errorf("%s hit %d times", p, n)
		}
	}
}

func TestLookupIPInfo(t *testing.T) {
	fs := newFakeServer(t, map[string]resp{
		"/ipwho":  okJSON(`{"ip":"203.0.113.7","success":false,"message":"rate limited"}`),
		"/ipinfo": okJSON(mustJSON(t, ipinfoBase(), nil)),
		"/ipapi":  okJSON(mustJSON(t, ipapiBase(), nil)),
	})
	useProviders(t, fs.URL)
	res, err := lookup(t, testClient(t, v4Only, fs))
	if err != nil {
		t.Fatal(err)
	}
	if res.Provider != "ipinfo.io" || res.Country != "GB" || res.CountryCode != "GB" || res.City != "London" ||
		res.Lat != 51.5085 || res.Lon != -0.1257 || !res.HasCoords || res.ASN != "AS212238" ||
		res.ISP != "Datacamp Limited" || res.TZName != "Europe/London" || res.HasOffset {
		t.Errorf("ipinfo.io mapping: %+v", res)
	}
	if fs.hitCount("/ipapi") != 0 {
		t.Error("ipapi.co queried after ipinfo.io succeeded")
	}
}

// TestLookupHostile feeds hostile ipwho.is responses; the other providers
// fail, so each case either yields a sanitised ipwho.is result or an error.
func TestLookupHostile(t *testing.T) {
	long := strings.Repeat("A", 10*1024)
	type check func(t *testing.T, r Result)
	cases := []struct {
		name    string
		resp    resp
		wantErr string // substring of the error; "" = success
		check   check
	}{
		{name: "bidi and controls", resp: okJSON(mustJSON(t, ipwhoBase(), func(m map[string]any) {
			m["city"] = "Lon\u202edon\u2066x\u2069"
			m["region"] = "Eng\u001b[2Jland\n"
			m["country"] = "\u200fUnited\u0085 Kingdom\u202c"
		})), check: func(t *testing.T, r Result) {
			if r.City != "Londonx" || r.Region != "Eng[2Jland" || r.Country != "United Kingdom" {
				t.Errorf("not sanitised: %q %q %q", r.City, r.Region, r.Country)
			}
		}},
		{name: "10KB string", resp: okJSON(mustJSON(t, ipwhoBase(), func(m map[string]any) {
			m["city"] = long
		})), check: func(t *testing.T, r Result) {
			if utf8.RuneCountInString(r.City) != 64 || r.City != strings.Repeat("A", 63)+"…" {
				t.Errorf("city not capped to 64: %d runes", utf8.RuneCountInString(r.City))
			}
		}},
		{name: "long string in every field", resp: okJSON(mustJSON(t, ipwhoBase(), func(m map[string]any) {
			mid := strings.Repeat("\u202eé", 300)
			m["region"], m["country"] = mid, mid
			m["connection"] = map[string]any{"asn": "AS" + strings.Repeat("9", 1024), "isp": mid}
			m["timezone"] = map[string]any{"id": strings.Repeat("A", 1024), "utc": strings.Repeat("+", 1024)}
		})), check: func(t *testing.T, r Result) {
			for _, s := range []string{r.Region, r.Country, r.ISP} {
				if s != strings.Repeat("é", 63)+"…" {
					t.Errorf("not sanitised/capped: %d runes", utf8.RuneCountInString(s))
				}
			}
			if r.ASN != "" || r.TZName != "" || r.HasOffset {
				t.Errorf("oversized optional fields kept: asn=%q tz=%q off=%v", r.ASN, r.TZName, r.HasOffset)
			}
		}},
		{name: "hostile tz name", resp: okJSON(mustJSON(t, ipwhoBase(), func(m map[string]any) {
			m["timezone"] = map[string]any{"id": "../../etc/passwd", "utc": "+99:00", "offset": 999999}
		})), check: func(t *testing.T, r Result) {
			if r.TZName != "" || r.HasOffset {
				t.Errorf("tz kept: %q %v", r.TZName, r.HasOffset)
			}
		}},
		{name: "tz markup", resp: okJSON(mustJSON(t, ipwhoBase(), func(m map[string]any) {
			m["timezone"] = map[string]any{"id": "Europe/London<script>", "utc": "+05:45"}
		})), check: func(t *testing.T, r Result) {
			if r.TZName != "" || !r.HasOffset || r.UTCOffsetSec != 20700 {
				t.Errorf("tz = %q %v %d", r.TZName, r.HasOffset, r.UTCOffsetSec)
			}
		}},
		{name: "no coordinates", resp: okJSON(mustJSON(t, ipwhoBase(), func(m map[string]any) {
			delete(m, "latitude")
			delete(m, "longitude")
		})), check: func(t *testing.T, r Result) {
			if r.HasCoords {
				t.Error("HasCoords without coordinates")
			}
		}},
		{name: "NaN literal", resp: okJSON(strings.Replace(mustJSON(t, ipwhoBase(), nil), `"latitude":51.5074`, `"latitude":NaN`, 1)), wantErr: "ipwho.is: decode"},
		{name: "NaN string", resp: okJSON(mustJSON(t, ipwhoBase(), func(m map[string]any) { m["latitude"] = "NaN" })), wantErr: "ipwho.is: decode"},
		{name: "huge exponent", resp: okJSON(strings.Replace(mustJSON(t, ipwhoBase(), nil), `"longitude":-0.1278`, `"longitude":1e400`, 1)), wantErr: "ipwho.is: decode"},
		{name: "lat out of range", resp: okJSON(mustJSON(t, ipwhoBase(), func(m map[string]any) { m["latitude"] = 90.5 })), wantErr: "invalid coordinates"},
		{name: "lon out of range", resp: okJSON(mustJSON(t, ipwhoBase(), func(m map[string]any) { m["longitude"] = -180.01 })), wantErr: "invalid coordinates"},
		{name: "lat only", resp: okJSON(mustJSON(t, ipwhoBase(), func(m map[string]any) { delete(m, "longitude") })), wantErr: "invalid coordinates"},
		{name: "bad ip", resp: okJSON(mustJSON(t, ipwhoBase(), func(m map[string]any) { m["ip"] = "not-an-ip" })), wantErr: "invalid ip"},
		{name: "private ip", resp: okJSON(mustJSON(t, ipwhoBase(), func(m map[string]any) { m["ip"] = "192.168.1.10" })), wantErr: "invalid ip"},
		{name: "loopback ip", resp: okJSON(mustJSON(t, ipwhoBase(), func(m map[string]any) { m["ip"] = "127.0.0.1" })), wantErr: "invalid ip"},
		{name: "zoned ip", resp: okJSON(mustJSON(t, ipwhoBase(), func(m map[string]any) { m["ip"] = "2001:db8::1%eth0" })), wantErr: "invalid ip"},
		{name: "missing ip", resp: okJSON(mustJSON(t, ipwhoBase(), func(m map[string]any) { delete(m, "ip") })), wantErr: "invalid ip"},
		{name: "lowercase cc", resp: okJSON(mustJSON(t, ipwhoBase(), func(m map[string]any) { m["country_code"] = "gb" })), wantErr: "invalid country code"},
		{name: "3-letter cc", resp: okJSON(mustJSON(t, ipwhoBase(), func(m map[string]any) { m["country_code"] = "GBR" })), wantErr: "invalid country code"},
		{name: "bidi cc", resp: okJSON(mustJSON(t, ipwhoBase(), func(m map[string]any) { m["country_code"] = "G\u202eB" })), wantErr: "invalid country code"},
		{name: "success false", resp: okJSON(mustJSON(t, ipwhoBase(), func(m map[string]any) { m["success"] = false })), wantErr: "ipwho.is: provider error"},
		{name: "wrong status", resp: resp{status: 429, ctype: "application/json", body: mustJSON(t, ipwhoBase(), nil)}, wantErr: "ipwho.is: status 429"},
		{name: "html content type", resp: resp{status: 200, ctype: "text/html", body: mustJSON(t, ipwhoBase(), nil)}, wantErr: "ipwho.is: content-type"},
		{name: "no content type", resp: resp{status: 200, body: mustJSON(t, ipwhoBase(), nil)}, wantErr: "ipwho.is: content-type"},
		{name: "non-JSON body", resp: okJSON("<html><body>hello</body></html>"), wantErr: "ipwho.is: decode"},
		{name: "JSON array", resp: okJSON(`[` + mustJSON(t, ipwhoBase(), nil) + `]`), wantErr: "ipwho.is: decode"},
		{name: "trailing data", resp: okJSON(mustJSON(t, ipwhoBase(), nil) + `{"ip":"198.51.100.1"}`), wantErr: "ipwho.is: decode"},
		{name: "body over 16 KiB", resp: okJSON(mustJSON(t, ipwhoBase(), func(m map[string]any) { m["pad"] = strings.Repeat("x", 17*1024) })), wantErr: "ipwho.is: body too large"},
		{name: "redirect to http", resp: resp{status: 302, location: "http://127.0.0.1:1/ipwho"}, wantErr: "ipwho.is: redirect"},
		{name: "redirect loop", resp: resp{status: 302, location: "self:/ipwho"}, wantErr: "ipwho.is: redirect"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fs := newFakeServer(t, map[string]resp{"/ipwho": c.resp, "/ipinfo": failResp, "/ipapi": failResp})
			useProviders(t, fs.URL)
			res, err := lookup(t, testClient(t, v4Only, fs))
			if c.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if res.Provider != "ipwho.is" || res.PublicIP != netip.MustParseAddr("203.0.113.7") {
					t.Fatalf("result = %+v", res)
				}
				c.check(t, res)
				return
			}
			if err == nil {
				t.Fatalf("expected error, got %+v", res)
			}
			if !strings.Contains(err.Error(), c.wantErr) {
				t.Errorf("error %q does not contain %q", err, c.wantErr)
			}
			if res.Source != "none" || res.PublicIP.IsValid() {
				t.Errorf("failed lookup returned %+v", res)
			}
		})
	}
}

func TestLookupRedirectHTTPSAllowed(t *testing.T) {
	fs := newFakeServer(t, map[string]resp{
		"/ipwho": {status: 301, location: "self:/r1"},
		"/r1":    {status: 302, location: "self:/r2"},
		"/r2":    okJSON(mustJSON(t, ipwhoBase(), nil)),
	})
	useProviders(t, fs.URL)
	res, err := lookup(t, testClient(t, v4Only, fs))
	if err != nil || res.Provider != "ipwho.is" {
		t.Fatalf("two https redirects: %+v, %v", res, err)
	}
	fs.mu.Lock()
	defer fs.mu.Unlock()
	for _, h := range fs.headers {
		if h.Get("User-Agent") != ua {
			t.Errorf("redirected request lost User-Agent: %v", h)
		}
	}
}

func TestLookupAllFailErrorIsMinimal(t *testing.T) {
	secret := "SECRET-MARKER \u202e"
	fs := newFakeServer(t, map[string]resp{
		"/ipwho":  {status: 500, ctype: "text/plain", body: secret},
		"/ipinfo": okJSON(mustJSON(t, ipinfoBase(), func(m map[string]any) { m["loc"] = "NaN,NaN"; m["city"] = secret })),
		"/ipapi":  okJSON(mustJSON(t, ipapiBase(), func(m map[string]any) { m["ip"] = secret })),
	})
	useProviders(t, fs.URL)
	res, err := lookup(t, testClient(t, v4Only, fs))
	if err == nil {
		t.Fatalf("expected error, got %+v", res)
	}
	msg := err.Error()
	for _, bad := range []string{"SECRET", "203.0.113", "127.0.0.1", "\u202e"} {
		if strings.Contains(msg, bad) {
			t.Errorf("error leaks %q: %s", bad, msg)
		}
	}
	for _, want := range []string{"ipwho.is: status 500", "ipinfo.io: invalid coordinates", "ipapi.co: invalid ip"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error %q lacks %q", msg, want)
		}
	}
	if res != (Result{Source: "none"}) {
		t.Errorf("result = %+v", res)
	}
}

func TestLookupIPInfoNaNLoc(t *testing.T) {
	for _, loc := range []string{"NaN,NaN", "Inf,0", "51.5", "a,b", "91,0"} {
		fs := newFakeServer(t, map[string]resp{
			"/ipwho":  failResp,
			"/ipinfo": okJSON(mustJSON(t, ipinfoBase(), func(m map[string]any) { m["loc"] = loc })),
			"/ipapi":  failResp,
		})
		useProviders(t, fs.URL)
		if res, err := lookup(t, testClient(t, v4Only, fs)); err == nil {
			t.Errorf("loc %q accepted: %+v", loc, res)
		}
	}
}

// TestLookupIPv6 checks the second, forced-tcp6 request.
func TestLookupIPv6(t *testing.T) {
	v4 := newFakeServer(t, map[string]resp{"/ipwho": okJSON(mustJSON(t, ipwhoBase(), nil))})
	v6 := newFakeServer(t, map[string]resp{"/ipwho": okJSON(mustJSON(t, ipwhoBase(), func(m map[string]any) {
		m["ip"] = "2001:db8::7"
	}))})
	useProviders(t, v4.URL)
	var mu sync.Mutex
	var networks []string
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		mu.Lock()
		networks = append(networks, network)
		mu.Unlock()
		if network == "tcp6" {
			addr = v6.Listener.Addr().String() // pretend IPv6 reaches the provider's v6 front end
		}
		var d net.Dialer
		return d.DialContext(ctx, "tcp", addr)
	}
	res, err := lookup(t, testClient(t, dial, v4, v6))
	if err != nil {
		t.Fatal(err)
	}
	if res.PublicIP != netip.MustParseAddr("203.0.113.7") || res.PublicIP6 != netip.MustParseAddr("2001:db8::7") {
		t.Errorf("addresses = %v / %v", res.PublicIP, res.PublicIP6)
	}
	mu.Lock()
	if strings.Join(networks, ",") != "tcp,tcp6" {
		t.Errorf("dials = %v", networks)
	}
	mu.Unlock()

	// A v6 answer that is not IPv6 is ignored.
	v6.mu.Lock()
	v6.routes["/ipwho"] = okJSON(mustJSON(t, ipwhoBase(), func(m map[string]any) { m["ip"] = "198.51.100.1" }))
	v6.mu.Unlock()
	res, err = lookup(t, testClient(t, dial, v4, v6))
	if err != nil || res.PublicIP6.IsValid() || res.PublicIP != netip.MustParseAddr("203.0.113.7") {
		t.Errorf("non-v6 second answer: %+v, %v", res, err)
	}

	// A failing v6 request is silent.
	v6.mu.Lock()
	v6.routes["/ipwho"] = resp{status: 500}
	v6.mu.Unlock()
	res, err = lookup(t, testClient(t, dial, v4, v6))
	if err != nil || res.PublicIP6.IsValid() || res.Provider != "ipwho.is" {
		t.Errorf("failed v6 request: %+v, %v", res, err)
	}
}

// TestLookupPrimaryV6 covers a first answer over IPv6: the extra request is
// then forced to tcp4.
func TestLookupPrimaryV6(t *testing.T) {
	v4 := newFakeServer(t, map[string]resp{"/ipwho": okJSON(mustJSON(t, ipwhoBase(), nil))})
	v6 := newFakeServer(t, map[string]resp{"/ipwho": okJSON(mustJSON(t, ipwhoBase(), func(m map[string]any) {
		m["ip"] = "2001:db8::7"
	}))})
	useProviders(t, v6.URL)
	var mu sync.Mutex
	var forced []string
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		if network == "tcp4" {
			mu.Lock()
			forced = append(forced, network)
			mu.Unlock()
			addr = v4.Listener.Addr().String()
		}
		var d net.Dialer
		return d.DialContext(ctx, "tcp", addr)
	}
	res, err := lookup(t, testClient(t, dial, v4, v6))
	if err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if res.PublicIP != netip.MustParseAddr("203.0.113.7") || res.PublicIP6 != netip.MustParseAddr("2001:db8::7") || len(forced) != 1 {
		t.Errorf("addresses = %v / %v, forced = %v", res.PublicIP, res.PublicIP6, forced)
	}
}

func TestLookupCanceled(t *testing.T) {
	fs := newFakeServer(t, map[string]resp{"/ipwho": okJSON(mustJSON(t, ipwhoBase(), nil))})
	useProviders(t, fs.URL)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res, err := Lookup(ctx, testClient(t, v4Only, fs), ua)
	if err == nil || !errors.Is(err, context.Canceled) || res.Source != "none" {
		t.Fatalf("canceled lookup: %+v, %v", res, err)
	}
	if fs.hitCount("/ipwho") != 0 {
		t.Error("request sent despite canceled context")
	}
}

func TestLookupSlowProviderTimesOut(t *testing.T) {
	block := make(chan struct{})
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-block:
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()
	defer close(block)
	useProviders(t, srv.URL)
	c := NewHTTPClient(v4Only)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	c.Transport.(*http.Transport).TLSClientConfig.RootCAs = pool
	c.Timeout = 100 * time.Millisecond
	start := time.Now()
	_, err := Lookup(context.Background(), c, ua)
	if err == nil || !strings.Contains(err.Error(), "ipwho.is: timeout") {
		t.Fatalf("err = %v", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Errorf("took %v", time.Since(start))
	}
}

func TestNewHTTPClient(t *testing.T) {
	c := NewHTTPClient(nil)
	if c.Timeout != 6*time.Second {
		t.Errorf("Timeout = %v", c.Timeout)
	}
	tr, ok := c.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport %T", c.Transport)
	}
	if tr.Proxy != nil || !tr.DisableKeepAlives || !tr.DisableCompression || tr.DialContext == nil {
		t.Errorf("transport = %+v", tr)
	}
	if tr.TLSClientConfig == nil || tr.TLSClientConfig.MinVersion < 0x0303 || tr.TLSClientConfig.InsecureSkipVerify ||
		tr.TLSClientConfig.RootCAs != nil {
		t.Errorf("tls config = %+v", tr.TLSClientConfig)
	}
	req := func(raw string) *http.Request {
		u, _ := url.Parse(raw)
		return &http.Request{URL: u}
	}
	via := func(n int) []*http.Request { return make([]*http.Request, n) }
	if err := c.CheckRedirect(req("https://a/"), via(1)); err != nil {
		t.Errorf("1st https redirect: %v", err)
	}
	if err := c.CheckRedirect(req("https://a/"), via(2)); err != nil {
		t.Errorf("2nd https redirect: %v", err)
	}
	if err := c.CheckRedirect(req("https://a/"), via(3)); err == nil {
		t.Error("3rd redirect allowed")
	}
	if err := c.CheckRedirect(req("http://a/"), via(1)); err == nil {
		t.Error("http redirect allowed")
	}
}

func TestNewHTTPClientUsesDialer(t *testing.T) {
	fs := newFakeServer(t, map[string]resp{"/ipwho": okJSON(mustJSON(t, ipwhoBase(), nil))})
	useProviders(t, "https://geo.invalid") // resolvable only through the custom dialer
	var calls int
	var mu sync.Mutex
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		mu.Lock()
		calls++
		mu.Unlock()
		if network == "tcp6" {
			return nil, errors.New("no v6")
		}
		var d net.Dialer
		return d.DialContext(ctx, "tcp", fs.Listener.Addr().String())
	}
	c := testClient(t, dial, fs)
	c.Transport.(*http.Transport).TLSClientConfig.ServerName = "example.com" // in the httptest cert
	res, err := lookup(t, c)
	if err != nil || res.Provider != "ipwho.is" {
		t.Fatalf("%+v, %v", res, err)
	}
	mu.Lock()
	defer mu.Unlock()
	if calls != 2 {
		t.Errorf("dialer calls = %d, want 2 (primary + v6)", calls)
	}
}
