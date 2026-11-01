package geo

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

const (
	maxBody          = 16 << 10
	defaultUserAgent = "PrivateVPNPro"
	capUserAgent     = 64
)

var (
	errContentType   = errors.New("content-type")
	errTooLarge      = errors.New("body too large")
	errInvalidIP     = errors.New("invalid ip")
	errInvalidCC     = errors.New("invalid country code")
	errInvalidCoords = errors.New("invalid coordinates")
)

type statusError int

func (e statusError) Error() string { return "status " + strconv.Itoa(int(e)) }

// providerError describes one provider's failure by class only: its text
// never echoes response content or addresses.
type providerError struct {
	provider string
	class    string
	err      error
}

func (e *providerError) Error() string { return e.provider + ": " + e.class }
func (e *providerError) Unwrap() error { return e.err }

// lookupError is returned when every provider failed.
type lookupError struct{ errs []error }

func (e *lookupError) Error() string { return "geo: all providers failed (" + e.classes() + ")" }

func (e *lookupError) Unwrap() []error { return e.errs }

// Lookup queries the providers in order (ipwho.is → ipinfo.io → ipapi.co,
// §10.2); the first valid response wins. It then makes one extra request to
// the same provider over the other address family (forced tcp6 after an
// IPv4 answer, tcp4 after an IPv6 one) to learn the second public address;
// failure of that request is silent. c == nil means NewHTTPClient(nil);
// forcing the family requires a client made by NewHTTPClient.
//
// On failure the Result has Source "none" and the error names each
// provider with a failure class only.
func Lookup(ctx context.Context, c *http.Client, userAgent string) (Result, error) {
	if c == nil {
		c = NewHTTPClient(nil)
	}
	userAgent = Sanitize(userAgent, capUserAgent)
	if userAgent == "" {
		userAgent = defaultUserAgent
	}
	var errs []error
	for _, p := range providers {
		if err := ctx.Err(); err != nil {
			errs = append(errs, &providerError{provider: p.name, class: classify(err), err: err})
			break
		}
		res, err := lookupOne(ctx, c, userAgent, p)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if res.PublicIP.IsValid() {
			if r2, err := lookupOne(withFamily(ctx, "tcp6"), c, userAgent, p); err == nil && r2.PublicIP6.IsValid() {
				res.PublicIP6 = r2.PublicIP6
			}
		} else {
			if r2, err := lookupOne(withFamily(ctx, "tcp4"), c, userAgent, p); err == nil && r2.PublicIP.IsValid() {
				res.PublicIP = r2.PublicIP
			}
		}
		return res, nil
	}
	return Result{Source: sourceNone}, &lookupError{errs: errs}
}

func lookupOne(ctx context.Context, c *http.Client, ua string, p provider) (Result, error) {
	body, err := fetch(ctx, c, ua, p.url)
	if err != nil {
		return Result{}, &providerError{provider: p.name, class: classify(err), err: err}
	}
	r, err := p.parse(body)
	if err != nil {
		class := "decode"
		if errors.Is(err, errProviderError) {
			class = "provider error"
		}
		return Result{}, &providerError{provider: p.name, class: class, err: err}
	}
	res, err := validate(p.name, r)
	if err != nil {
		return Result{}, &providerError{provider: p.name, class: err.Error(), err: err}
	}
	return res, nil
}

// fetch performs the bare GET (only User-Agent is set) and returns the body
// of a 200 JSON response of at most 16 KiB.
func fetch(ctx context.Context, c *http.Client, ua, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header = http.Header{"User-Agent": []string{ua}}
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, statusError(resp.StatusCode)
	}
	if !isJSON(resp.Header.Get("Content-Type")) {
		return nil, errContentType
	}
	if resp.ContentLength > maxBody {
		return nil, errTooLarge
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxBody {
		return nil, errTooLarge
	}
	return body, nil
}

func isJSON(contentType string) bool {
	mt, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return false
	}
	return mt == "application/json" || strings.HasSuffix(mt, "+json")
}

// classify maps a transport/fetch error to a short class for logs.
func classify(err error) string {
	var se statusError
	var ne net.Error
	var dnsErr *net.DNSError
	var certErr *tls.CertificateVerificationError
	var alert tls.AlertError
	var rhe tls.RecordHeaderError
	switch {
	case errors.As(err, &se):
		return se.Error()
	case errors.Is(err, errContentType), errors.Is(err, errTooLarge):
		return err.Error()
	case errors.Is(err, errTooManyRedirects), errors.Is(err, errInsecureRedirect):
		return "redirect"
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &ne) && ne.Timeout():
		return "timeout"
	case errors.As(err, &certErr), errors.As(err, &alert), errors.As(err, &rhe):
		return "tls"
	case errors.As(err, &dnsErr):
		return "dns"
	}
	return "network"
}

// validate applies §10.2: the IP must parse (global unicast, not private),
// coordinates must be finite and in range, the country code must match
// ^[A-Z]{2}$; strings are sanitised and capped (§10.5). Optional fields that
// fail their format (ASN, tz name, offset) are dropped.
func validate(name string, r raw) (Result, error) {
	ip, err := netip.ParseAddr(strings.TrimSpace(r.IP))
	if err != nil {
		return Result{}, errInvalidIP
	}
	ip = ip.Unmap()
	if ip.Zone() != "" || !ip.IsGlobalUnicast() || ip.IsPrivate() {
		return Result{}, errInvalidIP
	}
	cc := strings.TrimSpace(r.CountryCode)
	if cc != "" && !reCountryCode.MatchString(cc) {
		return Result{}, errInvalidCC
	}
	res := Result{
		Source:      sourceGeoIP,
		Provider:    Sanitize(name, capProvider),
		Country:     Sanitize(r.Country, capString),
		CountryCode: cc,
		Region:      Sanitize(r.Region, capString),
		City:        Sanitize(r.City, capString),
		AccuracyKm:  geoipAccuracyKm,
		ISP:         Sanitize(r.ISP, capString),
		ASN:         normalizeASN(r.ASN),
		CheckedAt:   time.Now(),
	}
	if ip.Is4() {
		res.PublicIP = ip
	} else {
		res.PublicIP6 = ip
	}
	switch {
	case r.Lat == nil && r.Lon == nil:
	case r.Lat == nil || r.Lon == nil || !validCoords(*r.Lat, *r.Lon):
		return Result{}, errInvalidCoords
	default:
		res.Lat, res.Lon, res.HasCoords = *r.Lat, *r.Lon, true
	}
	if tz := strings.TrimSpace(r.TZName); validTZName(tz) {
		res.TZName = tz
	}
	if off, ok := parseUTCOffset(r.UTCOffset); ok {
		res.UTCOffsetSec, res.HasOffset = off, true
	} else if r.OffsetSec != nil && *r.OffsetSec >= -maxOffsetSec && *r.OffsetSec <= maxOffsetSec {
		res.UTCOffsetSec, res.HasOffset = int(*r.OffsetSec), true
	}
	return res, nil
}
