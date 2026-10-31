package geo

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"time"
)

const (
	clientTimeout = 6 * time.Second
	maxRedirects  = 2
	maxHeaderSize = 16 << 10
)

var (
	errTooManyRedirects = errors.New("too many redirects")
	errInsecureRedirect = errors.New("redirect to non-https URL")
)

// familyKey is the context key that forces the address family of the next
// dial ("tcp4" or "tcp6") on a client made by NewHTTPClient.
type familyKey struct{}

func withFamily(ctx context.Context, network string) context.Context {
	return context.WithValue(ctx, familyKey{}, network)
}

// NewHTTPClient returns the GeoIP HTTP client of §10.2: no proxy, no
// keep-alives, no transparent compression (so the request carries no
// Accept-Encoding), TLS ≥ 1.2 with system roots, a 6 s overall timeout and
// at most 2 redirects, https only. dial (nil = net.Dialer) is used for every
// connection; the engine passes netbind's physical-interface dialer (§7.4).
func NewHTTPClient(dial func(ctx context.Context, network, addr string) (net.Conn, error)) *http.Client {
	if dial == nil {
		d := &net.Dialer{Timeout: clientTimeout}
		dial = d.DialContext
	}
	tr := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if f, ok := ctx.Value(familyKey{}).(string); ok && network == "tcp" {
				network = f
			}
			return dial(ctx, network, addr)
		},
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout:    clientTimeout,
		ResponseHeaderTimeout:  clientTimeout,
		DisableKeepAlives:      true,
		DisableCompression:     true,
		MaxResponseHeaderBytes: maxHeaderSize,
	}
	return &http.Client{
		Transport:     tr,
		Timeout:       clientTimeout,
		CheckRedirect: checkRedirect,
	}
}

func checkRedirect(req *http.Request, via []*http.Request) error {
	if len(via) > maxRedirects {
		return errTooManyRedirects
	}
	if req.URL.Scheme != "https" {
		return errInsecureRedirect
	}
	return nil
}
