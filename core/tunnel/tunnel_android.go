//go:build android

package tunnel

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"sync"

	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/tun"

	"github.com/cyberkyd01/private-vpn-pro/core/eventlog"
)

// Android client tunnel (§9.5). Kotlin's VpnService.Builder creates the
// interface (address, routes incl. the ::/0 sink, DNS, MTU, and
// addDisallowedApplication so our own sockets bypass the VPN) and hands Go
// a detached fd. Routes are Kotlin's business: RouteAdd/RouteDel are no-ops.
//
// Fail-closed on Android is the VPN interface itself: while it exists and
// WireGuard has no session, packets are dropped (plus the system's own
// "Block connections without VPN"). So Up establishes the new interface
// before the old one goes (Builder.establish replaces it atomically), Close
// keeps the interface (a failed session stays blocked), and only Down
// releases the VpnService — always, even from a fresh Tunnel.

// IsElevated is always false on Android: there is no elevation; the tunnel
// is created with NewAndroid.
func IsElevated() bool { return false }

type androidTunnel struct {
	mu        sync.Mutex
	establish func(cfgJSON string) (int, error)
	closeTun  func()
	log       *eventlog.Log
	wg        *wgDevice
	ifname    string
	closed    bool
}

// NewAndroid returns the Android tunnel. establish is Kotlin's
// Callbacks.establishTun: it receives the §9.1 config JSON (with the private
// and preshared keys zeroed — Kotlin needs only address, DNS and MTU) and
// returns a detached TUN fd that Go then owns. closeTun lets Kotlin release
// its VpnService session; Down calls it after closing the fd.
func NewAndroid(establish func(cfgJSON string) (fd int, err error), closeTun func(), log *eventlog.Log) Tunnel {
	return &androidTunnel{establish: establish, closeTun: closeTun, log: logOrDefault(log)}
}

func (t *androidTunnel) Up(cfg Config) (string, error) {
	if err := cfg.Validate(); err != nil {
		return "", err
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return "", errClosed
	}

	forKotlin := cfg
	forKotlin.PrivateKey = [32]byte{}
	forKotlin.Peer.PresharedKey = [32]byte{}
	js, err := json.Marshal(forKotlin)
	if err != nil {
		return "", err
	}
	// The previous interface (if any) stays up until the new one exists:
	// a rebuild never leaves a moment without a VPN interface, and a
	// refused establish keeps the old tunnel.
	old := t.wg
	fd, err := t.establish(string(js))
	if err != nil {
		return "", fmt.Errorf("tunnel: VpnService refused to establish: %w", err)
	}
	if fd < 0 {
		return "", errors.New("tunnel: VpnService returned no interface")
	}
	// From here on the system has replaced the old interface with the new
	// one; the old device is closed below whatever happens.
	defer func() {
		if old != nil {
			old.close()
		}
	}()
	// wireguard-go's CreateUnmonitoredTUNFromFD sets the fd non-blocking
	// first and returns before wrapping it when that fails — the fd would
	// leak and the VPN interface outlive the service. Do that step here so
	// its failure is ours to clean up; once wireguard-go has wrapped the fd
	// in an *os.File (every later failure) its finalizer owns it and a
	// second close could hit an unrelated, reused descriptor.
	if err := unix.SetNonblock(fd, true); err != nil {
		unix.Close(fd)
		t.wg, t.ifname = nil, ""
		t.callCloseTun()
		return "", fmt.Errorf("tunnel: TUN fd: %w", err)
	}
	tdev, name, err := tun.CreateUnmonitoredTUNFromFD(fd)
	if err != nil {
		t.wg, t.ifname = nil, ""
		t.callCloseTun()
		return "", fmt.Errorf("tunnel: TUN fd: %w", err)
	}
	wg, err := startDevice(tdev, cfg, 0, t.log)
	if err != nil {
		t.wg, t.ifname = nil, ""
		t.callCloseTun()
		return "", err
	}
	t.wg, t.ifname = wg, name
	t.log.Printf("tunnel", "up on %s, address %s, mtu %d", name, cfg.Address, cfg.MTU)
	return name, nil
}

func (t *androidTunnel) callCloseTun() {
	if t.closeTun != nil {
		t.closeTun()
	}
}

func (t *androidTunnel) SetEndpoint(ep netip.AddrPort) error {
	if err := CheckEndpoint(ep); err != nil {
		return err
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.wg == nil {
		return errNotUp
	}
	return t.wg.setEndpoint(ep)
}

// Status never reports warnings on Android: the OS owns routes, DNS and
// the IPv6 sink, and the kill switch is the system's.
func (t *androidTunnel) Status() (Status, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.wg == nil {
		return Status{HandshakeAgeSec: -1}, errNotUp
	}
	st, err := t.wg.status()
	st.IfName = t.ifname
	st.Warnings = nil
	return st, err
}

// RouteAdd is a no-op on Android (the app is excluded from the VPN).
func (t *androidTunnel) RouteAdd(dst netip.Addr) error { return CheckPublicIPv4(dst) }

// RouteDel is a no-op on Android.
func (t *androidTunnel) RouteDel(dst netip.Addr) error { return CheckPublicIPv4(dst) }

// Down closes the device (if this instance has one) and always releases
// the VpnService, so a fresh Tunnel created after a lost session can take
// the interface down. Idempotent.
func (t *androidTunnel) Down() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.wg != nil {
		t.wg.close() // closes the TUN fd
		t.wg, t.ifname = nil, ""
		t.log.Printf("tunnel", "down")
	}
	t.callCloseTun()
	return nil
}

// Close releases this instance but keeps the VPN interface: a session that
// ends without an explicit Down stays blocked. The orphaned device shuts
// itself down once the interface is revoked (Down from a fresh Tunnel).
func (t *androidTunnel) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.closed = true
	return nil
}
