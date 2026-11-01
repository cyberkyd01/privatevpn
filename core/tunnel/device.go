//go:build windows || darwin || linux

package tunnel

import (
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"

	"github.com/cyberkyd01/private-vpn-pro/core/eventlog"
)

// wgDevice is the client WireGuard device shared by every native tunnel.
type wgDevice struct {
	dev  *device.Device
	peer [32]byte
}

// newBind is replaced in tests by an in-memory bind.
var newBind = conn.NewDefaultBind

// startDevice creates the WireGuard device on tdev, configures it from c via
// UAPI and brings it up. On failure tdev has been closed.
func startDevice(tdev tun.Device, c Config, fwmark uint32, log *eventlog.Log) (*wgDevice, error) {
	dev := device.NewDevice(tdev, newBind(), newWGLogger(log))
	// IpcSet errors can quote the offending value (an endpoint): never
	// pass them on.
	if err := dev.IpcSet(uapiConfig(c, fwmark)); err != nil {
		dev.Close()
		return nil, errors.New("wireguard: configuration rejected")
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, errors.New("wireguard: device failed to start")
	}
	return &wgDevice{dev: dev, peer: c.Peer.PublicKey}, nil
}

func (w *wgDevice) setEndpoint(ep netip.AddrPort) error {
	if err := w.dev.IpcSet(uapiEndpoint(w.peer, ep)); err != nil {
		return errors.New("wireguard: endpoint update rejected")
	}
	return nil
}

func (w *wgDevice) status() (Status, error) {
	s, err := w.dev.IpcGet()
	if err != nil {
		return Status{HandshakeAgeSec: -1}, errors.New("wireguard: status unavailable")
	}
	return parseUAPIStatus(s, w.peer, time.Now()), nil
}

// close stops the device; this also closes the TUN.
func (w *wgDevice) close() { w.dev.Close() }

// newWGLogger routes wireguard-go errors into the event log with peer tags
// and addresses stripped (§12.1 rule 3). Verbose output is discarded, and a
// repeated message is logged at most once a minute.
func newWGLogger(log *eventlog.Log) *device.Logger {
	var mu sync.Mutex
	var last string
	var lastAt time.Time
	return &device.Logger{
		Verbosef: device.DiscardLogf,
		Errorf: func(format string, args ...any) {
			msg := Redact(fmt.Sprintf(format, args...))
			mu.Lock()
			if msg == last && time.Since(lastAt) < time.Minute {
				mu.Unlock()
				return
			}
			last, lastAt = msg, time.Now()
			mu.Unlock()
			log.Printf("wireguard", "%s", msg)
		},
	}
}

func logOrDefault(l *eventlog.Log) *eventlog.Log {
	if l == nil {
		return eventlog.Default
	}
	return l
}
