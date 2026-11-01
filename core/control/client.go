package control

import (
	"context"
	"crypto/cipher"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/cyberkyd01/private-vpn-pro/core/wire"
)

// ErrTimeout means the gateway did not answer (wrong key, firewall, offline
// or clock skew — the protocol cannot tell these apart by design).
var ErrTimeout = errors.New("control: no answer from gateway")

// RemoteError is an authenticated ERROR from the gateway.
type RemoteError struct{ Code wire.ErrCode }

func (e *RemoteError) Error() string { return "gateway: " + e.Code.String() }

// Retry schedules (wait after each send).
var (
	joinSchedule  = []time.Duration{1 * time.Second, 1 * time.Second, 2 * time.Second, 2 * time.Second}
	renewSchedule = []time.Duration{1500 * time.Millisecond, 1500 * time.Millisecond}
	infoSchedule  = []time.Duration{1 * time.Second, 2 * time.Second}
)

// Client sends control requests under one network's control key.
type Client struct {
	aead cipher.AEAD
	// ListenConfig is optional (socket options for the ephemeral socket).
	ListenConfig *net.ListenConfig
	now          func() time.Time
}

// NewClient returns a requester for the network whose K_ctrl is key.
func NewClient(key [32]byte) *Client {
	return &Client{aead: wire.NewAEAD(key), now: time.Now}
}

// Join requests a lease for clientPub (§6.3, §6.4).
func (c *Client) Join(ctx context.Context, gw netip.AddrPort, clientPub [32]byte, mtuHint int) (wire.JoinResp, error) {
	var out wire.JoinResp
	pt, err := c.exchange(ctx, gw, wire.TypeJoinReq, wire.TypeJoinResp, joinSchedule, func(ts uint64) []byte {
		return wire.JoinReq{ClientPub: clientPub, TS: ts, MTUHint: uint16(mtuHint)}.Marshal()
	})
	if err != nil {
		return out, err
	}
	out, err = wire.ParseJoinResp(pt)
	if err != nil {
		return out, err
	}
	return out, ValidateJoinResp(out)
}

// ValidateJoinResp applies the client-side checks of §6.4.
func ValidateJoinResp(r wire.JoinResp) error {
	switch {
	case r.Status != 0:
		return fmt.Errorf("join refused (status %d)", r.Status)
	case r.PrefixLen != 24:
		return errors.New("join: unexpected prefix length")
	case !r.Assigned.Is4() || !r.GatewayIP.Is4() || r.Assigned == r.GatewayIP:
		return errors.New("join: invalid addresses")
	case netip.PrefixFrom(r.Assigned, 24).Masked() != netip.PrefixFrom(r.GatewayIP, 24).Masked():
		return errors.New("join: addresses not in one /24")
	case !r.Assigned.IsPrivate():
		return errors.New("join: tunnel address is not private")
	case r.GatewayPub == [32]byte{}:
		return errors.New("join: missing gateway key")
	case r.MTU < 576 || r.MTU > 1420:
		return errors.New("join: MTU out of range")
	case r.LeaseSec < 30 || r.LeaseSec > 3600:
		return errors.New("join: lease length out of range")
	case r.WGPort == 0:
		return errors.New("join: missing WireGuard port")
	case r.Keepalive > 600:
		return errors.New("join: keepalive out of range")
	}
	return nil
}

// Renew refreshes a lease (§6.5).
func (c *Client) Renew(ctx context.Context, gw netip.AddrPort, clientPub [32]byte, token [16]byte) (wire.RenewResp, error) {
	pt, err := c.exchange(ctx, gw, wire.TypeRenewReq, wire.TypeRenewResp, renewSchedule, func(ts uint64) []byte {
		return wire.LeaseReq{ClientPub: clientPub, TS: ts, LeaseToken: token}.Marshal()
	})
	if err != nil {
		return wire.RenewResp{}, err
	}
	return wire.ParseRenewResp(pt)
}

// Leave releases a lease; best effort, no answer is expected.
func (c *Client) Leave(gw netip.AddrPort, clientPub [32]byte, token [16]byte) error {
	conn, err := c.listen(context.Background())
	if err != nil {
		return err
	}
	defer conn.Close()
	pt := wire.LeaseReq{ClientPub: clientPub, TS: uint64(c.now().Unix()), LeaseToken: token}.Marshal()
	d, _, err := wire.Seal(c.aead, wire.TypeLeave, pt, nil)
	if err != nil {
		return err
	}
	_, err = conn.WriteToUDPAddrPort(d, gw)
	return err
}

// Info fetches the gateway's details JSON (§6.6). The JSON is untrusted.
func (c *Client) Info(ctx context.Context, gw netip.AddrPort) ([]byte, error) {
	pt, err := c.exchange(ctx, gw, wire.TypeInfoReq, wire.TypeInfoResp, infoSchedule, func(ts uint64) []byte {
		return wire.InfoReq{TS: ts}.Marshal()
	})
	if err != nil {
		return nil, err
	}
	r, err := wire.ParseInfoResp(pt)
	if err != nil {
		return nil, err
	}
	return r.JSON, nil
}

func (c *Client) listen(ctx context.Context) (*net.UDPConn, error) {
	lc := c.ListenConfig
	if lc == nil {
		lc = &net.ListenConfig{}
	}
	pc, err := lc.ListenPacket(ctx, "udp4", "0.0.0.0:0")
	if err != nil {
		return nil, err
	}
	return pc.(*net.UDPConn), nil
}

// exchange sends a request (fresh nonce and timestamp per attempt) and waits
// for an authenticated answer to any attempt, following schedule.
func (c *Client) exchange(ctx context.Context, gw netip.AddrPort, reqT, respT wire.Type, schedule []time.Duration, body func(ts uint64) []byte) ([]byte, error) {
	if !gw.IsValid() || gw.Port() == 0 {
		return nil, errors.New("control: invalid gateway address")
	}
	gw = netip.AddrPortFrom(gw.Addr().Unmap(), gw.Port())
	conn, err := c.listen(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.SetReadDeadline(time.Now()) })
	defer stop()

	var sent []wire.Nonce
	buf := make([]byte, 1500)
	for _, wait := range schedule {
		d, n, err := wire.Seal(c.aead, reqT, body(uint64(c.now().Unix())), nil)
		if err != nil {
			return nil, err
		}
		sent = append(sent, n)
		if _, err := conn.WriteToUDPAddrPort(d, gw); err != nil {
			return nil, err
		}
		deadline := time.Now().Add(wait)
		conn.SetReadDeadline(deadline)
		for {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			m, from, err := conn.ReadFromUDPAddrPort(buf)
			if err != nil {
				var ne net.Error
				if errors.As(err, &ne) && ne.Timeout() {
					break
				}
				if ctx.Err() != nil {
					return nil, ctx.Err()
				}
				// ICMP unreachable surfaces as a read error on some OSes; keep waiting.
				if time.Now().After(deadline) {
					break
				}
				continue
			}
			if from.Addr().Unmap() != gw.Addr() || from.Port() != gw.Port() {
				continue
			}
			t, ok := wire.PreCheck(buf[:m])
			if !ok || (t != respT && t != wire.TypeError) {
				continue
			}
			for i := range sent {
				_, _, pt, err := wire.Open(c.aead, buf[:m], &sent[i])
				if err != nil {
					continue
				}
				if t == wire.TypeError {
					em, err := wire.ParseErrorMsg(pt)
					if err != nil {
						break
					}
					return nil, &RemoteError{Code: em.Code}
				}
				return pt, nil
			}
		}
	}
	return nil, ErrTimeout
}
