//go:build !android

package mobile

import "github.com/cyberkyd01/privatevpn/core/tunnel"

// newTunnel: the facade only runs on Android; on other GOOS values the
// package still compiles (go vet ./..., host builds) but has no tunnel, so
// client.connect reports "unsupported".
func newTunnel(Callbacks) func() (tunnel.Tunnel, error) { return nil }
