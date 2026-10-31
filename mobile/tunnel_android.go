//go:build android

package mobile

import (
	"github.com/cyberkyd01/privatevpn/core/eventlog"
	"github.com/cyberkyd01/privatevpn/core/tunnel"
)

// newTunnel wires the VpnService-backed tunnel (§9.5): Go asks Kotlin for
// the TUN fd through EstablishTun and tells it to stop the service through
// CloseTun.
func newTunnel(cb Callbacks) func() (tunnel.Tunnel, error) {
	return func() (tunnel.Tunnel, error) {
		return tunnel.NewAndroid(cb.EstablishTun, cb.CloseTun, eventlog.Default), nil
	}
}
