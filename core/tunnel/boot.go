//go:build windows || darwin || (linux && !android)

package tunnel

import (
	"github.com/cyberkyd01/privatevpn/core/eventlog"
)

// Unblock is `privatevpn unblock` (elevated): removes a kill-switch block
// left by an earlier session together with its boot-time pieces, tunnel
// leftovers, host routes and DNS changes. It is the manual recovery when
// the app cannot do it (deleted app, broken helper).
func Unblock(log *eventlog.Log) error {
	t, err := NewNative(log)
	if err != nil {
		return err
	}
	if err := t.Down(); err != nil {
		_ = t.Close()
		return err
	}
	return t.Close()
}

// KillSwitchBoot is `privatevpn killswitch-boot`, run at boot by the
// LaunchDaemon (macOS) / systemd unit (Linux) installed while the kill
// switch was engaged: it re-installs the block from the persisted record.
// On Windows the WFP objects themselves persist and this is a no-op.
func KillSwitchBoot(log *eventlog.Log) error {
	if !IsElevated() {
		return ErrNotElevated
	}
	return bootBlock(logOrDefault(log))
}
