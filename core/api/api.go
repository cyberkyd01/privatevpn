// Package api holds the transport-agnostic method names, error type and
// event types shared by the desktop HTTP API and mobile.Call (ARCHITECTURE §14).
package api

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// Method names (§14.1, "Core method" column).
const (
	StatusGet         = "status.get"
	KeyringList       = "keyring.list"
	KeyringAdd        = "keyring.add"
	KeyringCreate     = "keyring.create"
	KeyringRename     = "keyring.rename"
	KeyringRemove     = "keyring.remove"
	KeyringReveal     = "keyring.reveal"
	GatewaySetNetwork = "gateway.set_network"
	GatewayResetKey   = "gateway.reset_key"
	GatewayEnable     = "gateway.enable"
	GatewayDisable    = "gateway.disable"
	GatewaysList      = "gateways.list"
	GatewaysUnlock    = "gateways.unlock"
	GatewaysManualAdd = "gateways.manual_add"
	GatewaysManualRm  = "gateways.manual_remove"
	GatewaysInfo      = "gateways.info"
	ClientConnect     = "client.connect"
	ClientDisconnect  = "client.disconnect"
	ClientSelftest    = "client.selftest"
	SettingsGet       = "settings.get"
	SettingsSet       = "settings.set"
	FirewallAdd       = "firewall.add"
	LogGet            = "log.get"
	AppQuit           = "app.quit"
	SysNetworkChanged = "sys.network_changed"
)

// Error codes used across methods.
const (
	CodeBadRequest  = "bad_request"
	CodeUnsupported = "unsupported"
	CodeNotFound    = "not_found"
	CodeLocked      = "locked"
	CodeKeyFormat   = "key_format"
	CodeKeyMismatch = "key_mismatch"
	CodeUnreachable = "unreachable"
	CodeKeyringFull = "keyring_full"
	CodeInUse       = "in_use"
	CodeConflict    = "conflict"
	CodeElevation   = "elevation_needed"
	CodeClockSkew   = "clock_skew"
	CodeTimeout     = "timeout"
	CodeInternal    = "internal"
)

// Error is a method error. HTTP is the status code the desktop API uses.
type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	HTTP    int    `json:"-"`
}

func (e *Error) Error() string { return e.Code + ": " + e.Message }

// JSON returns the {"code","message"} document.
func (e *Error) JSON() []byte {
	b, _ := json.Marshal(e)
	return b
}

// Errf builds an Error with an HTTP status.
func Errf(code string, status int, format string, args ...any) *Error {
	return &Error{Code: code, Message: fmt.Sprintf(format, args...), HTTP: status}
}

// Common constructors.
func BadRequest(format string, args ...any) *Error {
	return Errf(CodeBadRequest, http.StatusBadRequest, format, args...)
}

func Unsupported() *Error {
	return Errf(CodeUnsupported, http.StatusBadRequest, "not supported on this device")
}

func NotFound(what string) *Error {
	return Errf(CodeNotFound, http.StatusNotFound, "%s not found", what)
}

func Internal(err error) *Error {
	return Errf(CodeInternal, http.StatusInternalServerError, "%v", err)
}

// Event types (§14.3).
const (
	EventStatus          = "status"
	EventGateways        = "gateways"
	EventKeyring         = "keyring"
	EventLog             = "log"
	EventError           = "error"
	EventElevationNeeded = "elevation_needed"
)
