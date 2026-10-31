//go:build !android && !windows

package web

import (
	"net"
	"strconv"
)

// listenLoopback binds 127.0.0.1:port over IPv4 only.
func listenLoopback(port int) (net.Listener, error) {
	return net.Listen("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
}
