package gateway

import (
	"time"

	"github.com/cyberkyd01/privatevpn/core/gwstack"
)

// Limits (ARCHITECTURE §8.7) and lease timing (§8.2).
const (
	leaseLifetime    = 120 * time.Second
	sweepInterval    = 5 * time.Second
	endpointInterval = time.Second // learned-endpoint poll, only with an EndpointHook

	poolSize = 253 // .2–.254

	// Global caps are below §8.7's 8192/4096: with ~0.6 MiB of buffers per
	// stalled TCP flow and 128 KiB per UDP flow they bound the worst case
	// (one member holding every lease) at roughly 1.3 GiB instead of
	// several GiB. A personal gateway never approaches them legitimately.
	tcpFlowsPerClient = 1024
	tcpFlowsGlobal    = 2048
	udpFlowsPerClient = 512
	udpFlowsGlobal    = 1024
	tcpBufferSize     = 256 << 10 // gVisor send and receive buffer per TCP flow, fixed
	newFlowRate       = 200       // per second per client
	newFlowBurst      = 400
	tcpMaxInFlight    = 256
	tcpDialTimeout    = 10 * time.Second
	tcpIdle           = 30 * time.Minute
	udpIdle           = 60 * time.Second
	dnsIdle           = 10 * time.Second
	dnsRate           = 50 // queries per second per client
	dnsBurst          = 100
	dnsTimeout        = 5 * time.Second
	dnsInFlight       = 64 // concurrent upstream queries per client

	defaultMTU        = 1280
	minMTU            = 576
	defaultListenPort = 51820
)

func stackLimits() gwstack.Limits {
	return gwstack.Limits{
		TCPPerClient:   tcpFlowsPerClient,
		TCPGlobal:      tcpFlowsGlobal,
		UDPPerClient:   udpFlowsPerClient,
		UDPGlobal:      udpFlowsGlobal,
		FlowRate:       newFlowRate,
		FlowBurst:      newFlowBurst,
		TCPMaxInFlight: tcpMaxInFlight,
		TCPDialTimeout: tcpDialTimeout,
		TCPIdle:        tcpIdle,
		UDPIdle:        udpIdle,
		DNSIdle:        dnsIdle,
		DNSRate:        dnsRate,
		DNSBurst:       dnsBurst,
		DNSTimeout:     dnsTimeout,
		DNSInFlight:    dnsInFlight,
		TCPBufferSize:  tcpBufferSize,
	}
}
