package gwstack

import (
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

// gVisor's TCP buffers must stay fixed and small: with its 1 MiB → 4 MiB
// auto-tuned defaults a member holding stalled flows could exhaust memory.
func TestTCPBuffersBounded(t *testing.T) {
	up := newFakeUpstream(t, false)
	h := newHarness(t, testLimits(), up.addr())
	var rcv tcpip.TCPReceiveBufferSizeRangeOption
	var snd tcpip.TCPSendBufferSizeRangeOption
	var moderate tcpip.TCPModerateReceiveBufferOption
	for _, opt := range []tcpip.GettableTransportProtocolOption{&rcv, &snd, &moderate} {
		if err := h.d.stack.TransportProtocolOption(tcp.ProtocolNumber, opt); err != nil {
			t.Fatal(err)
		}
	}
	if rcv.Default != defaultTCPBuffer || rcv.Max != defaultTCPBuffer ||
		snd.Default != defaultTCPBuffer || snd.Max != defaultTCPBuffer || bool(moderate) {
		t.Fatalf("rcv %+v snd %+v moderate %v", rcv, snd, moderate)
	}
}
