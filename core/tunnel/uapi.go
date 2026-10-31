package tunnel

import (
	"bufio"
	"encoding/hex"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// uapiConfig renders the WireGuard UAPI "set" text for a client device
// (§9.1). fwmark 0 omits the key (only Linux uses a mark).
func uapiConfig(c Config, fwmark uint32) string {
	var b strings.Builder
	b.WriteString("private_key=" + hex.EncodeToString(c.PrivateKey[:]) + "\n")
	b.WriteString("listen_port=0\n")
	if fwmark != 0 {
		b.WriteString("fwmark=" + strconv.FormatUint(uint64(fwmark), 10) + "\n")
	}
	b.WriteString("replace_peers=true\n")
	b.WriteString("public_key=" + hex.EncodeToString(c.Peer.PublicKey[:]) + "\n")
	b.WriteString("preshared_key=" + hex.EncodeToString(c.Peer.PresharedKey[:]) + "\n")
	b.WriteString("endpoint=" + c.Peer.Endpoint.String() + "\n")
	b.WriteString("persistent_keepalive_interval=" + strconv.Itoa(c.Peer.Keepalive) + "\n")
	b.WriteString("replace_allowed_ips=true\n")
	b.WriteString("allowed_ip=0.0.0.0/0\n")
	return b.String()
}

// uapiEndpoint renders the UAPI text that moves the existing peer to ep.
func uapiEndpoint(peer [32]byte, ep netip.AddrPort) string {
	return "public_key=" + hex.EncodeToString(peer[:]) + "\n" +
		"update_only=true\n" +
		"endpoint=" + ep.String() + "\n"
}

// parseUAPIStatus extracts handshake age and byte counters for peer from
// UAPI "get" output. HandshakeAgeSec is -1 when no handshake happened yet.
func parseUAPIStatus(get string, peer [32]byte, now time.Time) Status {
	st := Status{HandshakeAgeSec: -1}
	want := hex.EncodeToString(peer[:])
	inPeer := false
	sc := bufio.NewScanner(strings.NewReader(get))
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), "=")
		if !ok {
			continue
		}
		if k == "public_key" {
			inPeer = v == want
			continue
		}
		if !inPeer {
			continue
		}
		switch k {
		case "last_handshake_time_sec":
			if sec, err := strconv.ParseInt(v, 10, 64); err == nil && sec > 0 {
				age := now.Unix() - sec
				if age < 0 {
					age = 0
				}
				st.HandshakeAgeSec = age
			}
		case "rx_bytes":
			st.RxBytes, _ = strconv.ParseUint(v, 10, 64)
		case "tx_bytes":
			st.TxBytes, _ = strconv.ParseUint(v, 10, 64)
		}
	}
	return st
}
