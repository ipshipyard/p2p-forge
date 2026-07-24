package acme

import (
	"bytes"
	"encoding/base64"
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
	madns "github.com/multiformats/go-multiaddr-dns"
	"github.com/stretchr/testify/require"
)

func TestVetDestIP(t *testing.T) {
	blocked := []string{
		"127.0.0.1",              // loopback
		"::1",                    // loopback v6
		"0.0.0.0",                // unspecified
		"10.1.2.3",               // RFC1918
		"192.168.0.1",            // RFC1918
		"172.16.5.5",             // RFC1918
		"169.254.169.254",        // link-local (cloud metadata)
		"fe80::1",                // link-local v6
		"100.64.0.1",             // CGNAT
		"fc00::1",                // ULA
		"::ffff:10.0.0.1",        // IPv4-mapped private
		"::ffff:169.254.169.254", // IPv4-mapped metadata
		"64:ff9b::a9fe:a9fe",     // NAT64 of 169.254.169.254
		"64:ff9b:1::1",           // NAT64 local-use
		"2002:a9fe:a9fe::1",      // 6to4
		"2001::1",                // Teredo
		"224.0.0.1",              // multicast
		"0.1.2.3",                // 0.0.0.0/8 "this host"
		"::a9fe:a9fe",            // IPv4-compatible IPv6 of 169.254.169.254
		"::7f00:1",               // IPv4-compatible IPv6 of 127.0.0.1
		"198.18.0.1",             // benchmarking
		"240.0.0.1",              // reserved / Class E
		"255.255.255.255",        // broadcast
		"192.0.0.170",            // IETF protocol assignments (RFC 6890)
		"192.0.0.2",              // DS-Lite CPE (RFC 7335)
		"192.88.99.1",            // deprecated 6to4 relay anycast
		"100::1",                 // discard-only (RFC 6666)
	}
	for _, s := range blocked {
		t.Run("blocked/"+s, func(t *testing.T) {
			require.Error(t, vetDestIP(netip.MustParseAddr(s)), "%s must be rejected", s)
		})
	}

	allowed := []string{
		"1.1.1.1",
		"8.8.8.8",
		"203.0.113.7",
		"2606:4700:4700::1111",
	}
	for _, s := range allowed {
		t.Run("allowed/"+s, func(t *testing.T) {
			require.NoError(t, vetDestIP(netip.MustParseAddr(s)), "%s must be accepted", s)
		})
	}
}

// TestVettingRejectsPrivate confirms the probe refuses a loopback/private
// target when vetting is on (AllowPrivateAddrs=false), rather than dialing it.
func TestVettingRejectsPrivate(t *testing.T) {
	initMetrics()
	_, priv := newRegistrantHost(t)

	c := newTestWriter()
	c.AllowPrivateAddrs = false // enable vetting

	value := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x01}, 32))
	req := signedV2Request(t, priv, value, []string{"/ip4/127.0.0.1/tcp/4001", "/ip4/10.0.0.1/tcp/4001"})
	rec := httptest.NewRecorder()
	c.handleV2Challenge(rec, req)
	// No public address survives vetting, so the probe fails: 422.
	require.Equal(t, 422, rec.Code, rec.Body.String())
}

func TestIPGaterPins(t *testing.T) {
	gater := newIPGater([]netip.Addr{netip.MustParseAddr("203.0.113.7")})
	pid := peer.ID("")

	// Same IP over TCP and QUIC is permitted; a different IP is not.
	tcp := multiaddr.StringCast("/ip4/203.0.113.7/tcp/4001")
	quic := multiaddr.StringCast("/ip4/203.0.113.7/udp/4001/quic-v1")
	other := multiaddr.StringCast("/ip4/198.51.100.9/tcp/4001")
	require.True(t, gater.InterceptAddrDial(pid, tcp))
	require.True(t, gater.InterceptAddrDial(pid, quic))
	require.False(t, gater.InterceptAddrDial(pid, other))

	// An address with no IP literal (e.g. a bare dns name) is not permitted.
	dnsAddr := multiaddr.StringCast("/dns4/example.com/tcp/443")
	require.False(t, gater.InterceptAddrDial(pid, dnsAddr))
}

func TestResolveAndVetFiltersPrivate(t *testing.T) {
	addrs := []string{
		"/ip4/203.0.113.7/tcp/4001", // public: kept
		"/ip4/10.0.0.5/tcp/4001",    // RFC1918: dropped
		"/ip4/127.0.0.1/tcp/4001",   // loopback: dropped
	}
	dialable, ips, err := resolveAndVet(t.Context(), madns.DefaultResolver, addrs, false)
	require.NoError(t, err)
	require.Len(t, dialable, 1)
	require.Equal(t, []netip.Addr{netip.MustParseAddr("203.0.113.7")}, ips)

	// With only private addresses and vetting on, nothing survives.
	_, _, err = resolveAndVet(t.Context(), madns.DefaultResolver, []string{"/ip4/10.0.0.5/tcp/4001"}, false)
	require.ErrorContains(t, err, "no dialable public address")

	// allowPrivate keeps them.
	dialable, _, err = resolveAndVet(t.Context(), madns.DefaultResolver, []string{"/ip4/10.0.0.5/tcp/4001"}, true)
	require.NoError(t, err)
	require.Len(t, dialable, 1)
}
