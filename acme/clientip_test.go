package acme

import (
	"net/http"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestClientIPs(t *testing.T) {
	const trustedHeader = "CF-Connecting-IP"
	tests := []struct {
		name          string
		trustedHeader string // the header name to trust, "" = trust none
		headers       map[string]string
		remoteAddr    string
		expected      []netip.Addr
	}{
		{
			name:       "leftmost XFF is never trusted",
			headers:    map[string]string{"X-Forwarded-For": "1.2.3.4, 5.6.7.8"},
			remoteAddr: "9.9.9.9:80",
			expected:   []netip.Addr{netip.MustParseAddr("9.9.9.9")},
		},
		{
			name:          "trusted header is honored",
			trustedHeader: trustedHeader,
			headers:       map[string]string{trustedHeader: "1.2.3.4"},
			remoteAddr:    "9.9.9.9:80",
			expected:      []netip.Addr{netip.MustParseAddr("1.2.3.4"), netip.MustParseAddr("9.9.9.9")},
		},
		{
			name:          "spoofed XFF ignored even with trusted header configured",
			trustedHeader: trustedHeader,
			headers:       map[string]string{"X-Forwarded-For": "1.2.3.4"},
			remoteAddr:    "9.9.9.9:80",
			expected:      []netip.Addr{netip.MustParseAddr("9.9.9.9")},
		},
		{
			name:       "RemoteAddr IPv6 with port",
			remoteAddr: "[::1]:8080",
			expected:   []netip.Addr{netip.MustParseAddr("::1")},
		},
		{
			name:       "RemoteAddr without port",
			remoteAddr: "1.2.3.4",
			expected:   []netip.Addr{netip.MustParseAddr("1.2.3.4")},
		},
		{
			name:          "invalid trusted header value skipped",
			trustedHeader: trustedHeader,
			headers:       map[string]string{trustedHeader: "not-an-ip"},
			remoteAddr:    "1.2.3.4:80",
			expected:      []netip.Addr{netip.MustParseAddr("1.2.3.4")},
		},
		{
			name:       "empty",
			remoteAddr: "",
			expected:   nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &http.Request{
				Header:     make(http.Header),
				RemoteAddr: tt.remoteAddr,
			}
			for k, v := range tt.headers {
				r.Header.Set(k, v)
			}

			got := clientIPs(r, tt.trustedHeader)
			assert.Equal(t, tt.expected, got)
		})
	}
}

func TestMultiaddrsToIPs(t *testing.T) {
	tests := []struct {
		name     string
		addrs    []string
		expected []netip.Addr
	}{
		{
			name:     "IPv4 multiaddr",
			addrs:    []string{"/ip4/1.2.3.4/tcp/4001"},
			expected: []netip.Addr{netip.MustParseAddr("1.2.3.4")},
		},
		{
			name:     "IPv6 multiaddr",
			addrs:    []string{"/ip6/2001:db8::1/tcp/4001"},
			expected: []netip.Addr{netip.MustParseAddr("2001:db8::1")},
		},
		{
			name:     "mixed IPv4 and IPv6",
			addrs:    []string{"/ip4/1.2.3.4/tcp/4001", "/ip6/::1/tcp/4001"},
			expected: []netip.Addr{netip.MustParseAddr("1.2.3.4"), netip.MustParseAddr("::1")},
		},
		{
			name:     "invalid multiaddr skipped",
			addrs:    []string{"not-a-multiaddr", "/ip4/1.2.3.4/tcp/4001"},
			expected: []netip.Addr{netip.MustParseAddr("1.2.3.4")},
		},
		{
			name:     "empty input",
			addrs:    []string{},
			expected: []netip.Addr{},
		},
		{
			name:     "nil input",
			addrs:    nil,
			expected: []netip.Addr{},
		},
		{
			name:     "multiaddr without IP",
			addrs:    []string{"/dns4/example.com/tcp/4001"},
			expected: []netip.Addr{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := multiaddrsToIPs(tt.addrs)
			assert.Equal(t, tt.expected, got)
		})
	}
}
