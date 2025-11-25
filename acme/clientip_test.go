package acme

import (
	"net/http"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestClientIPs(t *testing.T) {
	tests := []struct {
		name       string
		xff        string
		remoteAddr string
		expected   []netip.Addr
	}{
		{
			name:       "XFF single IP",
			xff:        "1.2.3.4",
			remoteAddr: "",
			expected:   []netip.Addr{netip.MustParseAddr("1.2.3.4")},
		},
		{
			name:       "XFF multiple IPs uses leftmost",
			xff:        "1.2.3.4, 5.6.7.8, 9.10.11.12",
			remoteAddr: "",
			expected:   []netip.Addr{netip.MustParseAddr("1.2.3.4")},
		},
		{
			name:       "RemoteAddr IPv4 with port",
			xff:        "",
			remoteAddr: "1.2.3.4:8080",
			expected:   []netip.Addr{netip.MustParseAddr("1.2.3.4")},
		},
		{
			name:       "RemoteAddr IPv6 with port",
			xff:        "",
			remoteAddr: "[::1]:8080",
			expected:   []netip.Addr{netip.MustParseAddr("::1")},
		},
		{
			name:       "both XFF and RemoteAddr",
			xff:        "1.2.3.4",
			remoteAddr: "5.6.7.8:8080",
			expected:   []netip.Addr{netip.MustParseAddr("1.2.3.4"), netip.MustParseAddr("5.6.7.8")},
		},
		{
			name:       "empty headers",
			xff:        "",
			remoteAddr: "",
			expected:   nil,
		},
		{
			name:       "XFF with spaces",
			xff:        "  1.2.3.4  ",
			remoteAddr: "",
			expected:   []netip.Addr{netip.MustParseAddr("1.2.3.4")},
		},
		{
			name:       "invalid XFF skipped",
			xff:        "not-an-ip",
			remoteAddr: "1.2.3.4:80",
			expected:   []netip.Addr{netip.MustParseAddr("1.2.3.4")},
		},
		{
			name:       "RemoteAddr without port",
			xff:        "",
			remoteAddr: "1.2.3.4",
			expected:   []netip.Addr{netip.MustParseAddr("1.2.3.4")},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &http.Request{
				Header:     make(http.Header),
				RemoteAddr: tt.remoteAddr,
			}
			if tt.xff != "" {
				r.Header.Set("X-Forwarded-For", tt.xff)
			}

			got := clientIPs(r)
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
