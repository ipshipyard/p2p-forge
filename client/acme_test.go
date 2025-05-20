package client

import (
	"testing"

	"github.com/multiformats/go-multiaddr"
)

func TestIsPublicAddr(t *testing.T) {
	tests := []struct {
		name     string
		addr     string
		expected bool
	}{
		{
			name:     "Public IPv4 address (Google DNS)",
			addr:     "/ip4/8.8.8.8/tcp/4001",
			expected: true,
		},
		{
			name:     "Public IPv4 address (Cloudflare)",
			addr:     "/ip4/1.1.1.1/tcp/4001",
			expected: true,
		},
		{
			name:     "Private IPv4 address (LAN 192.168.x.x)",
			addr:     "/ip4/192.168.0.1/tcp/4001",
			expected: false,
		},
		{
			name:     "Private IPv4 address (LAN 10.x.x.x)",
			addr:     "/ip4/10.0.0.1/tcp/4001",
			expected: false,
		},
		{
			name:     "Public IPv6 address (Google)",
			addr:     "/ip6/2001:4860:4860::8888/tcp/4001",
			expected: true,
		},
		{
			name:     "Public IPv6 address (Cloudflare)",
			addr:     "/ip6/2606:4700:4700::1111/tcp/4001",
			expected: true,
		},
		{
			name:     "NAT64 IPv6 address for LAN IP",
			addr:     "/ip6/64:ff9b::192.0.2.1/tcp/4001",
			expected: false,
		},
		{
			name:     "libp2p Circuit relay address",
			addr:     "/ip4/8.8.8.8/tcp/4001/p2p-circuit",
			expected: false,
		},
		{
			name:     "Invalid multiaddr",
			addr:     "/invalid",
			expected: false,
		},
		{
			name:     "Localhost IPv4",
			addr:     "/ip4/127.0.0.1/tcp/4001",
			expected: false,
		},
		{
			name:     "Localhost IPv6",
			addr:     "/ip6/::1/tcp/4001",
			expected: false,
		},
		{
			name:     "Private IPv4 address (LAN 172.16.x.x)",
			addr:     "/ip4/172.16.0.1/tcp/4001",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr, err := multiaddr.NewMultiaddr(tt.addr)
			if err != nil {
				if tt.expected {
					t.Fatalf("failed to parse multiaddr %q: %v", tt.addr, err)
				}
				// If parsing fails and expected is false, let isPublicAddr handle it
				addr = nil
			}
			got := isPublicAddr(addr)
			if got != tt.expected {
				t.Errorf("isPublicAddr(%q) = %v; want %v", tt.addr, got, tt.expected)
			}
		})
	}

}
