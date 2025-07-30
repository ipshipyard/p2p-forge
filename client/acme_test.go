package client

import (
	"testing"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
	"go.uber.org/zap/zaptest"
)

const (
	testForgeDomain = "example.com"
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

// mockHostWithConfirmedAddrs implements just the interface we need for testing
type mockHostWithConfirmedAddrs struct {
	host.Host
	id               peer.ID
	reachableAddrs   []multiaddr.Multiaddr
	unreachableAddrs []multiaddr.Multiaddr
	pendingAddrs     []multiaddr.Multiaddr
}

func (m *mockHostWithConfirmedAddrs) ID() peer.ID {
	return m.id
}

func (m *mockHostWithConfirmedAddrs) ConfirmedAddrs() ([]multiaddr.Multiaddr, []multiaddr.Multiaddr, []multiaddr.Multiaddr) {
	return m.reachableAddrs, m.unreachableAddrs, m.pendingAddrs
}

func TestAddrFactoryFnSkipsUnreachableAddrs(t *testing.T) {
	// Create test peer ID
	testPeerID, err := peer.Decode("12D3KooWGzxzKZYveHXtpG6AsrUJBcWxHBFS2HsEoGTxrMLvKXtf")
	if err != nil {
		t.Fatalf("failed to decode test peer ID: %v", err)
	}

	// Create test multiaddrs (IPv4)
	// 1.1.1.1 is reachable - public Cloudflare DNS server
	reachableAddr, err := multiaddr.NewMultiaddr("/ip4/1.1.1.1/tcp/4001")
	if err != nil {
		t.Fatalf("failed to create reachable addr: %v", err)
	}

	// 192.168.1.1 is unreachable - private RFC 1918 address space
	unreachableAddr, err := multiaddr.NewMultiaddr("/ip4/192.168.1.1/tcp/4001")
	if err != nil {
		t.Fatalf("failed to create unreachable addr: %v", err)
	}

	// Create test multiaddrs (IPv6)
	// 2001:4860:4860::8888 is reachable - public Google DNS IPv6 server
	reachableAddrIPv6, err := multiaddr.NewMultiaddr("/ip6/2001:4860:4860::8888/tcp/4001")
	if err != nil {
		t.Fatalf("failed to create reachable IPv6 addr: %v", err)
	}

	// fe80::1 is unreachable - link-local IPv6 address (RFC 4291)
	unreachableAddrIPv6, err := multiaddr.NewMultiaddr("/ip6/fe80::1/tcp/4001")
	if err != nil {
		t.Fatalf("failed to create unreachable IPv6 addr: %v", err)
	}

	// Create forge addresses (IPv4)
	// Reachable forge - based on public Cloudflare DNS IP
	reachableForgeAddr, err := multiaddr.NewMultiaddr("/ip4/1.1.1.1/tcp/4001/tls/sni/wildcard." + testForgeDomain + "/ws")
	if err != nil {
		t.Fatalf("failed to create reachable forge addr: %v", err)
	}

	// Unreachable forge - based on private RFC 1918 IP
	unreachableForgeAddr, err := multiaddr.NewMultiaddr("/ip4/192.168.1.1/tcp/4001/tls/sni/wildcard." + testForgeDomain + "/ws")
	if err != nil {
		t.Fatalf("failed to create unreachable forge addr: %v", err)
	}

	// Create forge addresses (IPv6)
	// Reachable forge - based on public Google DNS IPv6
	reachableForgeAddrIPv6, err := multiaddr.NewMultiaddr("/ip6/2001:4860:4860::8888/tcp/4001/tls/sni/wildcard." + testForgeDomain + "/ws")
	if err != nil {
		t.Fatalf("failed to create reachable IPv6 forge addr: %v", err)
	}

	// Unreachable forge - based on link-local IPv6 address
	unreachableForgeAddrIPv6, err := multiaddr.NewMultiaddr("/ip6/fe80::1/tcp/4001/tls/sni/wildcard." + testForgeDomain + "/ws")
	if err != nil {
		t.Fatalf("failed to create unreachable IPv6 forge addr: %v", err)
	}

	// Expected transformed addresses (IPv4 - wildcard replaced with IP-based subdomain)
	expectedReachableForgeAddr, err := multiaddr.NewMultiaddr("/ip4/1.1.1.1/tcp/4001/tls/sni/1-1-1-1.k51qzi5uqu5diuci8bva7narzo109juvlfbckhzf3j2ljua2979b21rs6uyquk." + testForgeDomain + "/ws")
	if err != nil {
		t.Fatalf("failed to create expected reachable forge addr: %v", err)
	}

	// Short /dns4 version of the expected transformed address (IPv4)
	expectedReachableForgeAddrShort, err := multiaddr.NewMultiaddr("/dns4/1-1-1-1.k51qzi5uqu5diuci8bva7narzo109juvlfbckhzf3j2ljua2979b21rs6uyquk." + testForgeDomain + "/tcp/4001/tls/ws")
	if err != nil {
		t.Fatalf("failed to create expected short reachable forge addr: %v", err)
	}

	// Expected transformed addresses (IPv6 - wildcard replaced with IP-based subdomain, compressed format)
	expectedReachableForgeAddrIPv6, err := multiaddr.NewMultiaddr("/ip6/2001:4860:4860::8888/tcp/4001/tls/sni/2001-4860-4860--8888.k51qzi5uqu5diuci8bva7narzo109juvlfbckhzf3j2ljua2979b21rs6uyquk." + testForgeDomain + "/ws")
	if err != nil {
		t.Fatalf("failed to create expected reachable IPv6 forge addr: %v", err)
	}

	// Short /dns6 version of the expected transformed address (IPv6, compressed format)
	expectedReachableForgeAddrIPv6Short, err := multiaddr.NewMultiaddr("/dns6/2001-4860-4860--8888.k51qzi5uqu5diuci8bva7narzo109juvlfbckhzf3j2ljua2979b21rs6uyquk." + testForgeDomain + "/tcp/4001/tls/ws")
	if err != nil {
		t.Fatalf("failed to create expected short reachable IPv6 forge addr: %v", err)
	}

	// WSS component to decapsulate
	wssComponent, err := multiaddr.NewMultiaddr("/tls/sni/wildcard." + testForgeDomain + "/ws")
	if err != nil {
		t.Fatalf("failed to create wss component: %v", err)
	}

	// Create mock host that returns specific unreachable addresses (both IPv4 and IPv6)
	mockHost := &mockHostWithConfirmedAddrs{
		id:               testPeerID,
		unreachableAddrs: []multiaddr.Multiaddr{unreachableAddr, unreachableAddrIPv6},
	}

	hostFn := func() host.Host {
		return mockHost
	}

	logger := zaptest.NewLogger(t).Sugar()

	// Helper function to run addrFactoryFn and validate results
	runTest := func(t *testing.T, multiaddrs, expectedAddrs []multiaddr.Multiaddr, produceShortAddrs bool, description string) {
		result := addrFactoryFn(
			false, // skipForgeAddrs
			hostFn,
			testForgeDomain,   // forgeDomain
			true,              // allowPrivateForgeAddrs
			produceShortAddrs, // produceShortAddrs
			wssComponent,      // p2pForgeWssComponent
			multiaddrs,
			logger,
		)

		if len(result) != len(expectedAddrs) {
			t.Errorf("%s: expected %d addresses, got %d. Result: %v",
				description, len(expectedAddrs), len(result), result)
		}

		// Check that each expected address is present in the result
		for _, expectedAddr := range expectedAddrs {
			found := false
			for _, resultAddr := range result {
				if resultAddr.Equal(expectedAddr) {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("%s: expected address %v not found in result %v",
					description, expectedAddr, result)
			}
		}

		// Check that no unexpected addresses are present in the result
		for _, resultAddr := range result {
			found := false
			for _, expectedAddr := range expectedAddrs {
				if resultAddr.Equal(expectedAddr) {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("%s: unexpected address %v found in result %v",
					description, resultAddr, result)
			}
		}
	}

	tests := []struct {
		name          string
		multiaddrs    []multiaddr.Multiaddr
		expectedAddrs []multiaddr.Multiaddr
		description   string
	}{
		{
			name:          "skip unreachable forge address",
			multiaddrs:    []multiaddr.Multiaddr{reachableForgeAddr, unreachableForgeAddr},
			expectedAddrs: []multiaddr.Multiaddr{expectedReachableForgeAddrShort},
			description:   "unreachable forge address should be completely skipped",
		},
		{
			name:          "process reachable forge address",
			multiaddrs:    []multiaddr.Multiaddr{reachableForgeAddr},
			expectedAddrs: []multiaddr.Multiaddr{expectedReachableForgeAddrShort},
			description:   "reachable forge address should be processed and transformed",
		},
		{
			name:          "no forge addresses affected",
			multiaddrs:    []multiaddr.Multiaddr{reachableAddr, unreachableAddr},
			expectedAddrs: []multiaddr.Multiaddr{reachableAddr, unreachableAddr},
			description:   "non-forge addresses should not be affected by unreachable filter",
		},
		{
			name:          "skip unreachable IPv6 forge address",
			multiaddrs:    []multiaddr.Multiaddr{reachableForgeAddrIPv6, unreachableForgeAddrIPv6},
			expectedAddrs: []multiaddr.Multiaddr{expectedReachableForgeAddrIPv6Short},
			description:   "unreachable IPv6 forge address should be completely skipped",
		},
		{
			name:          "process reachable IPv6 forge address",
			multiaddrs:    []multiaddr.Multiaddr{reachableForgeAddrIPv6},
			expectedAddrs: []multiaddr.Multiaddr{expectedReachableForgeAddrIPv6Short},
			description:   "reachable IPv6 forge address should be processed and transformed",
		},
		{
			name:          "no IPv6 forge addresses affected",
			multiaddrs:    []multiaddr.Multiaddr{reachableAddrIPv6, unreachableAddrIPv6},
			expectedAddrs: []multiaddr.Multiaddr{reachableAddrIPv6, unreachableAddrIPv6},
			description:   "non-forge IPv6 addresses should not be affected by unreachable filter",
		},
		{
			name:          "mixed IPv4 and IPv6 forge addresses",
			multiaddrs:    []multiaddr.Multiaddr{reachableForgeAddr, unreachableForgeAddr, reachableForgeAddrIPv6, unreachableForgeAddrIPv6},
			expectedAddrs: []multiaddr.Multiaddr{expectedReachableForgeAddrShort, expectedReachableForgeAddrIPv6Short},
			description:   "should process reachable forge addresses and skip unreachable ones for both IPv4 and IPv6",
		},
	}

	// Test with produceShortAddrs: true (generates /dns4 short versions)
	for _, tt := range tests {
		t.Run(tt.name+" (short addrs)", func(t *testing.T) {
			runTest(t, tt.multiaddrs, tt.expectedAddrs, true, tt.description)
		})
	}

	// Test with produceShortAddrs: false (generates full /ip4/.../tls/sni/... versions)
	longTests := []struct {
		name          string
		multiaddrs    []multiaddr.Multiaddr
		expectedAddrs []multiaddr.Multiaddr
		description   string
	}{
		{
			name:          "process reachable forge address (long)",
			multiaddrs:    []multiaddr.Multiaddr{reachableForgeAddr},
			expectedAddrs: []multiaddr.Multiaddr{expectedReachableForgeAddr},
			description:   "reachable forge address should be processed and transformed to long format",
		},
		{
			name:          "process reachable IPv6 forge address (long)",
			multiaddrs:    []multiaddr.Multiaddr{reachableForgeAddrIPv6},
			expectedAddrs: []multiaddr.Multiaddr{expectedReachableForgeAddrIPv6},
			description:   "reachable IPv6 forge address should be processed and transformed to long format",
		},
	}

	for _, tt := range longTests {
		t.Run(tt.name, func(t *testing.T) {
			runTest(t, tt.multiaddrs, tt.expectedAddrs, false, tt.description)
		})
	}
}
