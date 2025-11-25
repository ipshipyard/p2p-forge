package client

import (
	"fmt"
	"testing"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
)

// TestExtractForgeAddrInfoProducesRFCCompliantLabels tests the production function
// ExtractForgeAddrInfo to ensure it produces RFC-compliant DNS labels for IPv6 addresses
func TestExtractForgeAddrInfoProducesRFCCompliantLabels(t *testing.T) {
	tests := []struct {
		name            string
		multiaddr       string
		expectedDNS     string
		expectedVersion string
		expectedPort    string
	}{
		{
			name:            "IPv4 address produces dash-separated label",
			multiaddr:       "/ip4/192.168.1.100/tcp/4001",
			expectedDNS:     "192-168-1-100",
			expectedVersion: "4",
			expectedPort:    "4001",
		},
		{
			name:            "IPv6 with trailing double colon adds trailing zero",
			multiaddr:       "/ip6/2001:db8::/tcp/4001",
			expectedDNS:     "2001-db8--0", // RFC compliant: cannot end with hyphen
			expectedVersion: "6",
			expectedPort:    "4001",
		},
		{
			name:            "IPv6 with leading double colon adds leading zero",
			multiaddr:       "/ip6/::1/tcp/4001",
			expectedDNS:     "0--1", // RFC compliant: cannot start with hyphen
			expectedVersion: "6",
			expectedPort:    "4001",
		},
		{
			name:            "IPv6 double colon only adds both zeros",
			multiaddr:       "/ip6/::/tcp/4001",
			expectedDNS:     "0--0", // RFC compliant: both leading and trailing zeros
			expectedVersion: "6",
			expectedPort:    "4001",
		},
		{
			name:            "IPv6 full address with middle double colon",
			multiaddr:       "/ip6/2001:db8:85a3::8a2e:370:7334/tcp/4001",
			expectedDNS:     "2001-db8-85a3--8a2e-370-7334",
			expectedVersion: "6",
			expectedPort:    "4001",
		},
		{
			name:            "IPv6 no double colon (gets normalized to compressed form)",
			multiaddr:       "/ip6/2001:db8:85a3:0:0:8a2e:370:7334/tcp/4001",
			expectedDNS:     "2001-db8-85a3--8a2e-370-7334", // multiaddr normalizes this to compressed form
			expectedVersion: "6",
			expectedPort:    "4001",
		},
		{
			name:            "IPv6 loopback",
			multiaddr:       "/ip6/::1/tcp/4001",
			expectedDNS:     "0--1",
			expectedVersion: "6",
			expectedPort:    "4001",
		},
		{
			name:            "IPv6 longest possible address stays under 63 char DNS label limit",
			multiaddr:       "/ip6/ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/tcp/4001",
			expectedDNS:     "ffff-ffff-ffff-ffff-ffff-ffff-ffff-ffff", // 39 chars - well under 63
			expectedVersion: "6",
			expectedPort:    "4001",
		},
	}

	// Create a test peer ID
	peerID, err := peer.Decode("12D3KooWGzxzKZYveHXtpG6AsrUJBcWxHBFS2HsEoGTxrMLvKXtf")
	if err != nil {
		t.Fatalf("Failed to decode test peer ID: %v", err)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Parse the test multiaddr
			ma, err := multiaddr.NewMultiaddr(tt.multiaddr)
			if err != nil {
				t.Fatalf("Failed to parse multiaddr %q: %v", tt.multiaddr, err)
			}

			// Call the production function
			forgeAddrInfo, err := ExtractForgeAddrInfo(ma, peerID)
			if err != nil {
				t.Fatalf("ExtractForgeAddrInfo failed: %v", err)
			}

			t.Logf("Input: %s", tt.multiaddr)
			t.Logf("Output: EscapedIP=%s, IPVersion=%s, TCPPort=%s",
				forgeAddrInfo.EscapedIP, forgeAddrInfo.IPVersion, forgeAddrInfo.TCPPort)

			// Verify expected results
			if forgeAddrInfo.EscapedIP != tt.expectedDNS {
				t.Errorf("Expected DNS label %q, got %q", tt.expectedDNS, forgeAddrInfo.EscapedIP)
			}

			if forgeAddrInfo.IPVersion != tt.expectedVersion {
				t.Errorf("Expected IP version %q, got %q", tt.expectedVersion, forgeAddrInfo.IPVersion)
			}

			if forgeAddrInfo.TCPPort != tt.expectedPort {
				t.Errorf("Expected TCP port %q, got %q", tt.expectedPort, forgeAddrInfo.TCPPort)
			}

			// Verify RFC compliance
			if err := validateRFCCompliantDNSLabel(forgeAddrInfo.EscapedIP); err != nil {
				t.Errorf("DNS label %q is not RFC compliant: %v", forgeAddrInfo.EscapedIP, err)
			}

			// Verify peer ID is properly encoded
			if forgeAddrInfo.PeerIDBase36 == "" {
				t.Error("PeerIDBase36 should not be empty")
			}

			// Test that it would produce a valid multiaddr for short addrs
			testMultiaddr := BuildShortForgeMultiaddr(forgeAddrInfo, "libp2p.direct")

			_, err = multiaddr.NewMultiaddr(testMultiaddr)
			if err != nil {
				t.Errorf("Generated short multiaddr %q is invalid: %v", testMultiaddr, err)
			} else {
				t.Logf("✓ Valid short multiaddr: %s", testMultiaddr)
			}

			// Test that it would produce a valid multiaddr for long addrs
			testMultiaddrLong := BuildLongForgeMultiaddr(forgeAddrInfo, "libp2p.direct")

			_, err = multiaddr.NewMultiaddr(testMultiaddrLong)
			if err != nil {
				t.Errorf("Generated long multiaddr %q is invalid: %v", testMultiaddrLong, err)
			} else {
				t.Logf("✓ Valid long multiaddr: %s", testMultiaddrLong)
			}
		})
	}
}

func validateRFCCompliantDNSLabel(label string) error {
	if len(label) == 0 {
		return nil
	}

	// RFC 1035: labels must not start or end with hyphen
	if label[0] == '-' {
		return fmt.Errorf("DNS label cannot start with hyphen")
	}
	if label[len(label)-1] == '-' {
		return fmt.Errorf("DNS label cannot end with hyphen")
	}

	// Additional RFC checks
	if len(label) > 63 {
		return fmt.Errorf("DNS label cannot exceed 63 characters")
	}

	return nil
}
