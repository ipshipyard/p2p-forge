package client

import (
	"strings"
	"testing"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
)

// FuzzEscapeIPv6ForDNS tests that IPv6 address escaping produces RFC 1035 compliant DNS labels
func FuzzEscapeIPv6ForDNS(f *testing.F) {
	// Seed corpus with known edge cases
	seeds := []string{
		"::1",                             // loopback
		"::",                              // all zeros
		"2001:db8::",                      // trailing compression
		"::ffff:192.0.2.1",                // IPv4-mapped
		"2001:db8:85a3::8a2e:370:7334",    // middle compression
		"2001:db8:85a3:0:0:8a2e:370:7334", // no compression
		"fe80::1",                         // link-local
		"ff02::1",                         // multicast
		"2001:0db8:0000:0000:0000:0000:0000:0001", // fully expanded
	}

	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, ipv6Addr string) {
		// escapeIPv6ForDNS should never panic (primary property)
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("escapeIPv6ForDNS panicked on input %q: %v", ipv6Addr, r)
			}
		}()

		result := escapeIPv6ForDNS(ipv6Addr)

		// Only validate RFC compliance for inputs that look like valid IPv6
		// (contain colons, which is what the function is designed to handle)
		if !strings.Contains(ipv6Addr, ":") {
			// Not an IPv6 address pattern - function may produce arbitrary output
			return
		}

		// RFC 1035 property: DNS labels cannot start with hyphen
		if len(result) > 0 && result[0] == '-' {
			t.Errorf("DNS label starts with hyphen: %q (from %q)", result, ipv6Addr)
		}

		// RFC 1035 property: DNS labels cannot end with hyphen
		if len(result) > 0 && result[len(result)-1] == '-' {
			t.Errorf("DNS label ends with hyphen: %q (from %q)", result, ipv6Addr)
		}
	})
}

// FuzzExtractForgeAddrInfo tests that multiaddr extraction handles malformed input safely
func FuzzExtractForgeAddrInfo(f *testing.F) {
	// Seed corpus with valid multiaddrs
	testPeerID, _ := peer.Decode("12D3KooWGzxzKZYveHXtpG6AsrUJBcWxHBFS2HsEoGTxrMLvKXtf")

	seeds := []string{
		"/ip4/192.168.1.1/tcp/4001",
		"/ip4/0.0.0.0/tcp/0",
		"/ip4/255.255.255.255/tcp/65535",
		"/ip6/::1/tcp/4001",
		"/ip6/::/tcp/4001",
		"/ip6/2001:db8::/tcp/4001",
		"/ip6/fe80::1/tcp/8080",
		"/ip4/127.0.0.1/tcp/1234/ws",
		"/ip6/::ffff:192.0.2.1/tcp/443",
	}

	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, maddrStr string) {
		// Attempt to parse multiaddr - this is expected to fail for invalid input
		ma, err := multiaddr.NewMultiaddr(maddrStr)
		if err != nil {
			// Invalid multiaddr format - this is expected for fuzz input
			return
		}

		// ExtractForgeAddrInfo should never panic, even on valid-but-unusual multiaddrs
		info, err := ExtractForgeAddrInfo(ma, testPeerID)

		if err != nil {
			// Error is acceptable - just verify it doesn't panic
			return
		}

		// If extraction succeeded, verify RFC compliance of output
		if info.EscapedIP != "" {
			// RFC 1035: No leading hyphen
			if info.EscapedIP[0] == '-' {
				t.Errorf("EscapedIP starts with hyphen: %q", info.EscapedIP)
			}

			// RFC 1035: No trailing hyphen
			if info.EscapedIP[len(info.EscapedIP)-1] == '-' {
				t.Errorf("EscapedIP ends with hyphen: %q", info.EscapedIP)
			}

			// RFC 1035: Max 63 characters
			if len(info.EscapedIP) > 63 {
				t.Errorf("EscapedIP exceeds 63 characters: %d", len(info.EscapedIP))
			}
		}

		// Verify IP version is valid
		if info.IPVersion != "4" && info.IPVersion != "6" {
			t.Errorf("Invalid IPVersion: %q", info.IPVersion)
		}

		// Verify PeerIDBase36 is not empty
		if info.PeerIDBase36 == "" {
			t.Errorf("PeerIDBase36 should not be empty")
		}

		// Verify TCP port is present
		if info.TCPPort == "" {
			t.Errorf("TCPPort should not be empty")
		}
	})
}

// FuzzForgeAddrRoundtrip tests end-to-end: multiaddr → ForgeAddrInfo → DNS-based multiaddr
func FuzzForgeAddrRoundtrip(f *testing.F) {
	testPeerID, _ := peer.Decode("12D3KooWGzxzKZYveHXtpG6AsrUJBcWxHBFS2HsEoGTxrMLvKXtf")

	// Seed with various IP formats
	seeds := []string{
		"/ip4/192.168.1.1/tcp/4001",
		"/ip6/::1/tcp/4001",
		"/ip6/2001:db8::/tcp/4001",
		"/ip6/fe80::abcd:ef01:2345:6789/tcp/8080",
	}

	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, maddrStr string) {
		// Parse input multiaddr
		ma, err := multiaddr.NewMultiaddr(maddrStr)
		if err != nil {
			return // Invalid format - expected for fuzz input
		}

		// Extract forge address info
		info, err := ExtractForgeAddrInfo(ma, testPeerID)
		if err != nil {
			return // Extraction failed - acceptable for some multiaddrs
		}

		// Build both short and long format multiaddrs
		shortMa := BuildShortForgeMultiaddr(info, "libp2p.direct")
		longMa := BuildLongForgeMultiaddr(info, "libp2p.direct")

		// Property: Generated multiaddrs must be parseable
		_, err = multiaddr.NewMultiaddr(shortMa)
		if err != nil {
			t.Errorf("Generated short multiaddr is invalid: %q, error: %v", shortMa, err)
		}

		_, err = multiaddr.NewMultiaddr(longMa)
		if err != nil {
			t.Errorf("Generated long multiaddr is invalid: %q, error: %v", longMa, err)
		}

		// Property: DNS component in short multiaddr should be RFC compliant
		if strings.Contains(shortMa, "/dns") {
			// Extract DNS part (between /dns{4|6}/ and /tcp/)
			parts := strings.Split(shortMa, "/")
			for i, part := range parts {
				if part == "dns4" || part == "dns6" {
					if i+1 < len(parts) {
						dnsLabel := parts[i+1]
						// Extract just the IP part (before first dot)
						if idx := strings.Index(dnsLabel, "."); idx > 0 {
							ipPart := dnsLabel[:idx]
							if len(ipPart) > 0 {
								if ipPart[0] == '-' {
									t.Errorf("DNS label in short multiaddr starts with hyphen: %q", ipPart)
								}
								if ipPart[len(ipPart)-1] == '-' {
									t.Errorf("DNS label in short multiaddr ends with hyphen: %q", ipPart)
								}
							}
						}
					}
					break
				}
			}
		}
	})
}

// FuzzBuildShortForgeMultiaddr tests multiaddr construction with arbitrary ForgeAddrInfo
func FuzzBuildShortForgeMultiaddr(f *testing.F) {
	// Seed with valid structures
	f.Add("192-168-1-1", "4", "/ip4/192.168.1.1", "4001", "k51qzi5uqu5testpeerid")
	f.Add("2001-db8--1", "6", "/ip6/2001:db8::1", "8080", "k51qzi5uqu5testpeerid")
	f.Add("0--1", "6", "/ip6/::1", "443", "k51qzi5uqu5testpeerid")

	f.Fuzz(func(t *testing.T, escapedIP, ipVersion, ipMaStr, tcpPort, peerIDBase36 string) {
		info := &ForgeAddrInfo{
			EscapedIP:    escapedIP,
			IPVersion:    ipVersion,
			IPMaStr:      ipMaStr,
			TCPPort:      tcpPort,
			PeerIDBase36: peerIDBase36,
		}

		// BuildShortForgeMultiaddr should never panic
		result := BuildShortForgeMultiaddr(info, "libp2p.direct")

		// Property: Result should be a valid string (non-empty if inputs are non-empty)
		if escapedIP != "" && ipVersion != "" && tcpPort != "" && peerIDBase36 != "" {
			if result == "" {
				t.Errorf("BuildShortForgeMultiaddr returned empty string with non-empty inputs")
			}

			// Property: Result should contain expected components
			if !strings.Contains(result, "libp2p.direct") {
				t.Errorf("Result doesn't contain forge domain: %q", result)
			}
			if !strings.Contains(result, "/tcp/") {
				t.Errorf("Result doesn't contain /tcp/: %q", result)
			}
		}
	})
}
