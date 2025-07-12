package ipparser

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/miekg/dns"
)


// TestDomainCompatibility tests full domain processing
func TestDomainCompatibility(t *testing.T) {
	// Test cases for domain compatibility
	testPeerID := "k51qzi5uqu5dj2c294cab64yiq2ri684kc5sr9odfhoo84osl4resldwfy8u5r"

	domainTests := []struct {
		name     string
		domain   string
		expected string
		isIPv4   bool
	}{
		{
			name:     "IPv4_Domain",
			domain:   "192-0-2-1." + testPeerID + ".libp2p.direct",
			expected: "192.0.2.1",
			isIPv4:   true,
		},
		{
			name:     "IPv6_Domain_Full",
			domain:   "2001-db8-0-0-0-0-0-1." + testPeerID + ".libp2p.direct",
			expected: "2001:db8::1",
			isIPv4:   false,
		},
		{
			name:     "IPv6_Domain_Compressed",
			domain:   "2001-db8--1." + testPeerID + ".libp2p.direct",
			expected: "2001:db8::1",
			isIPv4:   false,
		},
		{
			name:     "IPv6_Loopback",
			domain:   "0--1." + testPeerID + ".libp2p.direct",
			expected: "::1",
			isIPv4:   false,
		},
	}

	for _, tt := range domainTests {
		t.Run(tt.name, func(t *testing.T) {
			// Extract prefix from domain
			parts := strings.Split(tt.domain, ".")
			if len(parts) < 3 {
				t.Fatalf("Invalid domain format: %s", tt.domain)
			}

			prefix := parts[0]

			// Test IP parsing using the same logic as production
			expectedQtype := dns.TypeAAAA
			if tt.isIPv4 {
				expectedQtype = dns.TypeA
			}

			parsedIP, err := parseIPFromPrefix(prefix, expectedQtype)
			if err != nil {
				t.Errorf("Failed to parse IP from domain %s: %v", tt.domain, err)
				return
			}

			expectedIP, err := netip.ParseAddr(tt.expected)
			if err != nil {
				t.Errorf("Failed to parse expected IP %s: %v", tt.expected, err)
				return
			}

			if parsedIP.Compare(expectedIP) != 0 {
				t.Errorf("Domain %s: got IP %v, want %v", tt.domain, parsedIP, expectedIP)
			}
		})
	}
}


func TestParseIPFromPrefix(t *testing.T) {
	tests := []struct {
		name      string
		prefix    string
		qtype     uint16
		wantValid bool
		wantIP    string
	}{
		// IPv4 tests
		{
			name:      "Valid_IPv4_A_Query",
			prefix:    "192-168-1-1",
			qtype:     dns.TypeA,
			wantValid: true,
			wantIP:    "192.168.1.1",
		},
		{
			name:      "Valid_IPv4_AAAA_Query",
			prefix:    "192-168-1-1",
			qtype:     dns.TypeAAAA,
			wantValid: false,
		},
		{
			name:      "Invalid_IPv4_A_Query",
			prefix:    "256-1-1-1",
			qtype:     dns.TypeA,
			wantValid: false,
		},
		// Additional IPv4 patterns
		{
			name:      "IPv4_10_0_0_1",
			prefix:    "10-0-0-1",
			qtype:     dns.TypeA,
			wantValid: true,
			wantIP:    "10.0.0.1",
		},
		{
			name:      "IPv4_192_0_2_1",
			prefix:    "192-0-2-1",
			qtype:     dns.TypeA,
			wantValid: true,
			wantIP:    "192.0.2.1",
		},
		{
			name:      "IPv4_192_0_2_255",
			prefix:    "192-0-2-255",
			qtype:     dns.TypeA,
			wantValid: true,
			wantIP:    "192.0.2.255",
		},
		{
			name:      "IPv4_198_51_100_1",
			prefix:    "198-51-100-1",
			qtype:     dns.TypeA,
			wantValid: true,
			wantIP:    "198.51.100.1",
		},
		{
			name:      "IPv4_203_0_113_42",
			prefix:    "203-0-113-42",
			qtype:     dns.TypeA,
			wantValid: true,
			wantIP:    "203.0.113.42",
		},
		// IPv6 tests
		{
			name:      "Valid_IPv6_AAAA_Query",
			prefix:    "2001-db8--1",
			qtype:     dns.TypeAAAA,
			wantValid: true,
			wantIP:    "2001:db8::1",
		},
		{
			name:      "Valid_IPv6_A_Query",
			prefix:    "2001-db8--1",
			qtype:     dns.TypeA,
			wantValid: false,
		},
		{
			name:      "Invalid_IPv6_AAAA_Query",
			prefix:    "2001-db8-xyz-1",
			qtype:     dns.TypeAAAA,
			wantValid: false,
		},
		// Additional IPv6 patterns
		{
			name:      "IPv6_0_double_dash_1",
			prefix:    "0--1",
			qtype:     dns.TypeAAAA,
			wantValid: true,
			wantIP:    "::1",
		},
		{
			name:      "IPv6_double_dash_1",
			prefix:    "--1",
			qtype:     dns.TypeAAAA,
			wantValid: true,
			wantIP:    "::1",
		},
		{
			name:      "IPv6_2001_db8_double_dash",
			prefix:    "2001-db8--",
			qtype:     dns.TypeAAAA,
			wantValid: true,
			wantIP:    "2001:db8::",
		},
		{
			name:      "IPv6_2001_db8_double_dash_0",
			prefix:    "2001-db8--0",
			qtype:     dns.TypeAAAA,
			wantValid: true,
			wantIP:    "2001:db8::",
		},
		{
			name:      "IPv6_2001_db8_0_0_0_0_0_1",
			prefix:    "2001-db8-0-0-0-0-0-1",
			qtype:     dns.TypeAAAA,
			wantValid: true,
			wantIP:    "2001:db8::1",
		},
		{
			name:      "IPv6_2001_db8_double_dash_1_2",
			prefix:    "2001-db8--1-2",
			qtype:     dns.TypeAAAA,
			wantValid: true,
			wantIP:    "2001:db8::1:2",
		},
		{
			name:      "IPv6_2001_db8_85a3_0000_0000_8a2e_0370_7334",
			prefix:    "2001-db8-85a3-0000-0000-8a2e-0370-7334",
			qtype:     dns.TypeAAAA,
			wantValid: true,
			wantIP:    "2001:db8:85a3::8a2e:370:7334",
		},
		{
			name:      "IPv6_2001_db8_85a3_double_dash_8a2e",
			prefix:    "2001-db8-85a3--8a2e",
			qtype:     dns.TypeAAAA,
			wantValid: true,
			wantIP:    "2001:db8:85a3::8a2e",
		},
		{
			name:      "IPv6_2001_db8_double_dash_8a2e_370_7334",
			prefix:    "2001-db8--8a2e-370-7334",
			qtype:     dns.TypeAAAA,
			wantValid: true,
			wantIP:    "2001:db8::8a2e:370:7334",
		},
		{
			name:      "IPv6_2001_db8_double_dash_a_b",
			prefix:    "2001-db8--a-b",
			qtype:     dns.TypeAAAA,
			wantValid: true,
			wantIP:    "2001:db8::a:b",
		},
		{
			name:      "IPv6_fe80_double_dash_1",
			prefix:    "fe80--1",
			qtype:     dns.TypeAAAA,
			wantValid: true,
			wantIP:    "fe80::1",
		},
		// Unsupported query types
		{
			name:      "TXT_Query",
			prefix:    "192-168-1-1",
			qtype:     dns.TypeTXT,
			wantValid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip, err := parseIPFromPrefix(tt.prefix, tt.qtype)

			if tt.wantValid {
				if err != nil {
					t.Errorf("parseIPFromPrefix() unexpected error: %v", err)
					return
				}
				if ip.String() != tt.wantIP {
					t.Errorf("parseIPFromPrefix() got IP %v, want %v", ip.String(), tt.wantIP)
				}
			} else {
				if err == nil {
					t.Errorf("parseIPFromPrefix() expected error but got IP: %v", ip)
				}
			}
		})
	}
}
