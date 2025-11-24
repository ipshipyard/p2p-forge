package ipparser

import (
	"context"
	"net"
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
		// Zone identifier rejection tests (RFC 1035 compliance)
		{
			name:      "IPv6_with_zone_id_rejected",
			prefix:    "--1%eth0",
			qtype:     dns.TypeAAAA,
			wantValid: false, // Zone IDs not allowed in DNS labels
		},
		{
			name:      "IPv6_with_zone_id_numeric",
			prefix:    "fe80--1%1",
			qtype:     dns.TypeAAAA,
			wantValid: false, // Zone IDs not allowed
		},
		{
			name:      "IPv6_zone_with_control_char",
			prefix:    "--1%\x00",
			qtype:     dns.TypeAAAA,
			wantValid: false, // Zone IDs with null bytes rejected
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

// TestACMEChallengeIgnored tests that _acme-challenge domains are ignored by ipparser
func TestACMEChallengeIgnored(t *testing.T) {
	tests := []struct {
		name   string
		domain string
		qtype  uint16
	}{
		{
			name:   "TXT_acme_challenge",
			domain: "_acme-challenge.k51qzi5uqu5dj2c294cab64yiq2ri684kc5sr9odfhoo84osl4resldwfy8u5r.libp2p.direct",
			qtype:  dns.TypeTXT,
		},
		{
			name:   "A_acme_challenge",
			domain: "_acme-challenge.k51qzi5uqu5dj2c294cab64yiq2ri684kc5sr9odfhoo84osl4resldwfy8u5r.libp2p.direct",
			qtype:  dns.TypeA,
		},
		{
			name:   "AAAA_acme_challenge",
			domain: "_acme-challenge.k51qzi5uqu5dj2c294cab64yiq2ri684kc5sr9odfhoo84osl4resldwfy8u5r.libp2p.direct",
			qtype:  dns.TypeAAAA,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a test ipParser instance
			parser := ipParser{
				Next:        nil, // No next plugin
				ForgeDomain: "libp2p.direct",
				SOA:         nil,
			}

			// Create DNS message
			req := new(dns.Msg)
			req.Question = []dns.Question{
				{Name: tt.domain, Qtype: tt.qtype, Qclass: dns.ClassINET},
			}

			// Create test response writer
			w := &testResponseWriter{}

			// Call ServeDNS
			rcode, err := parser.ServeDNS(context.Background(), w, req)

			// _acme-challenge domains should be ignored (passed to next plugin)
			// Since we have no next plugin, this should result in calling the next plugin
			// which will return the "no next plugin" behavior
			if rcode != dns.RcodeServerFailure || err == nil {
				// If there was no next plugin, we expect this to be handled by plugin.NextOrFailure
				// which returns SERVFAIL when there's no next plugin
				t.Logf("Expected _acme-challenge domain to be ignored by ipparser and passed to next plugin")

				// The key test is that ipparser didn't handle it (didn't return success with answers)
				if w.msg != nil && len(w.msg.Answer) > 0 {
					t.Errorf("ipparser should not have generated answers for _acme-challenge domain")
				}
			}
		})
	}
}

// testResponseWriter is a simple test implementation of dns.ResponseWriter
type testResponseWriter struct {
	msg *dns.Msg
}

func (w *testResponseWriter) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53}
}

func (w *testResponseWriter) RemoteAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}
}

func (w *testResponseWriter) WriteMsg(msg *dns.Msg) error {
	w.msg = msg
	return nil
}

func (w *testResponseWriter) Write([]byte) (int, error) {
	return 0, nil
}

func (w *testResponseWriter) Close() error {
	return nil
}

func (w *testResponseWriter) TsigStatus() error {
	return nil
}

func (w *testResponseWriter) TsigTimersOnly(bool) {}

func (w *testResponseWriter) Hijack() {}
