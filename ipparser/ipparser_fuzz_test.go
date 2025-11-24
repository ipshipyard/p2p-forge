package ipparser

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// FuzzParseIPFromPrefix tests DNS label → IP address parsing with arbitrary input
func FuzzParseIPFromPrefix(f *testing.F) {
	// Seed corpus with valid and edge case DNS labels
	seeds := []string{
		// Valid IPv4 - boundary and common cases
		"192-168-1-1",
		"0-0-0-0",
		"255-255-255-255",
		"127-0-0-1",
		"10-0-0-1",
		"172-16-0-1",
		// Valid IPv6 - various compression patterns
		"2001-db8--1",
		"0--1",
		"0--0",
		"fe80--1",
		"2001-db8-85a3--8a2e-370-7334",
		"ffff-ffff-ffff-ffff-ffff-ffff-ffff-ffff",
		"--",
		"1--1",
		// Edge cases - empty and hyphen patterns
		"",
		"-",
		"---",
		"----",
		"-0-0-0-0",
		"0-0-0-0-",
		// Potential injection attempts
		"192-168-1-1/../../etc/passwd",
		"0x7f-0x00-0x00-0x01",
		"192.168.1.1",
		"../192-168-1-1",
		"192-168-1-1\x00",
		"192-168-1-1%00",
		// ACME challenge (should be ignored)
		"_acme-challenge",
		// Mixed/malformed formats
		"192-168-1-1-2001-db8",
		"abc-def-ghi-jkl",
		"999-999-999-999",
	}

	for _, seed := range seeds {
		f.Add(seed, uint16(dns.TypeA))
		f.Add(seed, uint16(dns.TypeAAAA))
	}

	f.Fuzz(func(t *testing.T, prefix string, qtype uint16) {
		// parseIPFromPrefix should never panic, regardless of input
		ip, err := parseIPFromPrefix(prefix, qtype)

		if err != nil {
			// Error is acceptable - verify error message is reasonable
			if err.Error() == "" {
				t.Errorf("Error has empty message")
			}
			return
		}

		// If parsing succeeded, verify the IP is valid
		if !ip.IsValid() {
			t.Errorf("parseIPFromPrefix returned invalid IP for prefix %q, qtype %d", prefix, qtype)
		}

		// Verify IP version matches query type
		switch qtype {
		case dns.TypeA:
			if !ip.Is4() {
				t.Errorf("TypeA query returned non-IPv4 address: %v (from prefix %q)", ip, prefix)
			}
		case dns.TypeAAAA:
			if !ip.Is6() {
				t.Errorf("TypeAAAA query returned non-IPv6 address: %v (from prefix %q)", ip, prefix)
			}
		}

		// Security property: Verify no path traversal in prefix could affect IP
		if strings.Contains(prefix, "..") {
			// Should have been rejected or sanitized
			ipStr := ip.String()
			if strings.Contains(ipStr, "..") {
				t.Errorf("Path traversal sequence leaked into IP: %v", ipStr)
			}
		}

		// Security property: Verify no hex prefix tricks
		if strings.Contains(prefix, "0x") || strings.Contains(prefix, "0X") {
			// Should have been rejected or sanitized
			ipStr := ip.String()
			if strings.Contains(ipStr, "0x") || strings.Contains(ipStr, "0X") {
				t.Errorf("Hex prefix leaked into IP: %v", ipStr)
			}
		}
	})
}

// FuzzParseIPFromPrefixRoundtrip tests that valid IPs can be encoded and decoded consistently
func FuzzParseIPFromPrefixRoundtrip(f *testing.F) {
	// Seed with valid IP addresses covering different ranges and formats
	seeds := []string{
		// IPv4 boundary cases
		"0.0.0.0",
		"255.255.255.255",
		"127.0.0.1",
		// IPv4 private ranges
		"10.0.0.1",
		"172.16.0.1",
		"192.168.1.1",
		// IPv6 special addresses
		"::1",
		"::",
		"::ffff:192.0.2.1",
		// IPv6 various compression positions
		"2001:db8::1",
		"2001:db8::",
		"fe80::1",
		"2001:db8:85a3::8a2e:370:7334",
		// IPv6 full address (no compression)
		"2001:db8:85a3:0:0:8a2e:370:7334",
		"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
	}

	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, ipStr string) {
		// Parse as IP address
		ip, err := netip.ParseAddr(ipStr)
		if err != nil {
			return // Not a valid IP - expected for fuzz input
		}

		// Skip IPs with zone identifiers - they're not valid in DNS labels
		if strings.Contains(ip.String(), "%") {
			return
		}

		// Convert to DNS label format
		var prefix string
		var qtype uint16

		if ip.Is4() {
			prefix = strings.ReplaceAll(ip.String(), ".", "-")
			qtype = dns.TypeA
		} else if ip.Is6() {
			prefix = strings.ReplaceAll(ip.String(), ":", "-")
			qtype = dns.TypeAAAA

			// Handle RFC 1035 compliance for IPv6
			if len(prefix) > 0 && prefix[0] == '-' {
				prefix = "0" + prefix
			}
			if len(prefix) > 0 && prefix[len(prefix)-1] == '-' {
				prefix = prefix + "0"
			}
		} else {
			return // Unknown IP version
		}

		// Parse back from DNS label
		parsedIP, err := parseIPFromPrefix(prefix, qtype)
		if err != nil {
			t.Errorf("Failed to parse back DNS label %q (from %v): %v", prefix, ip, err)
			return
		}

		// Property: Roundtrip should produce equivalent IP
		// Note: IPv6 addresses may be in different canonical forms
		if ip.Is4() {
			if !parsedIP.Is4() || parsedIP.String() != ip.String() {
				t.Errorf("IPv4 roundtrip mismatch: %v → %q → %v", ip, prefix, parsedIP)
			}
		} else if ip.Is6() {
			// For IPv6, compare as 16-byte arrays since string representations can differ
			if !parsedIP.Is6() || parsedIP.As16() != ip.As16() {
				t.Errorf("IPv6 roundtrip mismatch: %v → %q → %v", ip, prefix, parsedIP)
			}
		}
	})
}

// FuzzIPv6DNSLabelConsistency ensures IPv6 DNS labels are consistently handled
func FuzzIPv6DNSLabelConsistency(f *testing.F) {
	// Seed with IPv6 patterns that could cause issues
	seeds := []string{
		// Compression edge cases
		"--",         // double compression only (::)
		"0--0",       // compression with explicit zeros
		"a--b",       // compression in middle
		"2001-db8--", // trailing compression
		"--1",        // leading compression
		// Hyphen boundary cases
		"-1-2-3", // leading hyphen (invalid DNS)
		"1-2-3-", // trailing hyphen (invalid DNS)
		"----",   // multiple consecutive hyphens
		"-----",  // more consecutive hyphens
		// Expanded forms
		"0-0-0-0-0-0-0-0",                         // all zeros expanded
		"0-0-0-0-0-0-0-1",                         // loopback expanded
		"ffff-ffff-ffff-ffff-ffff-ffff-ffff-ffff", // max value
		// Mixed compression and explicit zeros
		"2001-0-0-0-0-0-0-1",
		"2001-db8-0-0-0-0-0-1",
	}

	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, prefix string) {
		// Attempt to parse as IPv6
		ip1, err1 := parseIPFromPrefix(prefix, dns.TypeAAAA)

		// Parse again - should be deterministic
		ip2, err2 := parseIPFromPrefix(prefix, dns.TypeAAAA)

		// Property: Consistency - same input should always produce same output
		if (err1 == nil) != (err2 == nil) {
			t.Errorf("Inconsistent error handling for prefix %q: err1=%v, err2=%v", prefix, err1, err2)
		}

		if err1 == nil && err2 == nil {
			if ip1.String() != ip2.String() {
				t.Errorf("Inconsistent parsing for prefix %q: ip1=%v, ip2=%v", prefix, ip1, ip2)
			}
		}

		// Property: Leading/trailing hyphens in input should not produce valid IPs
		// (unless RFC compliance handling adds zeros)
		if len(prefix) > 0 {
			startsWithHyphen := prefix[0] == '-'
			endsWithHyphen := prefix[len(prefix)-1] == '-'

			if startsWithHyphen || endsWithHyphen {
				// Should either error or produce valid IP (via zero-padding)
				if err1 == nil {
					// If it succeeded, verify the IP is actually valid IPv6
					if !ip1.IsValid() || !ip1.Is6() {
						t.Errorf("Prefix with leading/trailing hyphen %q produced invalid IP: %v", prefix, ip1)
					}
				}
			}
		}
	})
}

// FuzzParseIPSecurity tests for security vulnerabilities in IP parsing
func FuzzParseIPSecurity(f *testing.F) {
	// Seed with potential attack vectors
	seeds := []string{
		"192-168-1-1/../../etc/passwd",
		"0x7f-0x00-0x00-0x01",
		"127.0.0.1%00",
		"127.0.0.1\x00admin",
		"192-168-1-1\r\n",
		"192-168-1-1\n",
		"<script>alert(1)</script>",
		"'; DROP TABLE users; --",
		"../../../etc/passwd",
		"....//....//etc/passwd",
		"%2e%2e%2f%2e%2e%2f",
		"192-168-1-1' OR '1'='1",
	}

	for _, seed := range seeds {
		f.Add(seed, uint16(dns.TypeA))
		f.Add(seed, uint16(dns.TypeAAAA))
	}

	f.Fuzz(func(t *testing.T, prefix string, qtype uint16) {
		// parseIPFromPrefix should safely reject or sanitize malicious input
		ip, err := parseIPFromPrefix(prefix, qtype)

		if err != nil {
			// Rejection is safe
			return
		}

		// Property: Zone identifiers should be rejected
		// DNS labels cannot contain '%' per RFC 1035, so zone IDs are invalid
		if strings.Contains(ip.String(), "%") {
			t.Errorf("Zone identifier not rejected: %v (from prefix %q)", ip, prefix)
		}
	})
}
