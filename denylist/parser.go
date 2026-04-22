package denylist

import (
	"bufio"
	"io"
	"net/netip"
	"net/url"
	"strings"
)

// addrToPrefix converts a single IP address to a host prefix (/32 or /128).
func addrToPrefix(ip netip.Addr) netip.Prefix {
	bits := 32
	if ip.Is6() {
		bits = 128
	}
	return netip.PrefixFrom(ip, bits)
}

// parseIP parses content in IP format: one IP or CIDR per line.
// Lines starting with # or ; are comments. Empty lines are skipped.
// Used for Spamhaus DROP, FireHOL, and custom lists.
func parseIP(r io.Reader) ([]netip.Prefix, error) {
	var prefixes []netip.Prefix
	scanner := bufio.NewScanner(r)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}

		// Handle inline comments (some lists have "1.2.3.0/24 ; SBL123456")
		if idx := strings.IndexAny(line, ";#"); idx != -1 {
			line = strings.TrimSpace(line[:idx])
		}

		// Try parsing as CIDR first
		if prefix, err := netip.ParsePrefix(line); err == nil {
			prefixes = append(prefixes, prefix)
			continue
		}

		// Try parsing as single IP (convert to /32 or /128)
		if ip, err := netip.ParseAddr(line); err == nil {
			prefixes = append(prefixes, addrToPrefix(ip))
		}
		// Skip unparseable lines silently
	}

	return prefixes, scanner.Err()
}

// parseURLOptions configures URL parsing behavior.
type parseURLOptions struct {
	// ForgeSuffix is the forge domain suffix (e.g., "libp2p.direct").
	// If set, domains matching this suffix have their IP extracted directly
	// from the subdomain (e.g., "192-168-1-1.peerid.libp2p.direct" -> 192.168.1.1).
	ForgeSuffix string
}

// parseURL parses content in URL format: one URL per line.
// Extracts IPs directly from URL hosts. Domain names are skipped because:
// - Domain→IP mappings change frequently (stale cache)
// - Shared hosting IPs cause false positives
// - p2p-forge only blocks by IP, not domain
// Lines starting with # are comments. Used for URLhaus and similar feeds.
func parseURL(r io.Reader, opts parseURLOptions) ([]netip.Prefix, error) {
	// Normalize forge suffix
	forgeSuffix := strings.ToLower(opts.ForgeSuffix)
	if forgeSuffix != "" && !strings.HasPrefix(forgeSuffix, ".") {
		forgeSuffix = "." + forgeSuffix
	}

	seen := make(map[netip.Addr]struct{})

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse as URL
		u, err := url.Parse(line)
		if err != nil {
			continue
		}

		host := strings.ToLower(u.Hostname())
		if host == "" {
			continue
		}

		// Case 1: Host is already an IP - use it
		if ip, err := netip.ParseAddr(host); err == nil {
			seen[ip.Unmap()] = struct{}{}
			continue
		}

		// Case 2: Host matches forge suffix - extract IP from subdomain
		if forgeSuffix != "" && strings.HasSuffix(host, forgeSuffix) {
			if ip, ok := parseForgeIP(host, forgeSuffix); ok {
				seen[ip.Unmap()] = struct{}{}
				continue
			}
		}

		// Case 3: Regular domain - skip (DNS resolution is unreliable for IP blocking)
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	// Convert to prefixes
	prefixes := make([]netip.Prefix, 0, len(seen))
	for ip := range seen {
		prefixes = append(prefixes, addrToPrefix(ip))
	}

	return prefixes, nil
}

// parseForgeIP extracts the IP address from a forge domain subdomain.
// For example: "192-168-1-1.peerid.libp2p.direct" -> 192.168.1.1
// Returns the IP and true if successful, or invalid IP and false otherwise.
func parseForgeIP(host, forgeSuffix string) (netip.Addr, bool) {
	// Verify suffix matches
	if !strings.HasSuffix(host, forgeSuffix) {
		return netip.Addr{}, false
	}

	// Remove the forge suffix to get "192-168-1-1.peerid"
	withoutSuffix := strings.TrimSuffix(host, forgeSuffix)

	// Split by "." to get subdomain parts
	parts := strings.Split(withoutSuffix, ".")
	if len(parts) < 1 {
		return netip.Addr{}, false
	}

	// The IP prefix is the first part (leftmost subdomain)
	ipPrefix := parts[0]

	// Try IPv4: replace "-" with "."
	ipv4Str := strings.ReplaceAll(ipPrefix, "-", ".")
	if ip, err := netip.ParseAddr(ipv4Str); err == nil && ip.Is4() {
		return ip, true
	}

	// Try IPv6: replace "-" with ":"
	// Handle RFC 1035 compliance: leading/trailing zeros may be added
	ipv6Str := strings.ReplaceAll(ipPrefix, "-", ":")

	// Remove leading "0" added for RFC 1035 compliance (e.g., "0::1" -> "::1")
	if strings.HasPrefix(ipv6Str, "0:") && len(ipv6Str) > 2 && ipv6Str[1] == ':' {
		ipv6Str = ipv6Str[1:]
	}
	// Remove trailing "0" added for RFC 1035 compliance (e.g., "2001::" -> "2001::")
	if strings.HasSuffix(ipv6Str, ":0") && len(ipv6Str) > 2 {
		trimmed := strings.TrimSuffix(ipv6Str, "0")
		// Only remove if it results in valid "::" ending
		if strings.HasSuffix(trimmed, ":") {
			ipv6Str = trimmed
		}
	}

	if ip, err := netip.ParseAddr(ipv6Str); err == nil && ip.Is6() {
		return ip, true
	}

	return netip.Addr{}, false
}

// parse dispatches to the appropriate parser based on format.
func parse(format feedFormat, r io.Reader, forgeSuffix string) ([]netip.Prefix, error) {
	switch format {
	case formatURL:
		return parseURL(r, parseURLOptions{ForgeSuffix: forgeSuffix})
	default:
		return parseIP(r)
	}
}
