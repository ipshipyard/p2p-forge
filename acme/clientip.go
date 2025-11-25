package acme

import (
	"net"
	"net/http"
	"net/netip"
	"strings"

	"github.com/multiformats/go-multiaddr"
)

// clientIPs extracts client IPs from request: both X-Forwarded-For and RemoteAddr.
// Returns all valid IPs found (may be 0, 1, or 2 IPs).
//
// X-Forwarded-For spoofing is not a security concern here because:
//  1. We also check all IPs from the multiaddrs in the request body
//  2. The actual A/AAAA record being requested must match a multiaddr IP
//  3. An attacker cannot spoof the multiaddr IPs they're connecting from
//
// The client IP check is defense-in-depth; the multiaddr check is authoritative.
func clientIPs(r *http.Request) []netip.Addr {
	var ips []netip.Addr

	// Check X-Forwarded-For (leftmost = original client)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if comma := strings.Index(xff, ","); comma != -1 {
			xff = xff[:comma]
		}
		xff = strings.TrimSpace(xff)
		if ip, err := netip.ParseAddr(xff); err == nil {
			ips = append(ips, ip)
		}
	}

	// Also check RemoteAddr (direct connection IP)
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		ips = append(ips, ip)
	}

	return ips
}

// multiaddrsToIPs extracts IP addresses from multiaddr strings.
func multiaddrsToIPs(addrs []string) []netip.Addr {
	ips := make([]netip.Addr, 0, len(addrs))
	for _, addr := range addrs {
		ma, err := multiaddr.NewMultiaddr(addr)
		if err != nil {
			continue
		}
		// Try IPv4
		if val, err := ma.ValueForProtocol(multiaddr.P_IP4); err == nil {
			if ip, err := netip.ParseAddr(val); err == nil {
				ips = append(ips, ip)
				continue
			}
		}
		// Try IPv6
		if val, err := ma.ValueForProtocol(multiaddr.P_IP6); err == nil {
			if ip, err := netip.ParseAddr(val); err == nil {
				ips = append(ips, ip)
			}
		}
	}
	return ips
}
