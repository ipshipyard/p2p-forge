package acme

import (
	"net"
	"net/http"
	"net/netip"
	"strings"

	"github.com/multiformats/go-multiaddr"
)

// clientIPs returns the client IPs to check against the denylist: the direct
// connection address, plus the address from trustedHeader when the operator has
// configured one (e.g. CF-Connecting-IP behind Cloudflare).
//
// A leftmost X-Forwarded-For is never trusted: any client can forge it, which
// would let an attacker dodge an IP denylist entry or a per-IP rate limit. Only
// a header the deployment's proxy is known to set, named via the
// client-ip-header option, is honored.
func clientIPs(r *http.Request, trustedHeader string) []netip.Addr {
	var ips []netip.Addr

	if trustedHeader != "" {
		if v := strings.TrimSpace(r.Header.Get(trustedHeader)); v != "" {
			if ip, ok := parseHeaderIP(v); ok {
				ips = append(ips, ip)
			} else {
				// The proxy is expected to set a single IP here. A value we
				// cannot parse means the denylist would silently fall back to
				// the proxy's own address, so make the misconfiguration
				// visible instead.
				log.Warningf("%s header value %q is not an IP; ignoring it for the denylist", trustedHeader, v)
			}
		}
	}

	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		ips = append(ips, ip)
	}

	return ips
}

// parseHeaderIP parses a proxy-set client-IP header value, accepting either a
// bare IP or an "ip:port" pair (some proxies append the source port).
func parseHeaderIP(v string) (netip.Addr, bool) {
	if ip, err := netip.ParseAddr(v); err == nil {
		return ip, true
	}
	if ap, err := netip.ParseAddrPort(v); err == nil {
		return ap.Addr(), true
	}
	return netip.Addr{}, false
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
