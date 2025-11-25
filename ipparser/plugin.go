package ipparser

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	"github.com/miekg/dns"

	"github.com/ipshipyard/p2p-forge/denylist"
	"github.com/libp2p/go-libp2p/core/peer"
)

const pluginName = "ipparser"

func init() { plugin.Register(pluginName, setup) }

func setup(c *caddy.Controller) error {
	c.Next()

	var forgeDomain string
	if c.NextArg() {
		forgeDomain = c.Val()
	}

	config := dnsserver.GetConfig(c)

	// Read SOA from zone/{forgeDomain} file
	var soa *dns.SOA
	zoneFile := filepath.Join(config.Root, "zones", forgeDomain)
	f, err := os.Open(filepath.Clean(zoneFile))
	if err != nil {
		return plugin.Error(pluginName, fmt.Errorf("failed to open zone file %s: %v", zoneFile, err))
	}
	defer f.Close()
	zp := dns.NewZoneParser(f, forgeDomain+".", zoneFile)
	for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
		if s, ok := rr.(*dns.SOA); ok {
			soa = s
			break
		}
	}
	soaRR := []dns.RR{
		&dns.SOA{
			Hdr: dns.RR_Header{
				Name:   dns.Fqdn(forgeDomain + "."),
				Rrtype: dns.TypeSOA,
				Class:  dns.ClassINET,
				Ttl:    soa.Hdr.Ttl,
			},
			Ns:      soa.Ns,
			Mbox:    soa.Mbox,
			Serial:  soa.Serial,
			Refresh: soa.Refresh,
			Retry:   soa.Retry,
			Expire:  soa.Expire,
			Minttl:  soa.Minttl,
		},
	}

	p := &ipParser{
		ForgeDomain: strings.ToLower(forgeDomain),
		SOA:         soaRR,
		// Denylist reference is captured at setup time. If the denylist plugin
		// is reconfigured, this reference becomes stale. This is acceptable
		// because CoreDNS plugin reconfiguration requires a full server restart.
		Denylist: denylist.GetManager(),
	}

	// Add the Plugin to CoreDNS, so Servers can use it in their plugin chain.
	config.AddPlugin(func(next plugin.Handler) plugin.Handler {
		p.Next = next
		return p
	})

	return nil
}

type ipParser struct {
	Next        plugin.Handler
	ForgeDomain string
	SOA         []dns.RR          // Cached SOA record from zone file
	Denylist    *denylist.Manager // Optional IP denylist (nil if not configured)
}

// The TTL for self-referential ip.peerid.etld A/AAAA records can be as long as possible.
// We will be increasing this over time, as infrastructure ossifies.
const ttl = 7 * 24 * time.Hour

// ServeDNS implements the plugin.Handler interface.
func (p *ipParser) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	var answers []dns.RR
	containsNODATAResponse := false
	for _, q := range r.Question {
		normalizedName := strings.ToLower(q.Name)
		subdomain := strings.TrimSuffix(normalizedName, "."+p.ForgeDomain+".")
		if len(subdomain) == len(normalizedName) || len(subdomain) == 0 {
			continue
		}

		domainSegments := strings.Split(subdomain, ".")
		if len(domainSegments) > 2 {
			continue
		}

		peerIDStr := domainSegments[len(domainSegments)-1]

		_, err := peer.Decode(peerIDStr)
		if err != nil {
			continue
		}

		// Need to handle <peerID>.forgeDomain to return NODATA rather than NXDOMAIN per https://datatracker.ietf.org/doc/html/rfc8020
		if len(domainSegments) == 1 {
			containsNODATAResponse = true
			dynamicResponseCount.WithLabelValues("NODATA-PEERID-" + dnsToString(q.Qtype)).Add(1)
			continue
		}

		prefix := domainSegments[0]

		// Skip ACME challenge domains - let them pass through to acme plugin
		if strings.HasPrefix(prefix, "_acme-challenge") {
			continue
		}

		// Only handle A and AAAA queries - return NODATA for other query types on IP domains
		if q.Qtype != dns.TypeA && q.Qtype != dns.TypeAAAA {
			containsNODATAResponse = true
			dynamicResponseCount.WithLabelValues("NODATA-" + dnsToString(q.Qtype)).Add(1)
			continue
		}

		// Parse IP based on query type - parseIPFromPrefix handles all validation
		ip, err := parseIPFromPrefix(prefix, q.Qtype)
		if err != nil {
			// For invalid IPs, return NODATA
			containsNODATAResponse = true
			dynamicResponseCount.WithLabelValues("NODATA-" + dnsToString(q.Qtype)).Add(1)
			continue
		}

		// Check denylist (allowlists checked first internally)
		if p.Denylist != nil {
			if denied, result := p.Denylist.Check(ip); denied {
				containsNODATAResponse = true
				dynamicResponseCount.WithLabelValues("DENIED-" + result.Name).Add(1)
				continue
			}
		}

		switch q.Qtype {
		case dns.TypeA:
			answers = append(answers, &dns.A{
				Hdr: dns.RR_Header{
					Name:   dns.Fqdn(q.Name),
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    uint32(ttl.Seconds()),
				},
				A: ip.AsSlice(),
			})
			dynamicResponseCount.WithLabelValues("A").Add(1)

		case dns.TypeAAAA:
			answers = append(answers, &dns.AAAA{
				Hdr: dns.RR_Header{
					Name:   dns.Fqdn(q.Name),
					Rrtype: dns.TypeAAAA,
					Class:  dns.ClassINET,
					Ttl:    uint32(ttl.Seconds()),
				},
				AAAA: ip.AsSlice(),
			})
			dynamicResponseCount.WithLabelValues("AAAA").Add(1)
		}
	}

	if len(answers) > 0 || containsNODATAResponse {
		var m dns.Msg
		m.SetReply(r)
		m.Authoritative = true
		m.Answer = answers

		// RFC 2308 Compliance: NODATA responses (NOERROR with no answers)
		// should include an SOA in the AUTHORITY section to specify the
		// negative caching TTL (https://github.com/ipshipyard/p2p-forge/issues/52).
		if containsNODATAResponse {
			m.Ns = p.SOA
		}

		err := w.WriteMsg(&m)
		if err != nil {
			return dns.RcodeServerFailure, err
		}
		return dns.RcodeSuccess, nil
	}

	// Call next plugin (if any).
	return plugin.NextOrFailure(p.Name(), p.Next, ctx, w, r)
}

// Name implements the Handler interface.
func (p *ipParser) Name() string { return pluginName }

// parseIPFromPrefix converts a DNS prefix to an IP address based on query type
func parseIPFromPrefix(prefix string, qtype uint16) (netip.Addr, error) {
	segments := strings.Split(prefix, "-")

	switch qtype {
	case dns.TypeA:
		ipStr := strings.Join(segments, ".")
		if ip, err := netip.ParseAddr(ipStr); err == nil && ip.Is4() {
			return ip, nil
		}
		return netip.Addr{}, fmt.Errorf("invalid IPv4 address: %s", ipStr)

	case dns.TypeAAAA:
		ipStr := strings.Join(segments, ":")
		if ip, err := netip.ParseAddr(ipStr); err == nil && ip.Is6() {
			// Zone IDs like %eth0 can't appear in DNS labels (RFC 1035).
			// While netip.ParseAddr already rejects them, this check provides
			// defense if parsing behavior changes or malformed input gets through.
			if strings.Contains(ip.String(), "%") {
				return netip.Addr{}, errors.New("zone identifiers not allowed in DNS labels")
			}
			return ip, nil
		}
		return netip.Addr{}, fmt.Errorf("invalid IPv6 address: %s", ipStr)

	default:
		return netip.Addr{}, fmt.Errorf("unsupported query type: %d", qtype)
	}
}
