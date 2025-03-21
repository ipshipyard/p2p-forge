package ipparser

import (
	"context"
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
	if c.NextArg() {
		// If there was another token, return an error, because we don't have any configuration.
		// Any errors returned from this setup function should be wrapped with plugin.Error, so we
		// can present a slightly nicer error message to the user.
		return plugin.Error(pluginName, c.ArgErr())
	}

	// Read SOA from zone/{forgeDomain} file
	var soa *dns.SOA
	config := dnsserver.GetConfig(c)
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

	// Add the Plugin to CoreDNS, so Servers can use it in their plugin chain.
	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		return ipParser{Next: next, ForgeDomain: strings.ToLower(forgeDomain), SOA: soa}
	})

	return nil
}

type ipParser struct {
	Next        plugin.Handler
	ForgeDomain string
	SOA         *dns.SOA // Cached SOA record from zone file
}

// The TTL for self-referential ip.peerid.etld A/AAAA records can be as long as possible.
// We will be increasing this over time, as infrastructure ossifies.
const ttl = 7 * 24 * time.Hour

// ServeDNS implements the plugin.Handler interface.
func (p ipParser) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
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
		segments := strings.Split(prefix, "-")
		if len(segments) == 4 {
			ipStr := strings.Join(segments, ".")
			ip, err := netip.ParseAddr(ipStr)
			if err != nil {
				continue
			}

			// Need to handle <ipv4>.<peerID>.forgeDomain to return NODATA rather than NXDOMAIN per https://datatracker.ietf.org/doc/html/rfc8020
			if !(q.Qtype == dns.TypeA || q.Qtype == dns.TypeANY) {
				containsNODATAResponse = true
				dynamicResponseCount.WithLabelValues("NODATA-" + dnsToString(q.Qtype)).Add(1)
				continue
			}

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
			continue
		}

		// - is not a valid first or last character https://datatracker.ietf.org/doc/html/rfc1123#section-2
		if prefix[0] == '-' || prefix[len(prefix)-1] == '-' {
			continue
		}

		prefixAsIpv6 := strings.Join(segments, ":")
		ip, err := netip.ParseAddr(prefixAsIpv6)
		if err != nil {
			continue
		}

		if !(q.Qtype == dns.TypeAAAA || q.Qtype == dns.TypeANY) {
			containsNODATAResponse = true
			dynamicResponseCount.WithLabelValues("NODATA-" + dnsToString(q.Qtype)).Add(1)
			continue
		}

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

	if len(answers) > 0 || containsNODATAResponse {
		var m dns.Msg
		m.SetReply(r)
		m.Authoritative = true
		m.Answer = answers

		// RFC 2308 Compliance: NODATA responses (NOERROR with no answers)
		// should include an SOA in the AUTHORITY section to specify the
		// negative caching TTL (https://github.com/ipshipyard/p2p-forge/issues/52).
		if containsNODATAResponse {
			m.Ns = []dns.RR{
				&dns.SOA{
					Hdr: dns.RR_Header{
						Name:   dns.Fqdn(p.ForgeDomain + "."),
						Rrtype: dns.TypeSOA,
						Class:  dns.ClassINET,
						Ttl:    p.SOA.Hdr.Ttl,
					},
					Ns:      p.SOA.Ns,
					Mbox:    p.SOA.Mbox,
					Serial:  p.SOA.Serial,
					Refresh: p.SOA.Refresh,
					Retry:   p.SOA.Retry,
					Expire:  p.SOA.Expire,
					Minttl:  p.SOA.Minttl,
				},
			}
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
func (p ipParser) Name() string { return pluginName }
