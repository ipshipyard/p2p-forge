package acme

import (
	"context"
	"strings"

	"github.com/coredns/coredns/plugin"
	"github.com/ipfs/go-datastore"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/miekg/dns"
)

type acmeReader struct {
	Next        plugin.Handler
	ForgeDomain string
	Datastore   datastore.Datastore
}

const (
	// Subdomain used for DNS-01 challenge
	acmeSubdomain = "_acme-challenge"

	// The TTL for the _acme-challenge TXT record is as short as possible
	txtTTL = uint32(10) // seconds

	// TXT value returned when broker has no DNS-01 value yet
	DNS01NotSetValue = "not set yet"
)

// ServeDNS implements the plugin.Handler interface.
func (p acmeReader) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	var answers []dns.RR
	containsNODATAResponse := false
	for _, q := range r.Question {
		normalizedName := strings.ToLower(q.Name)
		subdomain := strings.TrimSuffix(normalizedName, "."+p.ForgeDomain+".")
		if len(subdomain) == len(normalizedName) || len(subdomain) == 0 {
			continue
		}

		domainSegments := strings.Split(subdomain, ".")
		if len(domainSegments) != 2 {
			continue
		}

		peerIDStr := domainSegments[1]
		peerID, err := peer.Decode(peerIDStr)
		if err != nil {
			continue
		}

		prefix := domainSegments[0]
		if prefix != acmeSubdomain {
			continue
		}

		if q.Qtype != dns.TypeTXT && q.Qtype != dns.TypeANY {
			containsNODATAResponse = true
			dns01ResponseCount.WithLabelValues("NODATA-" + dnsToString(q.Qtype)).Add(1)
			continue
		}

		val, err := p.Datastore.Get(ctx, datastore.NewKey(peerID.String()))
		if err != nil || len(val) == 0 {
			// return "empty" TXT record to have control over TTL that does not depend on minimal TTL from SOA
			// (avoiding issue described in https://github.com/ipshipyard/p2p-forge/issues/52)
			answers = append(answers, &dns.TXT{
				Hdr: dns.RR_Header{
					Name:   dns.Fqdn(q.Name),
					Rrtype: dns.TypeTXT,
					Class:  dns.ClassINET,
					Ttl:    txtTTL,
				},
				Txt: []string{DNS01NotSetValue},
			})
			// track "empty" TXT separately from NODATA (we do return a record, but DNS-01 value is not set yet)
			dns01ResponseCount.WithLabelValues("TXT-EMPTY").Add(1)
			continue
		}

		answers = append(answers, &dns.TXT{
			Hdr: dns.RR_Header{
				Name:   dns.Fqdn(q.Name),
				Rrtype: dns.TypeTXT,
				Class:  dns.ClassINET,
				Ttl:    txtTTL,
			},
			Txt: []string{string(val)},
		})
		dns01ResponseCount.WithLabelValues("TXT").Add(1)
	}

	if len(answers) > 0 || containsNODATAResponse {
		var m dns.Msg
		m.SetReply(r)
		m.Authoritative = true
		m.Answer = answers
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
func (p acmeReader) Name() string { return pluginName }
