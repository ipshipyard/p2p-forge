package acme

import (
	"context"
	"strings"
	"time"

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

const ttl = 1 * time.Hour

// ServeDNS implements the plugin.Handler interface.
func (p acmeReader) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	var answers []dns.RR
	for _, q := range r.Question {
		if q.Qtype != dns.TypeTXT && q.Qtype != dns.TypeANY {
			continue
		}

		subdomain := strings.TrimSuffix(q.Name, "."+p.ForgeDomain+".")
		if len(subdomain) == len(q.Name) || len(subdomain) == 0 {
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

		const acmeSubdomain = "_acme-challenge"
		prefix := domainSegments[0]
		if prefix != acmeSubdomain {
			continue
		}

		val, err := p.Datastore.Get(ctx, datastore.NewKey(peerID.String()))
		if err != nil {
			continue
		}

		answers = append(answers, &dns.TXT{
			Hdr: dns.RR_Header{
				Name:   dns.Fqdn(q.Name),
				Rrtype: dns.TypeTXT,
				Class:  dns.ClassINET,
				Ttl:    uint32(ttl.Seconds()),
			},
			Txt: []string{string(val)},
		})
	}

	if len(answers) > 0 {
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
