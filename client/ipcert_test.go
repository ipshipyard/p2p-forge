package client

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/multiformats/go-multiaddr"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
)

const testIPCertPort = 443

func TestEligibleIPs(t *testing.T) {
	for _, tc := range []struct {
		name         string
		addrs        []string
		allowPrivate bool
		want         []string
	}{
		{
			name:  "public tcp listener on the ACME port",
			addrs: []string{"/ip4/1.2.3.4/tcp/443"},
			want:  []string{"1.2.3.4"},
		},
		{
			name:  "the same listener with a TLS WebSocket on top",
			addrs: []string{"/ip4/1.2.3.4/tcp/443/tls/sni/wildcard.libp2p.direct/ws"},
			want:  []string{"1.2.3.4"},
		},
		{
			name:  "IPv6 counts too",
			addrs: []string{"/ip6/2606:4700:4700::1111/tcp/443/tls/ws"},
			want:  []string{"2606:4700:4700::1111"},
		},
		{
			name:  "the IPv6 documentation range is not routable",
			addrs: []string{"/ip6/2001:db8::1/tcp/443/tls/ws"},
			want:  nil,
		},
		{
			name:  "a listener on any other port cannot be validated",
			addrs: []string{"/ip4/1.2.3.4/tcp/4001", "/ip4/1.2.3.4/tcp/8443/tls/ws"},
			want:  nil,
		},
		{
			name:  "QUIC is not a TCP listener",
			addrs: []string{"/ip4/1.2.3.4/udp/443/quic-v1"},
			want:  nil,
		},
		{
			name:  "private addresses are not reachable by a public CA",
			addrs: []string{"/ip4/192.168.1.10/tcp/443", "/ip4/127.0.0.1/tcp/443"},
			want:  nil,
		},
		{
			name:         "private addresses are allowed when opted in, for tests",
			addrs:        []string{"/ip4/127.0.0.1/tcp/443"},
			allowPrivate: true,
			want:         []string{"127.0.0.1"},
		},
		{
			name:  "relayed addresses are somebody else's",
			addrs: []string{"/ip4/1.2.3.4/tcp/443/p2p/12D3KooWFTiMTVAvVvJLQGVQEZLxVGnYnfKk8ZbDBrJUXvcQBrRs/p2p-circuit"},
			want:  nil,
		},
		{
			name:  "duplicates collapse to one address",
			addrs: []string{"/ip4/1.2.3.4/tcp/443", "/ip4/1.2.3.4/tcp/443/tls/ws"},
			want:  []string{"1.2.3.4"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			addrs := make([]multiaddr.Multiaddr, 0, len(tc.addrs))
			for _, s := range tc.addrs {
				addrs = append(addrs, multiaddr.StringCast(s))
			}
			got := eligibleIPs(addrs, testIPCertPort, tc.allowPrivate)
			if len(got) != len(tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
			for _, ip := range tc.want {
				if _, ok := got[ip]; !ok {
					t.Errorf("%s missing from %v", ip, got)
				}
			}
		})
	}
}

func TestTLSWSEndpoint(t *testing.T) {
	for _, tc := range []struct {
		addr string
		ip   string
		port int
		ok   bool
	}{
		{addr: "/ip4/1.2.3.4/tcp/443/tls/ws", ip: "1.2.3.4", port: 443, ok: true},
		{addr: "/ip4/1.2.3.4/tcp/443/tls/sni/wildcard.libp2p.direct/ws", ip: "1.2.3.4", port: 443, ok: true},
		{addr: "/ip4/1.2.3.4/tcp/443/wss", ip: "1.2.3.4", port: 443, ok: true},
		{addr: "/ip6/2001:db8::1/tcp/8443/tls/ws", ip: "2001:db8::1", port: 8443, ok: true},
		{addr: "/ip4/1.2.3.4/tcp/443/ws"},   // cleartext WebSocket, we have nothing to certify
		{addr: "/ip4/1.2.3.4/tcp/443"},      // plain TCP
		{addr: "/ip4/1.2.3.4/tcp/443/http"}, // no WebSocket
		{addr: "/dns4/example.com/tcp/443/tls/ws"},
	} {
		t.Run(tc.addr, func(t *testing.T) {
			ip, port, ok := tlsWSEndpoint(multiaddr.StringCast(tc.addr))
			if ok != tc.ok {
				t.Fatalf("ok = %v, want %v", ok, tc.ok)
			}
			if ok && (ip != tc.ip || port != tc.port) {
				t.Errorf("got %s:%d, want %s:%d", ip, port, tc.ip, tc.port)
			}
		})
	}
}

// A node holding its own certificate announces the address clients can dial
// with it, and never a brokered one for the same listener.
func TestAddrFactoryPrefersOurOwnCertificate(t *testing.T) {
	log := zaptest.NewLogger(t).Sugar()
	mgr := newTestIPCertMgr(t, log)
	cacheTestCert(t, mgr, "1.2.3.4")

	wssComponent := multiaddr.StringCast("/tls/sni/wildcard." + testForgeDomain + "/ws")
	got := addrFactoryFn(
		true, // skipForgeAddrs: no broker certificate, which is the point
		func() host.Host { return nil },
		testForgeDomain,
		true, // allowPrivateForgeAddrs
		true, // produceShortAddrs
		wssComponent,
		[]multiaddr.Multiaddr{
			multiaddr.StringCast("/ip4/1.2.3.4/tcp/443/tls/sni/wildcard." + testForgeDomain + "/ws"),
			// The certificate covers the address, so a TLS listener on
			// another port of the same address is dialable with it too.
			multiaddr.StringCast("/ip4/1.2.3.4/tcp/4001/tls/sni/wildcard." + testForgeDomain + "/ws"),
			multiaddr.StringCast("/ip4/1.2.3.4/tcp/4001"),
			// Nothing to do with us: no certificate for this address.
			multiaddr.StringCast("/ip4/5.6.7.8/tcp/443/tls/sni/wildcard." + testForgeDomain + "/ws"),
		},
		mgr,
		log,
	)

	assertAddrs(t, got, []string{
		"/ip4/1.2.3.4/tcp/443/tls/ws",
		"/ip4/1.2.3.4/tcp/4001/tls/ws",
		"/ip4/1.2.3.4/tcp/4001",
	})
}

// Until the certificate exists, a TLS listener we mean to certify ourselves is
// left out: announcing it would only earn failed handshakes.
func TestAddrFactoryDropsUncertifiedTLSListener(t *testing.T) {
	log := zaptest.NewLogger(t).Sugar()
	mgr := newTestIPCertMgr(t, log)

	wssComponent := multiaddr.StringCast("/tls/sni/wildcard." + testForgeDomain + "/ws")
	got := addrFactoryFn(
		true,
		func() host.Host { return nil },
		testForgeDomain,
		true,
		true,
		wssComponent,
		[]multiaddr.Multiaddr{
			multiaddr.StringCast("/ip4/1.2.3.4/tcp/443/tls/ws"),
			multiaddr.StringCast("/ip4/1.2.3.4/tcp/4001/tls/ws"), // not ours to certify
		},
		mgr,
		log,
	)

	assertAddrs(t, got, []string{"/ip4/1.2.3.4/tcp/4001/tls/ws"})
}

// A client that dials an IP literal sends no SNI, and on a NAT-ed node the
// socket it reaches is bound to a different address than the one we certified.
// The certificate we hold is still the right answer.
func TestSelectCertificateWithoutSNI(t *testing.T) {
	log := zaptest.NewLogger(t).Sugar()
	mgr := newTestIPCertMgr(t, log)

	v4 := testCert(t, "1.2.3.4")
	v6 := testCert(t, "2001:db8::1")
	choices := []certmagic.Certificate{toCertmagicCert(t, mgr, v6), toCertmagicCert(t, mgr, v4)}

	got, err := mgr.SelectCertificate(testClientHello("192.168.1.10:443"), choices)
	if err != nil {
		t.Fatalf("SelectCertificate: %v", err)
	}
	if got.Names[0] != "1.2.3.4" {
		t.Errorf("picked %v for an IPv4 handshake, want the IPv4 certificate", got.Names)
	}

	if _, err := mgr.SelectCertificate(testClientHello("192.168.1.10:443"), nil); err == nil {
		t.Error("expected an error when there is nothing to serve")
	}
}

// Backoff has to outlive the process: a node that crash-loops would otherwise
// start a fresh attempt on every boot and spend the CA's failure budget.
func TestBackoffSurvivesRestart(t *testing.T) {
	log := zaptest.NewLogger(t).Sugar()
	mgr := newTestIPCertMgr(t, log)
	ctx := t.Context()

	if got := mgr.loadBackoff(ctx, "1.2.3.4"); got.Failures != 0 {
		t.Fatalf("unknown address should have no backoff, got %+v", got)
	}

	retryAfter := time.Now().Add(time.Hour).Round(time.Second)
	mgr.saveBackoff(ctx, "1.2.3.4", ipCertBackoff{Failures: 3, RetryAfter: retryAfter})

	// A fresh manager over the same storage, standing in for a restart.
	reloaded := newTestIPCertMgrWithStorage(t, log, mgr.storage)
	got := reloaded.loadBackoff(ctx, "1.2.3.4")
	if got.Failures != 3 || !got.RetryAfter.Equal(retryAfter) {
		t.Fatalf("got %+v, want 3 failures and a retry at %s", got, retryAfter)
	}

	reloaded.clearBackoff(ctx, "1.2.3.4")
	if got := mgr.loadBackoff(ctx, "1.2.3.4"); got.Failures != 0 {
		t.Fatalf("backoff should be gone after success, got %+v", got)
	}
}

// The broker is only asked for a certificate once we know we cannot get one
// ourselves.
func TestFallbackToBroker(t *testing.T) {
	log := zaptest.NewLogger(t).Sugar()

	t.Run("no address we could certify", func(t *testing.T) {
		mgr := newTestIPCertMgr(t, log)
		mgr.evaluated = true
		mgr.checkFallback()
		assertFallback(t, mgr, true)
	})

	t.Run("an attempt is in flight", func(t *testing.T) {
		mgr := newTestIPCertMgr(t, log)
		mgr.evaluated = true
		mgr.addrs["1.2.3.4"] = &ipCertStatus{obtaining: true}
		mgr.checkFallback()
		assertFallback(t, mgr, false)
	})

	t.Run("we hold our own certificate", func(t *testing.T) {
		mgr := newTestIPCertMgr(t, log)
		cacheTestCert(t, mgr, "1.2.3.4")
		mgr.evaluated = true
		mgr.addrs["1.2.3.4"] = &ipCertStatus{managed: true}
		mgr.checkFallback()
		assertFallback(t, mgr, false)
	})

	t.Run("our certificate expired and did not renew", func(t *testing.T) {
		// A node offline past expiry comes back holding a certificate it
		// cannot serve. It needs the broker rather than nothing to announce.
		mgr := newTestIPCertMgr(t, log)
		cacheExpiredTestCert(t, mgr, "1.2.3.4")
		if mgr.hasCertFor("1.2.3.4") {
			t.Fatal("an expired certificate should not count as coverage")
		}
		mgr.evaluated = true
		mgr.addrs["1.2.3.4"] = &ipCertStatus{managed: true}
		mgr.checkFallback()
		assertFallback(t, mgr, true)
	})

	t.Run("every address failed", func(t *testing.T) {
		mgr := newTestIPCertMgr(t, log)
		mgr.evaluated = true
		mgr.addrs["1.2.3.4"] = &ipCertStatus{backoff: ipCertBackoff{Failures: 1, RetryAfter: time.Now().Add(time.Hour)}}
		mgr.checkFallback()
		assertFallback(t, mgr, true)
	})

	t.Run("nothing decided yet", func(t *testing.T) {
		mgr := newTestIPCertMgr(t, log)
		mgr.checkFallback()
		assertFallback(t, mgr, false)
	})
}

// A node behind a port mapping has its public address on no interface of its
// own and only learns it from other peers, minutes after startup. Deciding on
// the first pass would send it to the broker for good, since the decision is
// taken once.
func TestFallbackWaitsForAPublicAddress(t *testing.T) {
	log := zaptest.NewLogger(t).Sugar()

	t.Run("listening on the ACME port, address not known yet", func(t *testing.T) {
		mgr := newTestIPCertMgr(t, log)
		mgr.allowPrivate = false
		mgr.reconcile(t.Context(), newAddrsHost("/ip4/192.168.1.10/tcp/443"))
		assertFallback(t, mgr, false)

		// The address turns up a moment later and is taken from there.
		mgr.reconcile(t.Context(), newAddrsHost("/ip4/192.168.1.10/tcp/443", "/ip4/1.2.3.4/tcp/443"))
		assertFallback(t, mgr, false)
		if _, ok := mgr.addrs["1.2.3.4"]; !ok {
			t.Error("public address was not picked up once it appeared")
		}
	})

	t.Run("no listener on the ACME port", func(t *testing.T) {
		// Nothing to wait for: this node could never answer the challenge.
		mgr := newTestIPCertMgr(t, log)
		mgr.allowPrivate = false
		mgr.reconcile(t.Context(), &addrsHost{
			addrs:  []multiaddr.Multiaddr{multiaddr.StringCast("/ip4/1.2.3.4/tcp/4001")},
			listen: []multiaddr.Multiaddr{multiaddr.StringCast("/ip4/0.0.0.0/tcp/4001")},
		})
		assertFallback(t, mgr, true)
	})

	t.Run("the wait runs out", func(t *testing.T) {
		mgr := newTestIPCertMgr(t, log)
		mgr.allowPrivate = false
		mgr.decideBy = time.Now().Add(-time.Second)
		mgr.reconcile(t.Context(), newAddrsHost("/ip4/192.168.1.10/tcp/443"))
		assertFallback(t, mgr, true)
	})
}

// An address that goes away, which is what a dynamic IP does, stops being
// renewed and stops being announced.
func TestReconcileDropsAddressesThatWentAway(t *testing.T) {
	log := zaptest.NewLogger(t).Sugar()
	mgr := newTestIPCertMgr(t, log)
	cacheTestCert(t, mgr, "1.2.3.4")
	mgr.addrs["1.2.3.4"] = &ipCertStatus{managed: true}

	if !mgr.hasCertFor("1.2.3.4") {
		t.Fatal("test certificate was not cached")
	}

	mgr.reconcile(t.Context(), newAddrsHost("/ip4/5.6.7.8/tcp/4001"))

	if _, ok := mgr.addrs["1.2.3.4"]; ok {
		t.Error("kept maintaining a certificate for an address the host no longer has")
	}
	if mgr.hasCertFor("1.2.3.4") {
		t.Error("still announcing an address the host no longer has")
	}
}

// Backoff is what keeps us inside the authority's failed-validation budget, so
// reconcile must not start an attempt while one is in effect.
func TestReconcileHonorsBackoff(t *testing.T) {
	log := zaptest.NewLogger(t).Sugar()
	mgr := newTestIPCertMgr(t, log)
	mgr.addrs["1.2.3.4"] = &ipCertStatus{
		backoff: ipCertBackoff{Failures: 2, RetryAfter: time.Now().Add(time.Hour)},
	}

	host := newAddrsHost("/ip4/1.2.3.4/tcp/443")
	mgr.reconcile(t.Context(), host)
	if mgr.addrs["1.2.3.4"].obtaining {
		t.Fatal("started an attempt while the address was in backoff")
	}

	// Once the wait is over the same address is tried again. The attempt
	// itself goes nowhere (the test CA is unroutable) and is canceled right
	// away, so only the decision to make it is under test.
	ctx, cancel := context.WithCancel(t.Context())
	mgr.addrs["1.2.3.4"].backoff.RetryAfter = time.Now().Add(-time.Second)
	mgr.reconcile(ctx, host)
	if !mgr.addrs["1.2.3.4"].obtaining {
		t.Error("did not retry after the backoff expired")
	}
	cancel()
	mgr.wg.Wait()
}

// Renewal follows whichever config certmagic is told maintains a certificate.
// Sending an IP certificate to the broker config would fail quietly every few
// days, since the broker has no name to publish a DNS record under.
func TestRenewalDispatch(t *testing.T) {
	for _, ipCerts := range []bool{true, false} {
		t.Run(fmt.Sprintf("ipCerts=%v", ipCerts), func(t *testing.T) {
			opts := []P2PForgeCertMgrOptions{
				WithLogger(zaptest.NewLogger(t).Sugar()),
				WithCertificateStorage(&certmagic.FileStorage{Path: filepath.Join(t.TempDir(), "certs")}),
			}
			if ipCerts {
				opts = append(opts, WithIPCerts())
			}
			mgr, err := NewP2PForgeCertMgr(opts...)
			if err != nil {
				t.Fatalf("NewP2PForgeCertMgr: %v", err)
			}

			ipCfg, err := mgr.configForCert(certmagic.Certificate{Names: []string{"1.2.3.4"}})
			if err != nil {
				t.Fatalf("configForCert: %v", err)
			}
			if ipCerts && ipCfg != mgr.ipCerts.cfg {
				t.Error("an IP certificate would be renewed through the broker")
			}
			if !ipCerts && ipCfg != mgr.certmagic {
				t.Error("without IP certificates everything belongs to the broker config")
			}

			brokered, err := mgr.configForCert(certmagic.Certificate{Names: []string{"*.k51qzi5uqu5.libp2p.direct"}})
			if err != nil {
				t.Fatalf("configForCert: %v", err)
			}
			if brokered != mgr.certmagic {
				t.Error("the brokered wildcard certificate must renew through the broker")
			}
		})
	}
}

// An operator who puts the node's public address in the config is telling it
// something it cannot discover on its own, which is the normal setup in a
// container or on a host whose public address lives on a router. That address
// has to count.
func TestCandidateAddrsIncludeAnnouncedOnes(t *testing.T) {
	log := zaptest.NewLogger(t).Sugar()
	mgr := newTestIPCertMgr(t, log)
	mgr.allowPrivate = false

	h := newAddrsHost("/ip4/1.2.3.4/tcp/443")     // Addresses.Announce
	h.all = addrList("/ip4/192.168.1.10/tcp/443") // everything the host found by itself

	// libp2p has confirmed the address it found, and knows nothing about the
	// one from the config.
	mgr.setReachable(addrList("/ip4/192.168.1.10/tcp/443"))

	got := eligibleIPs(mgr.candidateAddrs(h), testIPCertPort, false)
	if _, ok := got["1.2.3.4"]; !ok {
		t.Errorf("announced address was dropped, got %v", got)
	}
}

// An address the host found for itself and libp2p could not reach is not worth
// a validation attempt.
func TestCandidateAddrsDropUnreachableDiscoveredOnes(t *testing.T) {
	log := zaptest.NewLogger(t).Sugar()
	mgr := newTestIPCertMgr(t, log)
	mgr.allowPrivate = false

	h := newAddrsHost()
	h.all = addrList("/ip4/1.2.3.4/tcp/443", "/ip4/5.6.7.8/tcp/443")
	mgr.setReachable(addrList("/ip4/1.2.3.4/tcp/443"))

	got := eligibleIPs(mgr.candidateAddrs(h), testIPCertPort, false)
	if _, ok := got["5.6.7.8"]; ok {
		t.Errorf("address libp2p reported as unreachable was kept, got %v", got)
	}
	if _, ok := got["1.2.3.4"]; !ok {
		t.Errorf("reachable address was dropped, got %v", got)
	}
}

func addrList(addrs ...string) []multiaddr.Multiaddr {
	out := make([]multiaddr.Multiaddr, 0, len(addrs))
	for _, a := range addrs {
		out = append(out, multiaddr.StringCast(a))
	}
	return out
}

// addrsHost is a host that knows the addresses it announces, the ones it found
// for itself, and the ones it listens on, which is all reconcile asks it for.
type addrsHost struct {
	host.Host
	addrs  []multiaddr.Multiaddr
	all    []multiaddr.Multiaddr
	listen []multiaddr.Multiaddr
}

func (h *addrsHost) Addrs() []multiaddr.Multiaddr { return h.addrs }

// AllAddrs stands in for the method BasicHost exposes: everything the host
// believes about itself, before the address factory has a say.
func (h *addrsHost) AllAddrs() []multiaddr.Multiaddr {
	if h.all == nil {
		return h.addrs
	}
	return h.all
}

func (h *addrsHost) Network() network.Network { return &listenNetwork{listen: h.listen} }

type listenNetwork struct {
	network.Network
	listen []multiaddr.Multiaddr
}

func (n *listenNetwork) ListenAddresses() []multiaddr.Multiaddr { return n.listen }

// newAddrsHost builds a host listening on the ACME port, which is the shape a
// node has to be in for any of this to apply.
func newAddrsHost(addrs ...string) *addrsHost {
	h := &addrsHost{listen: []multiaddr.Multiaddr{
		multiaddr.StringCast(fmt.Sprintf("/ip4/0.0.0.0/tcp/%d", testIPCertPort)),
	}}
	for _, a := range addrs {
		h.addrs = append(h.addrs, multiaddr.StringCast(a))
	}
	return h
}

func assertFallback(t *testing.T, mgr *ipCertMgr, want bool) {
	t.Helper()
	select {
	case <-mgr.fallback:
		if !want {
			t.Error("fell back to the broker while the direct path was still viable")
		}
	default:
		if want {
			t.Error("did not fall back to the broker")
		}
	}
}

func assertAddrs(t *testing.T, got []multiaddr.Multiaddr, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i, w := range want {
		if got[i].String() != w {
			t.Errorf("address %d: got %s, want %s", i, got[i], w)
		}
	}
}

func newTestIPCertMgr(t *testing.T, log *zap.SugaredLogger) *ipCertMgr {
	t.Helper()
	return newTestIPCertMgrWithStorage(t, log, &certmagic.FileStorage{Path: filepath.Join(t.TempDir(), "certs")})
}

func newTestIPCertMgrWithStorage(t *testing.T, log *zap.SugaredLogger, storage certmagic.Storage) *ipCertMgr {
	t.Helper()
	cache := certmagic.NewCache(certmagic.CacheOptions{
		GetConfigForCert: func(certmagic.Certificate) (*certmagic.Config, error) {
			return certmagic.New(certmagic.NewCache(certmagic.CacheOptions{
				GetConfigForCert: func(certmagic.Certificate) (*certmagic.Config, error) { return nil, nil },
			}), certmagic.Config{Storage: storage}), nil
		},
		Logger: log.Desugar(),
	})
	t.Cleanup(cache.Stop)
	return newIPCertMgr(cache, &P2PForgeCertMgrConfig{
		storage: storage,
		// Unroutable on purpose: no unit test may reach a real ACME server,
		// even if one of them starts an issuance attempt by accident.
		caEndpoint:                 "https://127.0.0.1:0/directory",
		ipCertPort:                 testIPCertPort,
		ipCertProfile:              DefaultIPCertProfile,
		allowPrivateForgeAddresses: true,
	}, log)
}

// cacheTestCert puts a self-signed certificate for ip through the same
// storage-and-load path a freshly issued one takes, so the manager holds it
// exactly as it would in production, without talking to a CA.
func cacheTestCert(t *testing.T, mgr *ipCertMgr, ip string) {
	t.Helper()
	cacheCert(t, mgr, testCert(t, ip), ip)
}

// cacheExpiredTestCert is cacheTestCert with a certificate whose validity has
// run out, which is the state a node comes back in after being offline longer
// than a short-lived certificate lasts.
func cacheExpiredTestCert(t *testing.T, mgr *ipCertMgr, ip string) {
	t.Helper()
	cacheCert(t, mgr, expiredTestCert(t, ip), ip)
}

func cacheCert(t *testing.T, mgr *ipCertMgr, cert tls.Certificate, ip string) {
	t.Helper()
	ctx := t.Context()

	keyDER, err := x509.MarshalECPrivateKey(cert.PrivateKey.(*ecdsa.PrivateKey))
	if err != nil {
		t.Fatalf("marshal test key: %v", err)
	}
	res := certmagic.CertificateResource{
		SANs:           []string{ip},
		CertificatePEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}),
		PrivateKeyPEM:  pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
	}
	meta, err := json.Marshal(res)
	if err != nil {
		t.Fatalf("marshal test certificate metadata: %v", err)
	}
	for key, value := range map[string][]byte{
		certmagic.StorageKeys.SiteCert(mgr.issuerKey, ip):       res.CertificatePEM,
		certmagic.StorageKeys.SitePrivateKey(mgr.issuerKey, ip): res.PrivateKeyPEM,
		certmagic.StorageKeys.SiteMeta(mgr.issuerKey, ip):       meta,
	} {
		if err := mgr.storage.Store(ctx, key, value); err != nil {
			t.Fatalf("store test certificate: %v", err)
		}
	}
	if _, err := mgr.cfg.CacheManagedCertificate(ctx, ip); err != nil {
		t.Fatalf("caching test certificate: %v", err)
	}
}

func toCertmagicCert(t *testing.T, mgr *ipCertMgr, cert tls.Certificate) certmagic.Certificate {
	t.Helper()
	hash, err := mgr.cfg.CacheUnmanagedTLSCertificate(t.Context(), cert, nil)
	if err != nil {
		t.Fatalf("caching test certificate: %v", err)
	}
	for _, c := range mgr.cache.AllMatchingCertificates(cert.Leaf.IPAddresses[0].String()) {
		if c.Hash() == hash {
			return c
		}
	}
	t.Fatal("cached certificate not found")
	return certmagic.Certificate{}
}

func testCert(t *testing.T, ip string) tls.Certificate {
	t.Helper()
	// 160 hours is what Let's Encrypt issues for an address.
	return certForIP(t, ip, time.Now().Add(-time.Hour), time.Now().Add(160*time.Hour))
}

func expiredTestCert(t *testing.T, ip string) tls.Certificate {
	t.Helper()
	return certForIP(t, ip, time.Now().Add(-200*time.Hour), time.Now().Add(-40*time.Hour))
}

func certForIP(t *testing.T, ip string, notBefore, notAfter time.Time) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{Organization: []string{"p2p-forge test"}},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		IPAddresses:  []net.IP{net.ParseIP(ip)},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating certificate: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing certificate: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

// testClientHello is what an ECDSA-capable client dialing an IP literal looks
// like: no SNI, and enough of the handshake filled in for
// tls.ClientHelloInfo.SupportsCertificate to accept a P-256 certificate.
func testClientHello(localAddr string) *tls.ClientHelloInfo {
	return &tls.ClientHelloInfo{
		CipherSuites:      []uint16{tls.TLS_AES_128_GCM_SHA256, tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		SupportedCurves:   []tls.CurveID{tls.X25519, tls.CurveP256},
		SupportedPoints:   []uint8{0},
		SignatureSchemes:  []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256},
		SupportedVersions: []uint16{tls.VersionTLS13, tls.VersionTLS12},
		Conn:              fakeConn{local: localAddr},
	}
}

// fakeConn is a net.Conn that only knows its local address, which is all
// certificate selection looks at.
type fakeConn struct {
	net.Conn
	local string
}

func (c fakeConn) LocalAddr() net.Addr {
	addr, err := net.ResolveTCPAddr("tcp", c.local)
	if err != nil {
		panic(err)
	}
	return addr
}
