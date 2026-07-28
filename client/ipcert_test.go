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
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/multiformats/go-multiaddr"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest"
	"go.uber.org/zap/zaptest/observer"
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

// A certificate that ran out and was not renewed has to be replaced. Asking to
// obtain one would be a no-op, since certmagic treats a name whose files are in
// storage as settled however stale they are, so the address goes back through
// the attempt path and stops being counted as managed.
func TestExpiredCertificateIsTakenBack(t *testing.T) {
	log := zaptest.NewLogger(t).Sugar()
	mgr := newTestIPCertMgr(t, log)
	mgr.obtainWindow = 100 * time.Millisecond
	cacheExpiredTestCert(t, mgr, "1.2.3.4")
	mgr.addrs["1.2.3.4"] = &ipCertStatus{managed: true}

	ctx, cancel := context.WithCancel(t.Context())
	defer func() {
		cancel()
		mgr.wg.Wait()
	}()
	mgr.reconcile(ctx, newAddrsHost("/ip4/1.2.3.4/tcp/443"))

	st := mgr.addrs["1.2.3.4"]
	if st.managed {
		t.Error("still counted as managed while holding a certificate that ran out")
	}
	if !st.obtaining {
		t.Error("did not go back for a replacement certificate")
	}
}

// A host that took the broker path must not have its TLS listener withheld: no
// certificate for an address is coming, so withholding it would silence the
// listener for good.
func TestUncertifiedListenerIsOnlyWithheldOnTheDirectPath(t *testing.T) {
	log := zaptest.NewLogger(t).Sugar()
	mgr := newTestIPCertMgr(t, log)
	addr := multiaddr.StringCast("/ip4/1.2.3.4/tcp/443/tls/ws")

	if !mgr.covers(addr) {
		t.Error("a host on the direct path should withhold a listener it has no certificate for")
	}

	mgr.useBroker()
	if mgr.covers(addr) {
		t.Error("a host on the broker path should announce its listener as it finds it")
	}
}

// Listening on the port a certificate authority validates on is what commits a
// node to certifying its own address, so the check behind that decision has to
// recognise every shape a listener comes in.
func TestListensOnPort(t *testing.T) {
	for _, tc := range []struct {
		name         string
		listen       []string
		allowPrivate bool
		want         bool
	}{
		{name: "wildcard", listen: []string{"/ip4/0.0.0.0/tcp/443/tls/ws"}, want: true},
		{name: "one interface", listen: []string{"/ip4/10.0.0.5/tcp/443/tls/ws"}, want: true},
		{name: "the wildcard SNI form AutoWSS installs", listen: []string{"/ip4/0.0.0.0/tcp/443/tls/sni/wildcard.libp2p.direct/ws"}, want: true},
		{name: "IPv6", listen: []string{"/ip6/::/tcp/443/tls/ws"}, want: true},
		{name: "among others", listen: []string{"/ip4/0.0.0.0/tcp/4001/tls/ws", "/ip4/0.0.0.0/tcp/443/tls/ws"}, want: true},
		{name: "some other port", listen: []string{"/ip4/0.0.0.0/tcp/4001/tls/ws"}},
		{name: "QUIC on the same number", listen: []string{"/ip4/0.0.0.0/udp/443/quic-v1"}},
		{name: "nothing at all"},
		// A plain libp2p listener cannot terminate TLS, so it cannot answer
		// the challenge however right the port looks.
		{name: "TCP without TLS", listen: []string{"/ip4/0.0.0.0/tcp/443"}},
		// Nothing on loopback is reachable by a public authority.
		{name: "loopback only", listen: []string{"/ip4/127.0.0.1/tcp/443/tls/ws"}},
		{name: "loopback when checks are skipped", listen: []string{"/ip4/127.0.0.1/tcp/443/tls/ws"}, allowPrivate: true, want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := &addrsHost{listen: addrList(tc.listen...)}
			if got := listensOnPort(h, testIPCertPort, tc.allowPrivate); got != tc.want {
				t.Errorf("listensOnPort = %v, want %v", got, tc.want)
			}
		})
	}
}

// A node that listens on the port but has no public address there gets no
// certificate and no broker either, so the reason has to be in the log, and it
// has to stay there: said once at startup it would scroll away long before
// anyone came looking.
func TestNoAddressIsReportedAndRepeated(t *testing.T) {
	core, logs := observer.New(zapcore.ErrorLevel)
	mgr := newTestIPCertMgr(t, zap.New(core).Sugar())

	host := &addrsHost{
		addrs:  addrList("/ip4/192.168.1.10/tcp/4001"), // nothing on the ACME port
		listen: addrList(fmt.Sprintf("/ip4/0.0.0.0/tcp/%d/tls/ws", testIPCertPort)),
	}

	// Nothing is wrong yet on a node that started a moment ago.
	mgr.reconcile(t.Context(), host)
	if logs.Len() != 0 {
		t.Fatalf("complained %d times during the grace period, want silence", logs.Len())
	}

	mgr.mu.Lock()
	mgr.started = time.Now().Add(-ipCertNoAddressGrace - time.Minute)
	mgr.mu.Unlock()
	mgr.reconcile(t.Context(), host)
	if logs.Len() != 1 {
		t.Fatalf("logged %d errors, want the one saying there is no address to certify", logs.Len())
	}
	if entry := logs.All()[0]; !strings.Contains(entry.Message, "no public address") {
		t.Errorf("error reads %q, want it to name the missing address", entry.Message)
	}

	// Reconciling again a moment later says nothing new.
	mgr.reconcile(t.Context(), host)
	if logs.Len() != 1 {
		t.Errorf("repeated the error %d times in a row, want it rate limited", logs.Len())
	}

	// An hour on, it is worth saying again.
	mgr.mu.Lock()
	mgr.lastNoAddrLog = time.Now().Add(-ipCertNoAddressInterval - time.Minute)
	mgr.mu.Unlock()
	mgr.reconcile(t.Context(), host)
	if logs.Len() != 2 {
		t.Errorf("logged %d errors after the interval, want a second one", logs.Len())
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
	profile := DefaultIPCertProfile
	mgr := newIPCertMgr(cache, &P2PForgeCertMgrConfig{
		storage: storage,
		// Unroutable on purpose: no unit test may reach a real ACME server,
		// even if one of them starts an issuance attempt by accident.
		caEndpoint:                 "https://127.0.0.1:0/directory",
		ipCertPort:                 testIPCertPort,
		ipCertProfile:              &profile,
		allowPrivateForgeAddresses: true,
	}, log)
	return mgr
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
