package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/ipshipyard/p2p-forge/client"
	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/peer"
	libp2pws "github.com/libp2p/go-libp2p/p2p/transport/websocket"
	"github.com/multiformats/go-multiaddr"

	pebbleCA "github.com/letsencrypt/pebble/v2/ca"
	pebbleDB "github.com/letsencrypt/pebble/v2/db"
	pebbleVA "github.com/letsencrypt/pebble/v2/va"
	pebbleWFE "github.com/letsencrypt/pebble/v2/wfe"
)

// TestLibp2pIPCertE2E is the WithIPCerts counterpart of TestLibp2pACMEE2E: a
// node that listens on the port the CA validates on gets a certificate for its
// own address, and the broker is left out of it entirely.
//
// The CA connects to the address it is being asked to certify and runs the
// TLS-ALPN-01 challenge against the WebSocket listener already on that port,
// so the whole exchange is between the node and the CA. Nothing here talks to
// the p2p-forge registration endpoint, and the test fails if anything does.
//
// The one thing this cannot reproduce is the port. Let's Encrypt only ever
// connects to 443, which a test cannot bind, so Pebble's validation authority
// is pointed at the port the node did get, through the same WithIPCertPort
// option that exists for exactly this.
func TestLibp2pIPCertE2E(t *testing.T) {
	for _, tt := range []struct {
		name string
		// ip is the address the node listens on and asks to have certified.
		ip string
		// caValidity is the certificate lifetime pebble hands out, in seconds.
		// Zero leaves pebble's default, which is far too long to watch expire.
		caValidity uint64
		clientOpts []client.P2PForgeCertMgrOptions
		// awaitRenewal waits for a second certificate to replace the first.
		awaitRenewal bool
	}{
		{
			name: "IPv4",
			ip:   "127.0.0.1",
		},
		{
			name: "IPv6",
			ip:   "::1",
		},
		{
			// A certificate for an address lasts days rather than months, so
			// renewal is the normal case, not an edge one. A 25 second
			// lifetime puts the renewal window about 8 seconds out, and
			// checking every 2 seconds gives the maintenance loop several
			// chances to notice inside the test's budget.
			name: "a certificate that runs out is renewed",
			// A different loopback address than the other cases: certmagic
			// keeps in-flight challenges in one process-wide map keyed by
			// identifier, so subtests running in parallel must not ask for the
			// same address at the same time.
			ip:           "127.0.0.2",
			caValidity:   25,
			clientOpts:   []client.P2PForgeCertMgrOptions{client.WithRenewCheckInterval(2 * time.Second)},
			awaitRenewal: true,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			testIPCert(t, tt.ip, tt.caValidity, tt.awaitRenewal, tt.clientOpts)
		})
	}
}

func testIPCert(t *testing.T, nodeIP string, caValidity uint64, awaitRenewal bool, extraOpts []client.P2PForgeCertMgrOptions) {
	// The node listens on this port and Pebble connects back to it, so both
	// have to agree on it before either starts.
	nodePort := reserveLoopbackPort(t)

	// Stands in for the broker. Reaching it at all means the node fell back,
	// which for a node that can certify its own address is a failure.
	var brokerHits atomic.Int32
	brokerSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		brokerHits.Add(1)
		w.WriteHeader(http.StatusNotFound)
	}))
	defer brokerSrv.Close()

	logger := log.New(testWriter{t}, "pebble: ", 0)
	db := pebbleDB.NewMemoryStore()
	// Named after the profile Let's Encrypt requires for address
	// certificates, which is what the client asks for by default.
	caProfiles := map[string]pebbleCA.Profile{
		client.DefaultIPCertProfile: {
			Description:    "short-lived profile for IP address certificates",
			ValidityPeriod: caValidity, // zero leaves pebble's own default
		},
	}
	ca := pebbleCA.New(logger, db, "", "rsa", 0, 1, caProfiles)
	// httpPort 0 because HTTP-01 is never used here; tlsPort is where the
	// TLS-ALPN-01 challenge is answered. Empty resolver: an address needs no
	// name resolution.
	va := pebbleVA.New(logger, 0, nodePort, false, "", db)
	wfe := pebbleWFE.New(logger, db, va, ca, nil, false, false, 3, 5)

	acmeListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer acmeListener.Close()

	acmeCertPEM, acmeKeyPEM, err := generateSelfSignedCert("127.0.0.1")
	if err != nil {
		t.Fatalf("self-signed cert for the ACME endpoint: %v", err)
	}
	acmeCert, err := tls.X509KeyPair(acmeCertPEM, acmeKeyPEM)
	if err != nil {
		t.Fatalf("load ACME endpoint key pair: %v", err)
	}
	go func() {
		_ = http.Serve(tls.NewListener(acmeListener, &tls.Config{
			Certificates: []tls.Certificate{acmeCert},
		}), wfe.Handler())
	}()

	acmeRoots := x509.NewCertPool()
	acmeRoots.AppendCertsFromPEM(acmeCertPEM)

	certRenewed := make(chan struct{}, 1)
	sk, err := generateTestIdentity("TestLibp2pIPCertE2E", t.Name())
	if err != nil {
		t.Fatal(err)
	}

	opts := append([]client.P2PForgeCertMgrOptions{
		client.WithForgeDomain(forge),
		client.WithForgeRegistrationEndpoint(brokerSrv.URL),
		client.WithCAEndpoint(fmt.Sprintf("https://%s%s", acmeListener.Addr(), pebbleWFE.DirectoryPath)),
		client.WithTrustedRoots(acmeRoots),
		client.WithCertificateStorage(&certmagic.FileStorage{Path: filepath.Join(t.TempDir(), "cert-storage")}),
		// Loopback is not a public address and autonat has nothing to confirm
		// on a one-node network, so lift both checks.
		client.WithAllowPrivateForgeAddrs(),
		client.WithIPCerts(),
		client.WithIPCertPort(nodePort),
		client.WithOnCertRenewed(func() {
			select {
			case certRenewed <- struct{}{}:
			default:
			}
		}),
	}, extraOpts...)

	certMgr, err := client.NewP2PForgeCertMgr(opts...)
	if err != nil {
		t.Fatal(err)
	}

	safeCertMgrOperation(t, func() { certMgr.Start() }, "Start")
	defer safeCertMgrOperation(t, func() { certMgr.Stop() }, "Stop")

	// A plain /tls/ws listener, with no wildcard SNI: this node has no
	// brokered name and does not need one.
	listenAddr := fmt.Sprintf("/%s/%s/tcp/%d/tls/ws", ipProtocol(nodeIP), nodeIP, nodePort)
	h, err := libp2p.New(
		libp2p.Identity(sk),
		libp2p.ListenAddrStrings(listenAddr),
		libp2p.Transport(libp2pws.New, libp2pws.WithTLSConfig(certMgr.TLSConfig())),
		libp2p.AddrsFactory(certMgr.AddressFactory()),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	certMgr.ProvideHost(h)

	// The address only shows up once the certificate is there to serve it.
	wantAddr := multiaddr.StringCast(listenAddr)
	if !awaitAddr(t, h, wantAddr, 60*time.Second) {
		t.Fatalf("node never announced %s, has %v", wantAddr, h.Addrs())
	}

	// The certificate covers the address itself, with no name anywhere in it.
	leaf := peerLeafCert(t, net.JoinHostPort(nodeIP, strconv.Itoa(nodePort)), nodeIP, ca)
	if len(leaf.DNSNames) != 0 {
		t.Errorf("certificate carries DNS names %v, expected an address only", leaf.DNSNames)
	}
	if len(leaf.IPAddresses) != 1 || leaf.IPAddresses[0].String() != nodeIP {
		t.Errorf("certificate covers %v, expected %s", leaf.IPAddresses, nodeIP)
	}

	// A second node dials the announced address and completes the libp2p
	// handshake over it, which is the whole point of having the certificate.
	roots := x509.NewCertPool()
	roots.AddCert(ca.GetRootCert(0).Cert)
	h2, err := libp2p.New(
		libp2p.NoListenAddrs,
		libp2p.Transport(libp2pws.New, libp2pws.WithTLSClientConfig(&tls.Config{RootCAs: roots})),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer h2.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := h2.Connect(ctx, peer.AddrInfo{ID: h.ID(), Addrs: []multiaddr.Multiaddr{wantAddr}}); err != nil {
		t.Fatalf("dialing %s: %v", wantAddr, err)
	}

	if awaitRenewal {
		select {
		case <-certRenewed:
		case <-time.After(60 * time.Second):
			t.Fatal("certificate was never renewed")
		}
		renewed := peerLeafCert(t, net.JoinHostPort(nodeIP, strconv.Itoa(nodePort)), nodeIP, ca)
		if renewed.NotAfter.Compare(leaf.NotAfter) <= 0 {
			t.Errorf("certificate served after renewal still expires at %s, same as before", renewed.NotAfter)
		}
		if len(renewed.IPAddresses) != 1 || renewed.IPAddresses[0].String() != nodeIP {
			t.Errorf("renewed certificate covers %v, expected %s", renewed.IPAddresses, nodeIP)
		}
	}

	if hits := brokerHits.Load(); hits != 0 {
		t.Errorf("node made %d requests to the broker, expected none", hits)
	}
}

// ipProtocol returns the multiaddr protocol name for an address literal.
func ipProtocol(ip string) string {
	if strings.Contains(ip, ":") {
		return "ip6"
	}
	return "ip4"
}

// reserveLoopbackPort picks a free TCP port. It carries the usual race of
// handing a closed port to somebody else, which this test accepts for the same
// reason the forge registration endpoint does: several parties have to agree
// on the port before any of them starts.
func reserveLoopbackPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	return port
}

// awaitAddr waits for want to show up in the host's announced addresses.
func awaitAddr(t *testing.T, h interface{ Addrs() []multiaddr.Multiaddr }, want multiaddr.Multiaddr, timeout time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		for _, a := range h.Addrs() {
			if a.Equal(want) {
				return true
			}
		}
		time.Sleep(250 * time.Millisecond)
	}
	return false
}

// peerLeafCert returns the certificate a node serves on a plain TLS dial that
// carries no SNI, which is what a client dialing an address does.
func peerLeafCert(t *testing.T, addr, serverName string, ca *pebbleCA.CAImpl) *x509.Certificate {
	t.Helper()
	roots := x509.NewCertPool()
	roots.AddCert(ca.GetRootCert(0).Cert)
	conn, err := tls.Dial("tcp", addr, &tls.Config{
		RootCAs:    roots,
		ServerName: serverName, // an address, so Go verifies it against the IP SANs and sends no SNI
		NextProtos: []string{"h2", "http/1.1"},
	})
	if err != nil {
		t.Fatalf("TLS handshake with %s: %v", addr, err)
	}
	defer conn.Close()
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		t.Fatalf("%s presented no certificate", addr)
	}
	return certs[0]
}

// testWriter sends a logger's output to the test log, so a passing run stays
// quiet and a failing one keeps the CA's side of the story.
type testWriter struct{ t *testing.T }

func (w testWriter) Write(p []byte) (int, error) {
	w.t.Logf("%s", p)
	return len(p), nil
}
