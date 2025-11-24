package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	p2pacme "github.com/ipshipyard/p2p-forge/acme"
	"github.com/ipshipyard/p2p-forge/client"
	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/p2p/net/swarm"
	libp2pquic "github.com/libp2p/go-libp2p/p2p/transport/quic"
	"github.com/libp2p/go-libp2p/p2p/transport/tcp"
	libp2pwebrtc "github.com/libp2p/go-libp2p/p2p/transport/webrtc"
	libp2pws "github.com/libp2p/go-libp2p/p2p/transport/websocket"
	libp2pwebtransport "github.com/libp2p/go-libp2p/p2p/transport/webtransport"
	"github.com/miekg/dns"
	"github.com/multiformats/go-multiaddr"
	madns "github.com/multiformats/go-multiaddr-dns"
	"github.com/multiformats/go-multibase"

	// Load CoreDNS dnsserver.Directives + p2p-forge plugins
	_ "github.com/ipshipyard/p2p-forge/plugins"

	pebbleCA "github.com/letsencrypt/pebble/v2/ca"
	pebbleDB "github.com/letsencrypt/pebble/v2/db"
	pebbleVA "github.com/letsencrypt/pebble/v2/va"
	pebbleWFE "github.com/letsencrypt/pebble/v2/wfe"
)

const forge = "libp2p.direct"
const forgeRegistration = "registration.libp2p.direct"

const authEnvVar = client.ForgeAuthEnv
const authToken = "testToken"
const authForgeHeader = client.ForgeAuthHeader

// TestInfrastructure provides isolated test environment for each test
type TestInfrastructure struct {
	DNSServerAddress string
	HTTPPort         int
	TmpDir           string
	Instance         *caddy.Instance
}

// initDirectives sets up CoreDNS directives once during package initialization
func init() {
	dnsserver.Directives = []string{
		"log",
		"errors",
		"any",
		"whoami",
		"startup",
		"shutdown",
		"ipparser",
		"file",
		"acme",
	}
}

// NewTestInfrastructure creates an isolated test environment for a single test
func NewTestInfrastructure(t *testing.T) *TestInfrastructure {
	tmpDir := t.TempDir() // Use built-in cleanup

	tmpListener, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatalf("Failed to create HTTP listener: %v", err)
	}
	httpPort := tmpListener.Addr().(*net.TCPAddr).Port
	tmpListener.Close()

	corefile := fmt.Sprintf(`.:0 {
		log
		errors
		ipparser %s
		acme %s {
			registration-domain %s listen-address=:%d external-tls=true
			database-type badger %s
        }
	}`, forge, forge, forgeRegistration, httpPort, tmpDir)

	instance, err := caddy.Start(NewInput(corefile))
	if err != nil {
		t.Fatalf("Failed to start CoreDNS instance: %v", err)
	}

	testInfra := &TestInfrastructure{
		DNSServerAddress: instance.Servers()[0].LocalAddr().String(),
		HTTPPort:         httpPort,
		TmpDir:           tmpDir,
		Instance:         instance,
	}

	t.Cleanup(func() {
		if instance != nil {
			errs := instance.ShutdownCallbacks()
			if err := errors.Join(errs...); err != nil {
				t.Logf("Shutdown callback errors: %v", err)
			}
			if err := instance.Stop(); err != nil {
				t.Logf("Instance stop error: %v", err)
			}
			instance.Wait()
		}
	})

	return testInfra
}

func TestMain(m *testing.M) {
	// Set global auth environment variable for all tests
	if err := os.Setenv(authEnvVar, authToken); err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}

	// Run tests - each test now creates its own isolated infrastructure
	os.Exit(m.Run())
}

// Need to handle <peerID>.forgeDomain to return NODATA rather than NXDOMAIN per https://datatracker.ietf.org/doc/html/rfc8020
func TestRFC8020(t *testing.T) {
	t.Parallel()
	testInfra := NewTestInfrastructure(t)

	_, pk, err := crypto.GenerateEd25519Key(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	peerID, err := peer.IDFromPublicKey(pk)
	if err != nil {
		t.Fatal(err)
	}
	peerIDb36, err := peer.ToCid(peerID).StringOfBase(multibase.Base36)
	if err != nil {
		t.Fatal(err)
	}

	m := new(dns.Msg)
	m.Question = make([]dns.Question, 1)
	m.Question[0] = dns.Question{Qclass: dns.ClassINET, Name: fmt.Sprintf("%s.%s.", peerIDb36, forge), Qtype: dns.TypeTXT}

	r, err := dns.Exchange(m, testInfra.DNSServerAddress)
	if err != nil {
		t.Fatalf("Could not send message: %s", err)
	}
	if r.Rcode != dns.RcodeSuccess {
		t.Fatalf("Expected successful reply, got %s", dns.RcodeToString[r.Rcode])
	}
	if len(r.Answer) != 0 {
		t.Fatalf("expected no answers got %+v", r.Answer)
	}
}

// For valid subdomains (e.g. <ipv4|6>.<peerID>.forgeDomain) even though only A or AAAA records might be supported
// we should return a successful lookup with no answer rather than erroring
func TestIPSubdomainsNonExistentRecords(t *testing.T) {
	t.Parallel()
	testInfra := NewTestInfrastructure(t)

	_, pk, err := crypto.GenerateEd25519Key(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	peerID, err := peer.IDFromPublicKey(pk)
	if err != nil {
		t.Fatal(err)
	}
	peerIDb36, err := peer.ToCid(peerID).StringOfBase(multibase.Base36)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name      string
		subdomain string
		qtype     uint16
	}{
		{
			name:      "AAAA_ipv4.peerID.forge",
			subdomain: "1-2-3-4",
			qtype:     dns.TypeAAAA,
		},
		{
			name:      "TXT_ipv4.peerID.forge",
			subdomain: "1-2-3-4",
			qtype:     dns.TypeTXT,
		},
		{
			name:      "A_ipv6.peerID.forge",
			subdomain: "1234-5678-90AB-CDEF-1-22-33-444",
			qtype:     dns.TypeA,
		},
		{
			name:      "TXT_ipv6.peerID.forge",
			subdomain: "1234-5678-90AB-CDEF-1-22-33-444",
			qtype:     dns.TypeTXT,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			domain := fmt.Sprintf("%s.%s.%s.", tt.subdomain, peerIDb36, forge)
			m := new(dns.Msg)
			m.Question = make([]dns.Question, 1)
			m.Question[0] = dns.Question{Qclass: dns.ClassINET, Name: domain, Qtype: tt.qtype}

			r, err := dns.Exchange(m, testInfra.DNSServerAddress)
			if err != nil {
				t.Fatalf("Could not send message: %s", err)
			}
			if r.Rcode != dns.RcodeSuccess {
				t.Fatalf("Expected successful reply, got %s", dns.RcodeToString[r.Rcode])
			}
			if len(r.Answer) != 0 {
				t.Fatalf("expected no answers got %+v", r.Answer)
			}
		})
	}
}

func TestSetACMEChallenge(t *testing.T) {
	t.Parallel()
	testInfra := NewTestInfrastructure(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sk, _, err := crypto.GenerateEd25519Key(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	h, err := libp2p.New(libp2p.Identity(sk))
	if err != nil {
		t.Fatal(err)
	}

	testDigest := sha256.Sum256([]byte("test"))
	testChallenge := base64.RawURLEncoding.EncodeToString(testDigest[:])

	err = client.SendChallenge(ctx, fmt.Sprintf("http://127.0.0.1:%d", testInfra.HTTPPort), sk, testChallenge, h.Addrs(), authToken, "", func(req *http.Request) error {
		req.Host = forgeRegistration
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	peerIDb36, err := peer.ToCid(h.ID()).StringOfBase(multibase.Base36)
	if err != nil {
		t.Fatal(err)
	}

	m := new(dns.Msg)
	m.Question = make([]dns.Question, 1)
	m.Question[0] = dns.Question{Qclass: dns.ClassINET, Name: fmt.Sprintf("_acme-challenge.%s.%s.", peerIDb36, forge), Qtype: dns.TypeTXT}

	r, err := dns.Exchange(m, testInfra.DNSServerAddress)
	if err != nil {
		t.Fatalf("Could not send message: %s", err)
	}
	if r.Rcode != dns.RcodeSuccess || len(r.Answer) == 0 {
		t.Fatalf("Expected successful reply with TXT value, got empty %s", dns.RcodeToString[r.Rcode])
	}
	expectedAnswer := fmt.Sprintf(`%s	10	IN	TXT	"%s"`, m.Question[0].Name, testChallenge)
	if r.Answer[0].String() != expectedAnswer {
		t.Fatalf("Expected %s reply, got %s", expectedAnswer, r.Answer[0].String())
	}
}

// Confirm we ALWAYS return empty TXT instead of NODATA to avoid
// issues described in https://github.com/ipshipyard/p2p-forge/issues/52
func TestACMEChallengeNoDNS01Value(t *testing.T) {
	t.Parallel()
	testInfra := NewTestInfrastructure(t)

	sk, _, err := crypto.GenerateEd25519Key(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	h, err := libp2p.New(libp2p.Identity(sk))
	if err != nil {
		t.Fatal(err)
	}

	// Note: we don't register – we want DNS-01 to fail

	peerIDb36, err := peer.ToCid(h.ID()).StringOfBase(multibase.Base36)
	if err != nil {
		t.Fatal(err)
	}

	m := new(dns.Msg)
	m.Question = make([]dns.Question, 1)
	m.Question[0] = dns.Question{Qclass: dns.ClassINET, Name: fmt.Sprintf("_acme-challenge.%s.%s.", peerIDb36, forge), Qtype: dns.TypeTXT}

	r, err := dns.Exchange(m, testInfra.DNSServerAddress)
	if err != nil {
		t.Fatalf("Could not send message: %s", err)
	}
	if r.Rcode != dns.RcodeSuccess || len(r.Answer) == 0 {
		t.Fatalf("Expected successful reply with TXT value, got empty %s", dns.RcodeToString[r.Rcode])
	}
	expectedAnswer := fmt.Sprintf(`%s	10	IN	TXT	"%s"`, m.Question[0].Name, p2pacme.DNS01NotSetValue)
	if r.Answer[0].String() != expectedAnswer {
		t.Fatalf("Expected %s reply, got %s", expectedAnswer, r.Answer[0].String())
	}
}

func TestIPv4Lookup(t *testing.T) {
	t.Parallel()
	testInfra := NewTestInfrastructure(t)

	_, pk, err := crypto.GenerateEd25519Key(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	peerID, err := peer.IDFromPublicKey(pk)
	if err != nil {
		t.Fatal(err)
	}
	peerIDb36, err := peer.ToCid(peerID).StringOfBase(multibase.Base36)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name             string
		qtype            uint16
		subdomain        string
		expectedSuccess  bool
		expectedAddress  string
		expectServerFail bool
	}{
		{
			name:            "IPv4-A",
			qtype:           dns.TypeA,
			subdomain:       "1-2-3-4",
			expectedSuccess: true,
			expectedAddress: "1.2.3.4",
		},
		{
			name:            "IPv4-ANY",
			qtype:           dns.TypeANY,
			subdomain:       "11-222-33-4",
			expectedSuccess: true,
			expectedAddress: "", // ANY queries return HINFO per RFC 8482, not IP addresses
		},
		{
			name:            "IPv4-AAAA",
			qtype:           dns.TypeAAAA,
			subdomain:       "1-2-3-4",
			expectedSuccess: true,
			expectedAddress: "",
		},
		{
			name:            "InvalidIPv4_1-2-3-4-5",
			qtype:           dns.TypeA,
			subdomain:       "1-2-3-4-5",
			expectedSuccess: false,
			expectedAddress: "",
		},
		{
			name:            "InvalidIPv4_1-2-3",
			qtype:           dns.TypeA,
			subdomain:       "1-2-3",
			expectedSuccess: false,
			expectedAddress: "",
		},
		{
			name:            "InvalidIPv4_1-2-3-444",
			qtype:           dns.TypeA,
			subdomain:       "1-2-3-444",
			expectedSuccess: false,
			expectedAddress: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			m := new(dns.Msg)
			m.Question = make([]dns.Question, 1)
			m.Question[0] = dns.Question{Qclass: dns.ClassINET, Name: fmt.Sprintf("%s.%s.%s.", tt.subdomain, peerIDb36, forge), Qtype: tt.qtype}

			r, err := dns.Exchange(m, testInfra.DNSServerAddress)
			if err != nil {
				t.Fatalf("Could not send message: %s", err)
			}

			if !tt.expectedSuccess {
				if tt.expectServerFail {
					if r.Rcode != dns.RcodeServerFailure {
						t.Fatalf("Expected SERVFAIL reply, got %s", dns.RcodeToString[r.Rcode])
					}
				} else {
					if r.Rcode != dns.RcodeSuccess || len(r.Answer) != 0 {
						t.Fatalf("Expected NODATA reply, got %s and answers %+v", dns.RcodeToString[r.Rcode], r.Answer)
					}
				}
				return
			}

			if r.Rcode != dns.RcodeSuccess {
				t.Fatalf("Expected successful reply, got %s", dns.RcodeToString[r.Rcode])
			}

			if len(r.Answer) == 0 {
				if tt.expectedAddress != "" {
					t.Fatal("Expected an address but got none")
				}
				return
			}

			expectedAnswer := fmt.Sprintf(`%s	604800	IN	A	%s`, m.Question[0].Name, tt.expectedAddress)
			if r.Answer[0].String() != expectedAnswer {
				t.Fatalf("Expected %s reply, got %s", expectedAnswer, r.Answer[0].String())
			}
		})
	}
}

func TestIPv6Lookup(t *testing.T) {
	t.Parallel()
	testInfra := NewTestInfrastructure(t)

	_, pk, err := crypto.GenerateEd25519Key(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	peerID, err := peer.IDFromPublicKey(pk)
	if err != nil {
		t.Fatal(err)
	}
	peerIDb36, err := peer.ToCid(peerID).StringOfBase(multibase.Base36)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name             string
		qtype            uint16
		subdomain        string
		expectedSuccess  bool
		expectedAddress  string
		expectServerFail bool
	}{
		{
			name:            "A",
			qtype:           dns.TypeA,
			subdomain:       "0--1",
			expectedSuccess: true,
			expectedAddress: "",
		},
		{
			name:            "ANY",
			qtype:           dns.TypeANY,
			subdomain:       "1234-5678-90AB-CDEF-1-22-33-444",
			expectedSuccess: true,
			expectedAddress: "", // ANY queries return HINFO per RFC 8482, not IP addresses
		},
		{
			name:            "AAAA",
			qtype:           dns.TypeAAAA,
			subdomain:       "0--1",
			expectedSuccess: true,
			expectedAddress: "::1",
		},
		{
			name:            "Valid_Leading_Compression",
			qtype:           dns.TypeAAAA,
			subdomain:       "--1",
			expectedSuccess: true,
			expectedAddress: "::1",
		},
		{
			name:            "Valid_Trailing_Compression",
			qtype:           dns.TypeAAAA,
			subdomain:       "0--",
			expectedSuccess: true,
			expectedAddress: "::",
		},
		{
			name:             "InvalidIPv6_IPv4Combo",
			qtype:            dns.TypeAAAA,
			subdomain:        "0--1.2.3.4",
			expectedSuccess:  false,
			expectedAddress:  "",
			expectServerFail: true, // Domain parsing rejects dots in labels
		},
		{
			name:            "Invalid_TooSmall",
			qtype:           dns.TypeAAAA,
			subdomain:       "1-2-3-4-5-6-7",
			expectedSuccess: false,
			expectedAddress: "",
		},
		{
			name:            "Invalid_TooBig",
			qtype:           dns.TypeAAAA,
			subdomain:       "1-2-3-4-5-6-7-8-9",
			expectedSuccess: false,
			expectedAddress: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			m := new(dns.Msg)
			m.Question = make([]dns.Question, 1)
			m.Question[0] = dns.Question{Qclass: dns.ClassINET, Name: fmt.Sprintf("%s.%s.%s.", tt.subdomain, peerIDb36, forge), Qtype: tt.qtype}

			r, err := dns.Exchange(m, testInfra.DNSServerAddress)
			if err != nil {
				t.Fatalf("Could not send message: %s", err)
			}

			if !tt.expectedSuccess {
				if tt.expectServerFail {
					if r.Rcode != dns.RcodeServerFailure {
						t.Fatalf("Expected SERVFAIL reply, got %s", dns.RcodeToString[r.Rcode])
					}
				} else {
					if r.Rcode != dns.RcodeSuccess || len(r.Answer) != 0 {
						t.Fatalf("Expected NODATA reply, got %s and answers %+v", dns.RcodeToString[r.Rcode], r.Answer)
					}
				}
				return
			}

			if r.Rcode != dns.RcodeSuccess {
				t.Fatalf("Expected successful reply, got %s", dns.RcodeToString[r.Rcode])
			}

			if len(r.Answer) == 0 {
				if tt.expectedAddress != "" {
					t.Fatal("Expected an address but got none")
				}
				return
			}

			expectedAnswer := fmt.Sprintf(`%s	604800	IN	AAAA	%s`, m.Question[0].Name, tt.expectedAddress)
			if r.Answer[0].String() != expectedAnswer {
				t.Fatalf("Expected %s reply, got %s", expectedAnswer, r.Answer[0].String())
			}
		})
	}
}

func TestLibp2pACMEE2E(t *testing.T) {
	isValidResolvedForgeAddr := func(addr string) bool {
		return strings.Contains(addr, "libp2p.direct/ws")
	}
	isValidShortForgeAddr := func(addr string) bool {
		return strings.Contains(addr, "libp2p.direct/tcp/") && strings.Contains(addr, "/tls/ws")
	}
	defaultAddrCheck := isValidResolvedForgeAddr

	tests := []struct {
		name                    string
		clientOpts              []client.P2PForgeCertMgrOptions
		isValidForgeAddr        func(addr string) bool
		caCertValidityPeriod    uint64        // 0 means default from letsencrypt/pebble/ca/v2#defaultValidityPeriod will be used
		awaitOnCertRenewed      bool          // include renewal test
		expectRegistrationDelay time.Duration // include delayed registration test that fails if registration occured sooner
	}{
		{
			name:             "default opts",
			clientOpts:       []client.P2PForgeCertMgrOptions{},
			isValidForgeAddr: defaultAddrCheck,
		},
		{
			name: "expired cert gets renewed and triggers OnCertRenewed",
			clientOpts: []client.P2PForgeCertMgrOptions{
				// Check every 2s ensures 4+ opportunities to detect renewal during 8.3s renewal window
				client.WithRenewCheckInterval(2 * time.Second),
			},
			isValidForgeAddr: defaultAddrCheck,
			// 25s lifetime creates 8.3s renewal window (CertMagic renews at 1/3 remaining = 25*(1/3))
			caCertValidityPeriod: 25,
			awaitOnCertRenewed:   true,
		},
		{
			name:             "explicit WithShortForgeAddrs(true)",
			clientOpts:       []client.P2PForgeCertMgrOptions{client.WithShortForgeAddrs(true)},
			isValidForgeAddr: isValidShortForgeAddr,
		},
		{
			name:             "explicit WithShortForgeAddrs(false)",
			clientOpts:       []client.P2PForgeCertMgrOptions{client.WithShortForgeAddrs(false)},
			isValidForgeAddr: isValidResolvedForgeAddr,
		},
		{
			name:                    "WithRegistrationDelay() produces a delay",
			clientOpts:              []client.P2PForgeCertMgrOptions{client.WithRegistrationDelay(15 * time.Second)},
			isValidForgeAddr:        defaultAddrCheck,
			expectRegistrationDelay: 15 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Enable full parallelization - all tests are now isolated
			t.Parallel()

			// Skip renewal test in high concurrency scenarios to avoid CertMagic callback timing issues
			if tt.awaitOnCertRenewed && (os.Getenv("GOTESTFLAGS") != "" || testing.Short()) {
				t.Skip("Skipping certificate renewal test in high concurrency mode due to upstream CertMagic timing issues")
			}

			testInfra := NewTestInfrastructure(t)

			db := pebbleDB.NewMemoryStore()
			logger := log.New(os.Stdout, "", 0)
			caProfiles := map[string]pebbleCA.Profile{"default": {Description: "The test profile for " + tt.name, ValidityPeriod: tt.caCertValidityPeriod}}
			ca := pebbleCA.New(logger, db, "", 0, 1, caProfiles)
			va := pebbleVA.New(logger, 0, 0, false, testInfra.DNSServerAddress, db)

			wfeImpl := pebbleWFE.New(logger, db, va, ca, false, false, 3, 5)
			muxHandler := wfeImpl.Handler()

			acmeHTTPListener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer acmeHTTPListener.Close()

			// Generate the self-signed certificate and private key for mocked ACME endpoint
			certPEM, privPEM, err := generateSelfSignedCert("127.0.0.1")
			if err != nil {
				log.Fatalf("Failed to generate self-signed certificate: %v", err)
			}

			// Load the certificate and key into tls.Certificate
			cert, err := tls.X509KeyPair(certPEM, privPEM)
			if err != nil {
				log.Fatalf("Failed to load key pair: %v", err)
			}

			// Create a TLS configuration with the certificate
			tlsConfig := &tls.Config{
				Certificates: []tls.Certificate{cert},
			}

			// Wrap the listener with TLS
			acmeHTTPListener = tls.NewListener(acmeHTTPListener, tlsConfig)

			go func() {
				http.Serve(acmeHTTPListener, muxHandler)
			}()

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			// Create DNS resolver to be used in tests
			resolver := &net.Resolver{
				PreferGo: true,
				Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
					d := net.Dialer{
						Timeout: time.Second * 1,
					}
					log.Printf("p2p-forge/client DNS query to p2p-forge at %s (instead of %s)\n", testInfra.DNSServerAddress, address)
					return d.DialContext(ctx, network, testInfra.DNSServerAddress)
				},
			}

			cas := x509.NewCertPool()
			cas.AppendCertsFromPEM(certPEM)

			acmeEndpoint := fmt.Sprintf("https://%s%s", acmeHTTPListener.Addr(), pebbleWFE.DirectoryPath)
			certLoaded := make(chan bool, 1)
			certRenewed := make(chan bool, 1)

			// Generate unique identity for this specific subtest
			sk, err := generateTestIdentity("TestLibp2pACMEE2E", tt.name)
			if err != nil {
				t.Fatal(err)
			}

			// Create test-specific certificate storage path using URL-safe encoding
			testPath := filepath.Join("cert-storage", t.Name(), tt.name)
			certStoragePath := filepath.Join(testInfra.TmpDir, testPath)

			clientOpts := append([]client.P2PForgeCertMgrOptions{
				client.WithForgeDomain(forge),
				client.WithForgeRegistrationEndpoint(fmt.Sprintf("http://127.0.0.1:%d", testInfra.HTTPPort)),
				client.WithCAEndpoint(acmeEndpoint),
				client.WithTrustedRoots(cas),
				client.WithCertificateStorage(&certmagic.FileStorage{Path: certStoragePath}), // Unique storage per test
				client.WithModifiedForgeRequest(func(req *http.Request) error {
					req.Host = forgeRegistration
					req.Header.Set(authForgeHeader, authToken)
					return nil
				}),
				client.WithAllowPrivateForgeAddrs(),
				client.WithOnCertLoaded(func() {
					select {
					case certLoaded <- true:
					default:
					}
				}),
				client.WithOnCertRenewed(func() {
					select {
					case certRenewed <- true:
					default:
					}
				}),
				client.WithResolver(resolver),
			}, tt.clientOpts...)

			// Create certificate manager with unique identity and storage
			certMgr, err := client.NewP2PForgeCertMgr(clientOpts...)
			if err != nil {
				t.Fatal(err)
			}
			start := time.Now()

			// Use safe wrapper to handle potential CertMagic panics
			safeCertMgrOperation(t, func() {
				certMgr.Start()
			}, "Start")

			// Ensure cleanup happens even if there are panics
			defer func() {
				safeCertMgrOperation(t, func() {
					certMgr.Stop()
				}, "Stop")
			}()

			madnsResolver, err := madns.NewResolver(madns.WithDefaultResolver(resolver))
			if err != nil {
				t.Fatal(err)
			}
			customResolver, err := madns.NewResolver(madns.WithDomainResolver("libp2p.direct.", madnsResolver))
			if err != nil {
				t.Fatal(err)
			}

			// Create libp2p host with unique identity BEFORE providing it to certificate manager
			h, err := libp2p.New(libp2p.ChainOptions(
				libp2p.Identity(sk), // Use unique identity generated for this test
				libp2p.DefaultListenAddrs,
				libp2p.Transport(tcp.NewTCPTransport),
				libp2p.Transport(libp2pquic.NewTransport),
				libp2p.Transport(libp2pwebtransport.New),
				libp2p.Transport(libp2pwebrtc.New),

				libp2p.ListenAddrStrings(
					certMgr.AddrStrings()..., // TODO reuse tcp port for ws
				),
				libp2p.Transport(libp2pws.New, libp2pws.WithTLSConfig(certMgr.TLSConfig())),
				libp2p.AddrsFactory(certMgr.AddressFactory()),
				libp2p.MultiaddrResolver(swarm.ResolverFromMaDNS{Resolver: customResolver}),
			))
			if err != nil {
				t.Fatal(err)
			}

			// Provide the host with unique identity to the certificate manager
			certMgr.ProvideHost(h)

			// Log the unique peer ID for debugging
			t.Logf("Test %s using unique peer ID: %s", tt.name, h.ID().String())

			cp := x509.NewCertPool()
			cp.AddCert(ca.GetRootCert(0).Cert)
			tlsCfgWithTestCA := &tls.Config{RootCAs: cp}

			h2, err := libp2p.New(libp2p.Transport(libp2pws.New, libp2pws.WithTLSClientConfig(tlsCfgWithTestCA)),
				libp2p.MultiaddrResolver(swarm.ResolverFromMaDNS{Resolver: customResolver}))
			if err != nil {
				t.Fatal(err)
			}

			// Wait for certificate with additional safety against CertMagic issues
			select {
			case <-certLoaded:
				t.Logf("Certificate loaded successfully")
			case <-time.After(time.Second*30 + tt.expectRegistrationDelay):
				// Check if this might be due to a CertMagic issue
				t.Fatal("timed out waiting for certificate - this may be due to CertMagic panic recovery")
			}

			// optional WithRegistrationDelay test
			// confirms registration took longer than the delay defined
			if tt.expectRegistrationDelay != 0 {
				remainingDelay := tt.expectRegistrationDelay - time.Since(start)
				if remainingDelay > 0 {
					t.Fatalf("WithRegistrationDelay was expected to delay registration by %s", tt.expectRegistrationDelay)
				}
			}

			var dialAddr multiaddr.Multiaddr
			hAddrs := h.Addrs()
			for _, addr := range hAddrs {
				as := addr.String()
				if strings.Contains(as, "p2p-circuit") {
					continue
				}
				if tt.isValidForgeAddr(as) {
					dialAddr = addr
					break
				}
			}
			if dialAddr == nil {
				t.Fatalf("no valid wss addresses: %v", hAddrs)
			}

			if err := h2.Connect(ctx, peer.AddrInfo{ID: h.ID(), Addrs: []multiaddr.Multiaddr{dialAddr}}); err != nil {
				t.Fatal(err)
			}

			if tt.awaitOnCertRenewed {
				select {
				case <-certRenewed:
					t.Logf("Certificate renewed successfully")
				case <-time.After(60 * time.Second): // 2.4x cert lifetime (60s/25s) handles CertMagic delays and high concurrency
					// This timeout is often hit due to CertMagic issues or high concurrency, so provide helpful context
					t.Fatal("timed out waiting for certificate renewal - this may be due to CertMagic panic recovery, upstream CertMagic issues, or high test concurrency")
				}
			}
		})
	}
}

func generateSelfSignedCert(ipAddr string) ([]byte, []byte, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Test Mocked ACME Endpoint"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(1 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP(ipAddr)},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	privDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, nil, err
	}
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privDER})

	return certPEM, privPEM, nil
}

// Input implements the caddy.Input interface and acts as an easy way to use a string as a Corefile.
type Input struct {
	corefile []byte
}

// NewInput returns a pointer to Input, containing the corefile string as input.
func NewInput(corefile string) *Input {
	return &Input{corefile: []byte(corefile)}
}

// Body implements the Input interface.
func (i *Input) Body() []byte { return i.corefile }

// Path implements the Input interface.
func (i *Input) Path() string { return "Corefile" }

// ServerType implements the Input interface.
func (i *Input) ServerType() string { return "dns" }

// generateTestIdentity creates a unique Ed25519 private key for testing
// based on the test name and current time, ensuring each test run gets a unique peer identity
func generateTestIdentity(testName, subtestName string) (crypto.PrivKey, error) {
	// Create a unique seed from test names + current time to avoid conflicts in -count=N runs
	// Use nanosecond precision to ensure uniqueness even in rapid parallel execution
	combinedName := fmt.Sprintf("%s|%s|%d", testName, subtestName, time.Now().UnixNano())
	testSeed := sha256.Sum256([]byte(combinedName))

	// Use a seeded reader to generate cryptographically valid keys
	// Each test run will get a unique key, preventing conflicts in -count=N scenarios
	seededReader := &deterministicReader{seed: testSeed[:]}

	sk, _, err := crypto.GenerateEd25519Key(seededReader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate test identity for %s: %w", combinedName, err)
	}

	return sk, nil
}

// deterministicReader provides a deterministic source of "randomness" for key generation
type deterministicReader struct {
	seed   []byte
	offset uint64
}

func (d *deterministicReader) Read(p []byte) (n int, err error) {
	for i := range p {
		if len(d.seed) == 0 {
			return i, fmt.Errorf("insufficient seed data")
		}

		// Use a simple but effective method to generate deterministic bytes
		// Hash the seed with the current offset to get new bytes
		offsetBytes := make([]byte, 8)
		binary.LittleEndian.PutUint64(offsetBytes, d.offset)

		h := sha256.New()
		h.Write(d.seed)
		h.Write(offsetBytes)
		result := h.Sum(nil)

		p[i] = result[d.offset%32] // Use offset to cycle through the hash
		d.offset++
	}
	return len(p), nil
}

// safeCertMgrOperation wraps CertMagic operations with panic recovery to provide
// clear error messages when Pebble ACME test server race conditions occur.
//
// This function detects panics from the Pebble ACME test server (used by CertMagic
// for testing) and fails the test with a comprehensive explanation and solution.
//
// NOTE: This is a testing-only issue with the Pebble mock ACME server, not production
// CertMagic or Let's Encrypt. Production usage is not affected by these panics.
func safeCertMgrOperation(t *testing.T, operation func(), operationName string) {
	defer func() {
		if r := recover(); r != nil {
			stack := debug.Stack()

			t.Fatalf(`KNOWN ISSUE: Pebble ACME test server race condition detected during %s

This is a testing-only issue with the Pebble mock ACME server used by CertMagic
for testing. Production CertMagic and Let's Encrypt are not affected.

SOLUTION: Re-run the test - this panic is intermittent and usually resolves on retry.

Original panic: %v

Stack trace:
%s`, operationName, r, stack)
		}
	}()

	operation()
}
