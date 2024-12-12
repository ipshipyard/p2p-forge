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
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/ipshipyard/p2p-forge/client"
	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	httppeeridauth "github.com/libp2p/go-libp2p/p2p/http/auth"
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

	// Load CoreDNS + p2p-forge plugins
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

var dnsServerAddress string
var httpPort int

func TestMain(m *testing.M) {
	tmpDir, err := os.MkdirTemp("", "p2p-forge")
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}

	if err := os.Setenv(authEnvVar, authToken); err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}

	defer os.RemoveAll(tmpDir)

	tmpListener, err := net.Listen("tcp", ":0")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	httpPort = tmpListener.Addr().(*net.TCPAddr).Port
	if err := tmpListener.Close(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	dnsserver.Directives = []string{
		"log",
		"whoami",
		"startup",
		"shutdown",
		"ipparser",
		"acme",
	}

	corefile := fmt.Sprintf(`.:0 {
		log
		ipparser %s
		acme %s {
			registration-domain %s listen-address=:%d external-tls=true
			database-type badger %s
        }
	}`, forge, forge, forgeRegistration, httpPort, tmpDir)

	instance, err := caddy.Start(NewInput(corefile))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
	}

	dnsServerAddress = instance.Servers()[0].LocalAddr().String()

	m.Run()

	errs := instance.ShutdownCallbacks()
	err = errors.Join(errs...)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	if err := instance.Stop(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	instance.Wait()
}

// Need to handle <peerID>.forgeDomain to return NODATA rather than NXDOMAIN per https://datatracker.ietf.org/doc/html/rfc8020
func TestRFC8020(t *testing.T) {
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

	r, err := dns.Exchange(m, dnsServerAddress)
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
			domain := fmt.Sprintf("%s.%s.%s.", tt.subdomain, peerIDb36, forge)
			m := new(dns.Msg)
			m.Question = make([]dns.Question, 1)
			m.Question[0] = dns.Question{Qclass: dns.ClassINET, Name: domain, Qtype: tt.qtype}

			r, err := dns.Exchange(m, dnsServerAddress)
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

	req, err := client.ChallengeRequest(ctx, fmt.Sprintf("http://127.0.0.1:%d", httpPort), testChallenge, h.Addrs())
	if err != nil {
		t.Fatal(err)
	}
	req.Host = forgeRegistration
	req.Header.Set(authForgeHeader, authToken)

	peerHTTPClient := &httppeeridauth.ClientPeerIDAuth{PrivKey: sk}
	_, resp, err := peerHTTPClient.AuthenticatedDo(http.DefaultClient, req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		t.Fatal(fmt.Errorf("%s : %s", resp.Status, respBody))
	}

	peerIDb36, err := peer.ToCid(h.ID()).StringOfBase(multibase.Base36)
	if err != nil {
		t.Fatal(err)
	}

	m := new(dns.Msg)
	m.Question = make([]dns.Question, 1)
	m.Question[0] = dns.Question{Qclass: dns.ClassINET, Name: fmt.Sprintf("_acme-challenge.%s.%s.", peerIDb36, forge), Qtype: dns.TypeTXT}

	r, err := dns.Exchange(m, dnsServerAddress)
	if err != nil {
		t.Fatalf("Could not send message: %s", err)
	}
	if r.Rcode != dns.RcodeSuccess || len(r.Answer) == 0 {
		t.Fatalf("Expected successful reply, got %s", dns.RcodeToString[r.Rcode])
	}
	expectedAnswer := fmt.Sprintf(`%s	3600	IN	TXT	"%s"`, m.Question[0].Name, testChallenge)
	if r.Answer[0].String() != expectedAnswer {
		t.Fatalf("Expected %s reply, got %s", expectedAnswer, r.Answer[0].String())
	}
}

func TestIPv4Lookup(t *testing.T) {
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
		name            string
		qtype           uint16
		subdomain       string
		expectedSuccess bool
		expectedAddress string
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
			expectedAddress: "11.222.33.4",
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
			qtype:           dns.TypeANY,
			subdomain:       "1-2-3-4-5",
			expectedSuccess: false,
			expectedAddress: "",
		},
		{
			name:            "InvalidIPv4_1-2-3",
			qtype:           dns.TypeANY,
			subdomain:       "1-2-3",
			expectedSuccess: false,
			expectedAddress: "",
		},
		{
			name:            "InvalidIPv4_1-2-3-444",
			qtype:           dns.TypeANY,
			subdomain:       "1-2-3-444",
			expectedSuccess: false,
			expectedAddress: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := new(dns.Msg)
			m.Question = make([]dns.Question, 1)
			m.Question[0] = dns.Question{Qclass: dns.ClassINET, Name: fmt.Sprintf("%s.%s.%s.", tt.subdomain, peerIDb36, forge), Qtype: tt.qtype}

			r, err := dns.Exchange(m, dnsServerAddress)
			if err != nil {
				t.Fatalf("Could not send message: %s", err)
			}

			if !tt.expectedSuccess {
				if r.Rcode != dns.RcodeServerFailure || len(r.Answer) != 0 {
					t.Fatalf("Expected failed reply, got %s and answers %+v", dns.RcodeToString[r.Rcode], r.Answer)
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

			expectedAnswer := fmt.Sprintf(`%s	86400	IN	A	%s`, m.Question[0].Name, tt.expectedAddress)
			if r.Answer[0].String() != expectedAnswer {
				t.Fatalf("Expected %s reply, got %s", expectedAnswer, r.Answer[0].String())
			}
		})
	}
}

func TestIPv6Lookup(t *testing.T) {
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
		name            string
		qtype           uint16
		subdomain       string
		expectedSuccess bool
		expectedAddress string
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
			expectedAddress: "1234:5678:90ab:cdef:1:22:33:444",
		},
		{
			name:            "AAAA",
			qtype:           dns.TypeAAAA,
			subdomain:       "0--1",
			expectedSuccess: true,
			expectedAddress: "::1",
		},
		{
			name:            "Invalid_Starting0",
			qtype:           dns.TypeANY,
			subdomain:       "--1",
			expectedSuccess: false,
			expectedAddress: "",
		},
		{
			name:            "Invalid_Ending0",
			qtype:           dns.TypeANY,
			subdomain:       "0--",
			expectedSuccess: false,
			expectedAddress: "",
		},
		{
			name:            "InvalidIPv6_IPv4Combo",
			qtype:           dns.TypeANY,
			subdomain:       "0--1.2.3.4",
			expectedSuccess: false,
			expectedAddress: "",
		},
		{
			name:            "Invalid_TooSmall",
			qtype:           dns.TypeANY,
			subdomain:       "1-2-3-4-5-6-7",
			expectedSuccess: false,
			expectedAddress: "",
		},
		{
			name:            "Invalid_TooBig",
			qtype:           dns.TypeANY,
			subdomain:       "1-2-3-4-5-6-7-8-9",
			expectedSuccess: false,
			expectedAddress: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := new(dns.Msg)
			m.Question = make([]dns.Question, 1)
			m.Question[0] = dns.Question{Qclass: dns.ClassINET, Name: fmt.Sprintf("%s.%s.%s.", tt.subdomain, peerIDb36, forge), Qtype: tt.qtype}

			r, err := dns.Exchange(m, dnsServerAddress)
			if err != nil {
				t.Fatalf("Could not send message: %s", err)
			}

			if !tt.expectedSuccess {
				if r.Rcode != dns.RcodeServerFailure || len(r.Answer) != 0 {
					t.Fatalf("Expected failed reply, got %s and answers %+v", dns.RcodeToString[r.Rcode], r.Answer)
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

			expectedAnswer := fmt.Sprintf(`%s	86400	IN	AAAA	%s`, m.Question[0].Name, tt.expectedAddress)
			if r.Answer[0].String() != expectedAnswer {
				t.Fatalf("Expected %s reply, got %s", expectedAnswer, r.Answer[0].String())
			}
		})
	}
}

func TestLibp2pACMEE2E(t *testing.T) {
	db := pebbleDB.NewMemoryStore()
	logger := log.New(os.Stdout, "", 0)
	ca := pebbleCA.New(logger, db, "", 0, 1, 0)
	va := pebbleVA.New(logger, 0, 0, false, dnsServerAddress, db)

	wfeImpl := pebbleWFE.New(logger, db, va, ca, false, false, 3, 5)
	muxHandler := wfeImpl.Handler()

	acmeHTTPListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer acmeHTTPListener.Close()

	// Generate the self-signed certificate and private key
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

	cas := x509.NewCertPool()
	cas.AppendCertsFromPEM(certPEM)

	acmeEndpoint := fmt.Sprintf("https://%s%s", acmeHTTPListener.Addr(), pebbleWFE.DirectoryPath)
	certLoaded := make(chan bool, 1)

	certMgr, err := client.NewP2PForgeCertMgr(
		client.WithForgeDomain(forge), client.WithForgeRegistrationEndpoint(fmt.Sprintf("http://127.0.0.1:%d", httpPort)), client.WithCAEndpoint(acmeEndpoint), client.WithTrustedRoots(cas),
		client.WithModifiedForgeRequest(func(req *http.Request) error {
			req.Host = forgeRegistration
			req.Header.Set(authForgeHeader, authToken)
			return nil
		}),
		client.WithAllowPrivateForgeAddrs(),
		client.WithOnCertLoaded(func() {
			certLoaded <- true
		}))
	if err != nil {
		t.Fatal(err)
	}
	certMgr.Start()
	defer certMgr.Stop()

	h, err := libp2p.New(libp2p.ChainOptions(
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
	))
	if err != nil {
		t.Fatal(err)
	}
	certMgr.ProvideHost(h)

	cp := x509.NewCertPool()
	cp.AddCert(ca.GetRootCert(0).Cert)
	tlsCfgWithTestCA := &tls.Config{RootCAs: cp}

	localDnsResolver, err := madns.NewResolver(madns.WithDefaultResolver(&net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{
				Timeout: time.Second * 5, // Set a timeout for the connection
			}
			return d.DialContext(ctx, network, dnsServerAddress)
		},
	}))
	if err != nil {
		t.Fatal(err)
	}
	customResolver, err := madns.NewResolver(madns.WithDomainResolver("libp2p.direct.", localDnsResolver))
	if err != nil {
		t.Fatal(err)
	}

	h2, err := libp2p.New(libp2p.Transport(libp2pws.New, libp2pws.WithTLSClientConfig(tlsCfgWithTestCA)),
		libp2p.MultiaddrResolver(swarm.ResolverFromMaDNS{Resolver: customResolver}))
	if err != nil {
		t.Fatal(err)
	}

	select {
	case <-certLoaded:
	case <-time.After(time.Second * 30):
		t.Fatal("timed out waiting for certificate")
	}

	var dialAddr multiaddr.Multiaddr
	hAddrs := h.Addrs()
	for _, addr := range hAddrs {
		as := addr.String()
		if strings.Contains(as, "p2p-circuit") {
			continue
		}
		if strings.Contains(as, "libp2p.direct/ws") {
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
			Organization: []string{"My Organization"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour), // Valid for 1 year
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
