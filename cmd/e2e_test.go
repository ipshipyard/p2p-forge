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
	libp2pws "github.com/libp2p/go-libp2p/p2p/transport/websocket"
	"github.com/multiformats/go-multiaddr"
	madns "github.com/multiformats/go-multiaddr-dns"
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
	"github.com/miekg/dns"
	"github.com/multiformats/go-multibase"

	_ "github.com/coredns/coredns/core/plugin" // Load all managed plugins in github.com/coredns/coredns.
	_ "github.com/ipshipyard/p2p-forge/acme"
	_ "github.com/ipshipyard/p2p-forge/ipparser"

	pebbleCA "github.com/letsencrypt/pebble/v2/ca"
	pebbleDB "github.com/letsencrypt/pebble/v2/db"
	pebbleVA "github.com/letsencrypt/pebble/v2/va"
	pebbleWFE "github.com/letsencrypt/pebble/v2/wfe"
)

const forge = "libp2p.direct"

var dnsServerAddress string
var httpPort int

func TestMain(m *testing.M) {
	tmpDir, err := os.MkdirTemp("", "p2p-forge")
	if err != nil {
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
		acme %s :%d badger %s
	}`, forge, forge, httpPort, tmpDir)

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

	if err := client.SendChallenge(ctx, fmt.Sprintf("http://127.0.0.1:%d", httpPort), h.ID(), sk, testChallenge, h.Addrs()); err != nil {
		t.Fatal(err)
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
			expectedSuccess: false,
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

			if r.Rcode != dns.RcodeSuccess || len(r.Answer) == 0 {
				t.Fatalf("Expected successful reply, got %s", dns.RcodeToString[r.Rcode])
			}
			expectedAnswer := fmt.Sprintf(`%s	3600	IN	A	%s`, m.Question[0].Name, tt.expectedAddress)
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
			expectedSuccess: false,
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

			if r.Rcode != dns.RcodeSuccess || len(r.Answer) == 0 {
				t.Fatalf("Expected successful reply, got %s", dns.RcodeToString[r.Rcode])
			}
			expectedAnswer := fmt.Sprintf(`%s	3600	IN	AAAA	%s`, m.Question[0].Name, tt.expectedAddress)
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
	h, err := client.NewHostWithP2PForge(forge, fmt.Sprintf("http://127.0.0.1:%d", httpPort), acmeEndpoint, "foo@bar.com", cas, func() {
		certLoaded <- true
	}, true)
	if err != nil {
		t.Fatal(err)
	}

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
		libp2p.MultiaddrResolver(customResolver))
	if err != nil {
		t.Fatal(err)
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

	select {
	case <-certLoaded:
	case <-time.After(time.Second * 30):
		t.Fatal("timed out waiting for certificate")
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
