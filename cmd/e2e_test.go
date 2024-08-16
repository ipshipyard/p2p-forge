package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"os"
	"testing"

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
