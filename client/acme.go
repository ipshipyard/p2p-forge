package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	httppeeridauth "github.com/libp2p/go-libp2p/p2p/http/auth"

	"github.com/caddyserver/certmagic"
	logging "github.com/ipfs/go-log/v2"
	"github.com/libp2p/go-libp2p/config"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/mholt/acmez/v2"
	"github.com/mholt/acmez/v2/acme"
	"github.com/multiformats/go-multiaddr"
	manet "github.com/multiformats/go-multiaddr/net"
	"github.com/multiformats/go-multibase"
)

var log = logging.Logger("p2p-forge/client")

type P2PForgeCertMgr struct {
	ctx                       context.Context
	cancel                    func()
	forgeDomain               string
	forgeRegistrationEndpoint string
	ProvideHost               func(host.Host)
	hostFn                    func() host.Host
	hasHost                   func() bool
	cfg                       *certmagic.Config

	hasCert     bool // tracking if we've received a certificate
	certCheckMx sync.RWMutex
}

type P2PForgeHostConfig struct {
	certMgrOpts            []P2PForgeCertMgrOptions
	allowPrivateForgeAddrs bool
}

type P2PForgeHostOptions func(*P2PForgeHostConfig)

func WithP2PForgeCertMgrOptions(opts ...P2PForgeCertMgrOptions) P2PForgeHostOptions {
	return func(h *P2PForgeHostConfig) {
		h.certMgrOpts = append(h.certMgrOpts, opts...)
	}
}

// WithAllowPrivateForgeAddrs is meant for testing
func WithAllowPrivateForgeAddrs() P2PForgeHostOptions {
	return func(h *P2PForgeHostConfig) {
		h.allowPrivateForgeAddrs = true
	}
}

func isRelayAddr(a multiaddr.Multiaddr) bool {
	found := false
	multiaddr.ForEach(a, func(c multiaddr.Component) bool {
		found = c.Protocol().Code == multiaddr.P_CIRCUIT
		return !found
	})
	return found
}

// isPublicAddr follows the logic of manet.IsPublicAddr, except it uses
// a stricter definition of "public" for ipv6 by excluding nat64 addresses.
func isPublicAddr(a multiaddr.Multiaddr) bool {
	ip, err := manet.ToIP(a)
	if err != nil {
		return false
	}
	if ip.To4() != nil {
		return manet.IsPublicAddr(a)
	}

	return manet.IsPublicAddr(a) && !manet.IsNAT64IPv4ConvertedIPv6Addr(a)
}

func inAddrRange(ip net.IP, ipnets []*net.IPNet) bool {
	for _, ipnet := range ipnets {
		if ipnet.Contains(ip) {
			return true
		}
	}

	return false
}

type P2PForgeCertMgrConfig struct {
	forgeDomain               string
	forgeRegistrationEndpoint string
	caEndpoint                string
	userEmail                 string
	trustedRoots              *x509.CertPool
	storage                   certmagic.Storage
	modifyForgeRequest        func(r *http.Request) error
	onCertLoaded              func()
}

type P2PForgeCertMgrOptions func(*P2PForgeCertMgrConfig) error

func WithOnCertLoaded(fn func()) P2PForgeCertMgrOptions {
	return func(config *P2PForgeCertMgrConfig) error {
		config.onCertLoaded = fn
		return nil
	}
}

func WithForgeDomain(domain string) P2PForgeCertMgrOptions {
	return func(config *P2PForgeCertMgrConfig) error {
		config.forgeDomain = domain
		return nil
	}
}

func WithForgeRegistrationEndpoint(endpoint string) P2PForgeCertMgrOptions {
	return func(config *P2PForgeCertMgrConfig) error {
		config.forgeRegistrationEndpoint = endpoint
		return nil
	}
}

func WithCAEndpoint(caEndpoint string) P2PForgeCertMgrOptions {
	return func(config *P2PForgeCertMgrConfig) error {
		config.caEndpoint = caEndpoint
		return nil
	}
}

func WithCertificateStorage(storage certmagic.Storage) P2PForgeCertMgrOptions {
	return func(config *P2PForgeCertMgrConfig) error {
		config.storage = storage
		return nil
	}
}

func WithUserEmail(email string) P2PForgeCertMgrOptions {
	return func(config *P2PForgeCertMgrConfig) error {
		config.userEmail = email
		return nil
	}
}

// WithModifiedForgeRequest enables modifying how the ACME DNS challenges are sent to the forge, such as to enable
// custom HTTP headers, etc.
func WithModifiedForgeRequest(fn func(req *http.Request) error) P2PForgeCertMgrOptions {
	return func(config *P2PForgeCertMgrConfig) error {
		config.modifyForgeRequest = fn
		return nil
	}
}

// WithTrustedRoots is meant for testing
func WithTrustedRoots(trustedRoots *x509.CertPool) P2PForgeCertMgrOptions {
	return func(config *P2PForgeCertMgrConfig) error {
		config.trustedRoots = trustedRoots
		return nil
	}
}

// NewP2PForgeCertMgr handles the creation and management of certificates that are automatically granted by a forge
// to a libp2p host.
//
// Calling this function signifies your acceptance to
// the CA's Subscriber Agreement and/or Terms of Service. Let's Encrypt is the default CA.
func NewP2PForgeCertMgr(opts ...P2PForgeCertMgrOptions) (*P2PForgeCertMgr, error) {
	mgrCfg := &P2PForgeCertMgrConfig{}
	for _, opt := range opts {
		if err := opt(mgrCfg); err != nil {
			return nil, err
		}
	}

	const libp2pDirectName = "libp2p.direct"
	const libp2pDirectRegistrationEndpoint = "https://registration.libp2p.direct"
	if mgrCfg.forgeDomain == "" {
		mgrCfg.forgeDomain = "libp2p.direct"
	}
	if mgrCfg.caEndpoint == "" {
		mgrCfg.caEndpoint = certmagic.LetsEncryptProductionCA
	}
	if mgrCfg.forgeRegistrationEndpoint == "" {
		if mgrCfg.forgeDomain == libp2pDirectName {
			mgrCfg.forgeRegistrationEndpoint = libp2pDirectRegistrationEndpoint
		} else {
			return nil, fmt.Errorf("must specify the forge registration endpoint if using a non-default forge")
		}
	}

	const defaultStorageLocation = "p2p-forge-certs"
	if mgrCfg.storage == nil {
		mgrCfg.storage = &certmagic.FileStorage{Path: defaultStorageLocation}
	}

	certCfg := certmagic.NewDefault()
	certCfg.Storage = mgrCfg.storage
	hostChan := make(chan host.Host, 1)
	provideHost := func(host host.Host) { hostChan <- host }
	hasHostChan := make(chan struct{})
	hasHostFn := func() bool {
		select {
		case <-hasHostChan:
			return true
		default:
			return false
		}
	}
	hostFn := sync.OnceValue(func() host.Host {
		defer close(hasHostChan)
		return <-hostChan
	})

	myACME := certmagic.NewACMEIssuer(certCfg, certmagic.ACMEIssuer{ // TODO: UX around user passed emails + agreement
		CA:           mgrCfg.caEndpoint,
		Email:        mgrCfg.userEmail,
		Agreed:       true,
		DNS01Solver:  &dns01P2PForgeSolver{mgrCfg.forgeRegistrationEndpoint, hostFn, mgrCfg.modifyForgeRequest},
		TrustedRoots: mgrCfg.trustedRoots,
	})
	certCfg.Issuers = []certmagic.Issuer{myACME}

	mgr := &P2PForgeCertMgr{
		forgeDomain:               mgrCfg.forgeDomain,
		forgeRegistrationEndpoint: mgrCfg.forgeRegistrationEndpoint,
		ProvideHost:               provideHost,
		hostFn:                    hostFn,
		hasHost:                   hasHostFn,
		cfg:                       certCfg,
	}

	if mgrCfg.onCertLoaded != nil {
		certCfg.OnEvent = func(ctx context.Context, event string, data map[string]any) error {
			if event == "cached_managed_cert" {
				sans, ok := data["sans"]
				if !ok {
					return nil
				}
				sanList, ok := sans.([]string)
				if !ok {
					return nil
				}
				peerID := hostFn().ID()
				pidStr := peer.ToCid(peerID).Encode(multibase.MustNewEncoder(multibase.Base36))
				certName := fmt.Sprintf("*.%s.%s", pidStr, mgrCfg.forgeDomain)
				for _, san := range sanList {
					if san == certName {
						// When the certificate is loaded mark that it has been so we know we are good to use the domain name
						// TODO: This won't handle if the cert expires and cannot get renewed
						mgr.certCheckMx.Lock()
						mgr.hasCert = true
						mgr.certCheckMx.Unlock()
						// Execute user function for on certificate load
						mgrCfg.onCertLoaded()
					}
				}
				return nil
			}
			return nil
		}
	}

	return mgr, nil
}

func (m *P2PForgeCertMgr) Start() error {
	m.ctx, m.cancel = context.WithCancel(context.Background())
	go func() {
		pb36 := peer.ToCid(m.hostFn().ID()).Encode(multibase.MustNewEncoder(multibase.Base36))

		if err := m.cfg.ManageAsync(m.ctx, []string{fmt.Sprintf("*.%s.%s", pb36, m.forgeDomain)}); err != nil {
			log.Error(err)
		}
	}()
	return nil
}

func (m *P2PForgeCertMgr) Stop() {
	m.cancel()
}

// TLSConfig returns a tls.Config that managed by the P2PForgeCertMgr
func (m *P2PForgeCertMgr) TLSConfig() *tls.Config {
	tlsCfg := m.cfg.TLSConfig()
	tlsCfg.NextProtos = nil // remove the ACME ALPN
	return tlsCfg
}

func (m *P2PForgeCertMgr) AddrStrings() []string {
	return []string{fmt.Sprintf("/ip4/0.0.0.0/tcp/0/tls/sni/*.%s/ws", m.forgeDomain),
		fmt.Sprintf("/ip6/::/tcp/0/tls/sni/*.%s/ws", m.forgeDomain),
	}
}

// AddressFactory returns a function that rewrites a set of forge managed multiaddresses.
// This should be used with the libp2p.AddrsFactory option to ensure that a libp2p host with forge managed addresses
// only announces those that are active and valid.
func (m *P2PForgeCertMgr) AddressFactory(opts ...P2PForgeHostOptions) config.AddrsFactory {
	cfg := &P2PForgeHostConfig{}
	for _, opt := range opts {
		opt(cfg)
	}

	tlsCfg := m.cfg.TLSConfig()
	tlsCfg.NextProtos = []string{"h2", "http/1.1"} // remove the ACME ALPN and set the HTTP 1.1 and 2 ALPNs

	return m.createAddrsFactory(cfg.allowPrivateForgeAddrs)
}

func (m *P2PForgeCertMgr) createAddrsFactory(allowPrivateForgeAddrs bool) config.AddrsFactory {
	var p2pForgeWssComponent = multiaddr.StringCast(fmt.Sprintf("/tls/sni/*.%s/ws", m.forgeDomain))

	return func(multiaddrs []multiaddr.Multiaddr) []multiaddr.Multiaddr {
		var skipForgeAddrs bool
		if !m.hasHost() {
			skipForgeAddrs = true
		}
		m.certCheckMx.RLock()
		if !m.hasCert {
			skipForgeAddrs = true
		}
		m.certCheckMx.RUnlock()

		return addrFactoryFn(skipForgeAddrs, func() peer.ID { return m.hostFn().ID() }, m.forgeDomain, allowPrivateForgeAddrs, p2pForgeWssComponent, multiaddrs)
	}
}

type dns01P2PForgeSolver struct {
	forge              string
	hostFn             func() host.Host
	modifyForgeRequest func(r *http.Request) error
}

func (d *dns01P2PForgeSolver) Wait(ctx context.Context, challenge acme.Challenge) error {
	// TODO: query the authoritative DNS
	time.Sleep(time.Second * 5)
	return nil
}

func (d *dns01P2PForgeSolver) Present(ctx context.Context, challenge acme.Challenge) error {
	host := d.hostFn()
	req, err := ChallengeRequest(ctx, d.forge, challenge.DNS01KeyAuthorization(), host.Addrs())
	if err != nil {
		return err
	}
	if d.modifyForgeRequest != nil {
		if err := d.modifyForgeRequest(req); err != nil {
			return err
		}
	}

	client := &httppeeridauth.ClientPeerIDAuth{PrivKey: host.Peerstore().PrivKey(host.ID())}
	_, resp, err := client.AuthenticatedDo(http.DefaultClient, req)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("%s : %s", resp.Status, respBody)
	}
	return nil
}

func (d *dns01P2PForgeSolver) CleanUp(ctx context.Context, challenge acme.Challenge) error {
	//TODO: Should we implement this, or is doing delete and Last-Writer-Wins enough?
	return nil
}

var _ acmez.Solver = (*dns01P2PForgeSolver)(nil)
var _ acmez.Waiter = (*dns01P2PForgeSolver)(nil)

func addrFactoryFn(skipForgeAddrs bool, peerIDFn func() peer.ID, forgeDomain string, allowPrivateForgeAddrs bool, p2pForgeWssComponent multiaddr.Multiaddr, multiaddrs []multiaddr.Multiaddr) []multiaddr.Multiaddr {
	retAddrs := make([]multiaddr.Multiaddr, 0, len(multiaddrs))
	for _, a := range multiaddrs {
		if isRelayAddr(a) {
			retAddrs = append(retAddrs, a)
			continue
		}

		// We expect the address to be of the form: /ipX/<IP address>/tcp/<Port>/tls/sni/*.<forge-domain>/ws
		// We'll then replace the * with the IP address
		withoutForgeWSS := a.Decapsulate(p2pForgeWssComponent)
		if withoutForgeWSS.Equal(a) {
			retAddrs = append(retAddrs, a)
			continue
		}

		index := 0
		var escapedIPStr string
		var ipMaStr string
		var tcpPortStr string
		multiaddr.ForEach(withoutForgeWSS, func(c multiaddr.Component) bool {
			switch index {
			case 0:
				switch c.Protocol().Code {
				case multiaddr.P_IP4:
					ipMaStr = c.String()
					ipAddr := c.Value()
					escapedIPStr = strings.ReplaceAll(ipAddr, ".", "-")
				case multiaddr.P_IP6:
					ipMaStr = c.String()
					ipAddr := c.Value()
					escapedIPStr = strings.ReplaceAll(ipAddr, ":", "-")
					if escapedIPStr[0] == '-' {
						escapedIPStr = "0" + escapedIPStr
					}
					if escapedIPStr[len(escapedIPStr)-1] == '-' {
						escapedIPStr = escapedIPStr + "0"
					}
				default:
					return false
				}
			case 1:
				if c.Protocol().Code != multiaddr.P_TCP {
					return false
				}
				tcpPortStr = c.Value()
			default:
				index++
				return false
			}
			index++
			return true
		})
		if index != 2 || escapedIPStr == "" || tcpPortStr == "" {
			retAddrs = append(retAddrs, a)
			continue
		}

		// It looks like it's a valid forge address, now figure out if we skip these forge addresses
		if skipForgeAddrs {
			continue
		}

		// don't return non-public forge addresses unless explicitly opted in
		if !allowPrivateForgeAddrs && !isPublicAddr(a) {
			continue
		}

		pidStr := peer.ToCid(peerIDFn()).Encode(multibase.MustNewEncoder(multibase.Base36))

		newMaStr := fmt.Sprintf("%s/tcp/%s/tls/sni/%s.%s.%s/ws", ipMaStr, tcpPortStr, escapedIPStr, pidStr, forgeDomain)
		newMA, err := multiaddr.NewMultiaddr(newMaStr)
		if err != nil {
			log.Errorf("error creating new multiaddr from %q: %s", newMaStr, err.Error())
			retAddrs = append(retAddrs, a)
			continue
		}
		retAddrs = append(retAddrs, newMA)
	}
	return retAddrs
}
