package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/caddyserver/certmagic"
	logging "github.com/ipfs/go-log/v2"
	"github.com/libp2p/go-libp2p/config"
	"github.com/libp2p/go-libp2p/core/event"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/mholt/acmez/v3"
	"github.com/mholt/acmez/v3/acme"
	ma "github.com/multiformats/go-multiaddr"
	manet "github.com/multiformats/go-multiaddr/net"
	"github.com/multiformats/go-multibase"
)

type P2PForgeCertMgr struct {
	ctx                        context.Context
	cancel                     func()
	forgeDomain                string
	forgeRegistrationEndpoint  string
	registrationDelay          time.Duration
	ProvideHost                func(host.Host)
	hostFn                     func() host.Host
	hasHost                    func() bool
	certmagic                  *certmagic.Config
	log                        *zap.SugaredLogger
	allowPrivateForgeAddresses bool
	produceShortAddrs          bool

	hasCert     bool // tracking if we've received a certificate
	certCheckMx sync.RWMutex

	// onCertLoaded is the user callback for when forge addresses become available.
	// On obtain path: called after cert is ready AND reachability confirmed.
	// On cached path: called immediately after cert loads (ConfirmedAddrs filters).
	onCertLoaded func()

	// certReady signals that a valid certificate is available (closed when ready).
	// Used to coordinate between certmagic's OnEvent (which signals) and Start()
	// (which orchestrates callback timing based on reachability requirements).
	certReady     chan struct{}
	certReadyOnce sync.Once
}

func isRelayAddr(a ma.Multiaddr) bool {
	for _, p := range a {
		if p.Protocol().Code == ma.P_CIRCUIT {
			return true
		}
	}
	return false
}

func isTCPAddr(a ma.Multiaddr) bool {
	for _, p := range a {
		if p.Protocol().Code == ma.P_TCP {
			return true
		}
	}
	return false
}

// isPublicAddr follows the logic of manet.IsPublicAddr, except it uses
// a stricter definition of "public" for ipv6 by excluding nat64 addresses
// and /p2p-circuit ones
func isPublicAddr(a ma.Multiaddr) bool {
	// skip p2p-circuit ones
	for _, p := range a.Protocols() {
		if p.Code == ma.P_CIRCUIT {
			return false
		}
	}

	// public vs private IPs
	ip, err := manet.ToIP(a)
	if err != nil {
		return false
	}
	if ip.To4() != nil {
		return manet.IsPublicAddr(a)
	}

	return manet.IsPublicAddr(a) && !manet.IsNAT64IPv4ConvertedIPv6Addr(a)
}

type P2PForgeCertMgrConfig struct {
	forgeDomain                string
	forgeRegistrationEndpoint  string
	forgeAuth                  string
	caEndpoint                 string
	userEmail                  string
	userAgent                  string
	trustedRoots               *x509.CertPool
	storage                    certmagic.Storage
	modifyForgeRequest         func(r *http.Request) error
	onCertLoaded               func()
	onCertRenewed              func()
	log                        *zap.SugaredLogger
	resolver                   *net.Resolver
	allowPrivateForgeAddresses bool
	produceShortAddrs          bool
	renewCheckInterval         time.Duration
	registrationDelay          time.Duration
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

// WithForgeAuth sets optional secret be sent with requests to the forge
// registration endpoint.
func WithForgeAuth(forgeAuth string) P2PForgeCertMgrOptions {
	return func(config *P2PForgeCertMgrConfig) error {
		config.forgeAuth = forgeAuth
		return nil
	}
}

// WithUserAgent sets custom User-Agent sent to the forge.
func WithUserAgent(userAgent string) P2PForgeCertMgrOptions {
	return func(config *P2PForgeCertMgrConfig) error {
		config.userAgent = userAgent
		return nil
	}
}

/*
// WithHTTPClient sets a custom HTTP Client to be used when talking to registration endpoint.
func WithHTTPClient(h httpClient) error {
	return func(config *P2PForgeCertMgrConfig) error {
		return nil
	}
}
*/

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

// WithOnCertRenewed is optional callback executed on cert renewal event
func WithOnCertRenewed(fn func()) P2PForgeCertMgrOptions {
	return func(config *P2PForgeCertMgrConfig) error {
		config.onCertRenewed = fn
		return nil
	}
}

// WithRenewCheckInterval is meant for testing
func WithRenewCheckInterval(renewCheckInterval time.Duration) P2PForgeCertMgrOptions {
	return func(config *P2PForgeCertMgrConfig) error {
		config.renewCheckInterval = renewCheckInterval
		return nil
	}
}

// WithRegistrationDelay allows delaying initial registration to ensure node was online for a while before requesting TLS cert.
func WithRegistrationDelay(registrationDelay time.Duration) P2PForgeCertMgrOptions {
	return func(config *P2PForgeCertMgrConfig) error {
		config.registrationDelay = registrationDelay
		return nil
	}
}

// WithAllowPrivateForgeAddrs is meant for testing or skipping all the
// connectivity checks libp2p node needs to pass before it can request domain
// and start ACME DNS-01 challenge.
func WithAllowPrivateForgeAddrs() P2PForgeCertMgrOptions {
	return func(config *P2PForgeCertMgrConfig) error {
		config.allowPrivateForgeAddresses = true
		return nil
	}
}

// WithShortForgeAddrs controls if final addresses produced by p2p-forge addr
// factory are short and start with /dnsX or are longer and the DNS name is
// fully resolved into /ipX /sni components.
//
// Using /dnsX may be beneficial when interop with older libp2p clients is
// required, or when shorter addresses are preferred.
//
// Example multiaddr formats:
//   - When true: /dnsX/<escaped-ip>.<peer-id>.<forge-domain>/tcp/<port>/tls/ws
//   - When false:  /ipX/<ip>/tcp/<port>/tls/sni/<escaped-ip>.<peer-id>.<forge-domain>/ws
func WithShortForgeAddrs(produceShortAddrs bool) P2PForgeCertMgrOptions {
	return func(config *P2PForgeCertMgrConfig) error {
		config.produceShortAddrs = produceShortAddrs
		return nil
	}
}

func WithLogger(log *zap.SugaredLogger) P2PForgeCertMgrOptions {
	return func(config *P2PForgeCertMgrConfig) error {
		config.log = log
		return nil
	}
}

// WithResolver allows passing custom DNS resolver to be used for DNS-01 checks.
// By default [net.DefaultResolver] is used.
func WithResolver(resolver *net.Resolver) P2PForgeCertMgrOptions {
	return func(config *P2PForgeCertMgrConfig) error {
		config.resolver = resolver
		return nil
	}
}

// NewP2PForgeCertMgr handles the creation and management of certificates that are automatically granted by a forge
// to a libp2p host.
//
// Calling this function signifies your acceptance to
// the CA's Subscriber Agreement and/or Terms of Service. Let's Encrypt is the default CA.
func NewP2PForgeCertMgr(opts ...P2PForgeCertMgrOptions) (*P2PForgeCertMgr, error) {
	// Init config + apply optional user settings
	mgrCfg := &P2PForgeCertMgrConfig{}
	for _, opt := range opts {
		if err := opt(mgrCfg); err != nil {
			return nil, err
		}
	}

	if mgrCfg.log == nil {
		mgrCfg.log = logging.Logger("p2p-forge/client").Desugar().Sugar()
	}
	if mgrCfg.forgeDomain == "" {
		mgrCfg.forgeDomain = DefaultForgeDomain
	}
	if mgrCfg.caEndpoint == "" {
		mgrCfg.caEndpoint = DefaultCAEndpoint
	} else if mgrCfg.caEndpoint == DefaultCATestEndpoint {
		mgrCfg.log.Errorf("initialized with staging endpoint (%s): certificate won't work correctly in web browser; make sure to change to WithCAEndpoint(DefaultCAEndpoint) (%s) before deploying to production or testing in web browser", DefaultCATestEndpoint, DefaultCAEndpoint)
	}
	if mgrCfg.forgeRegistrationEndpoint == "" {
		if mgrCfg.forgeDomain == DefaultForgeDomain {
			mgrCfg.forgeRegistrationEndpoint = DefaultForgeEndpoint
		} else {
			return nil, fmt.Errorf("must specify the forge registration endpoint if using a non-default forge")
		}
	}
	if mgrCfg.storage == nil {
		mgrCfg.storage = &certmagic.FileStorage{Path: DefaultStorageLocation}
	}

	// Wire up resolver for verifying DNS-01 TXT record got published correctly
	if mgrCfg.resolver == nil {
		mgrCfg.resolver = net.DefaultResolver
	}

	// Wire up p2p-forge manager instance
	hostChan := make(chan host.Host, 1)
	hasHostChan := make(chan struct{})
	hostFn := sync.OnceValue(func() host.Host {
		defer close(hasHostChan)
		return <-hostChan
	})
	// provideHost sends host to channel and immediately resolves hostFn,
	// ensuring hasHost() returns true right after ProvideHost is called.
	// This prevents a race where address factory is called before Start().
	provideHost := func(h host.Host) {
		hostChan <- h
		_ = hostFn()
	}
	hasHostFn := func() bool {
		select {
		case <-hasHostChan:
			return true
		default:
			return false
		}
	}
	mgr := &P2PForgeCertMgr{
		forgeDomain:                mgrCfg.forgeDomain,
		forgeRegistrationEndpoint:  mgrCfg.forgeRegistrationEndpoint,
		ProvideHost:                provideHost,
		hostFn:                     hostFn,
		hasHost:                    hasHostFn,
		log:                        mgrCfg.log,
		allowPrivateForgeAddresses: mgrCfg.allowPrivateForgeAddresses,
		produceShortAddrs:          mgrCfg.produceShortAddrs,
		registrationDelay:          mgrCfg.registrationDelay,
		onCertLoaded:               mgrCfg.onCertLoaded,
		certReady:                  make(chan struct{}),
	}

	// NOTE: callback getter is necessary to avoid circular dependency
	// but also structure code to avoid issues like https://github.com/ipshipyard/p2p-forge/issues/28
	configGetter := func(cert certmagic.Certificate) (*certmagic.Config, error) {
		if mgr.certmagic == nil {
			return nil, errors.New("P2PForgeCertmgr.certmagic is not set")
		}
		return mgr.certmagic, nil
	}

	magicCache := certmagic.NewCache(certmagic.CacheOptions{
		GetConfigForCert:   configGetter,
		RenewCheckInterval: mgrCfg.renewCheckInterval,
		Logger:             mgrCfg.log.Desugar(),
	})

	// Wire up final certmagic config by calling upstream New with sanity checks
	mgr.certmagic = certmagic.New(magicCache, certmagic.Config{
		Storage: mgrCfg.storage,
		Logger:  mgrCfg.log.Desugar(),
	})

	// Wire up Issuer that does brokered DNS-01 ACME challenge
	acmeLog := mgrCfg.log.Named("acme-broker")
	brokeredDNS01Issuer := certmagic.NewACMEIssuer(mgr.certmagic, certmagic.ACMEIssuer{
		CA:     mgrCfg.caEndpoint,
		Email:  mgrCfg.userEmail,
		Agreed: true,
		DNS01Solver: &dns01P2PForgeSolver{
			forgeRegistrationEndpoint:  mgrCfg.forgeRegistrationEndpoint,
			forgeAuth:                  mgrCfg.forgeAuth,
			hostFn:                     mgr.hostFn,
			modifyForgeRequest:         mgrCfg.modifyForgeRequest,
			userAgent:                  mgrCfg.userAgent,
			allowPrivateForgeAddresses: mgrCfg.allowPrivateForgeAddresses,
			log:                        acmeLog.Named("dns01solver"),
			resolver:                   mgrCfg.resolver,
		},
		TrustedRoots: mgrCfg.trustedRoots,
		Logger:       acmeLog.Desugar(),
	})
	mgr.certmagic.Issuers = []certmagic.Issuer{brokeredDNS01Issuer}

	// Wire up certmagic event handler.
	// OnEvent only updates state and signals readiness via channel.
	// The onCertLoaded callback is called by Start() which orchestrates
	// timing based on reachability requirements.
	mgr.certmagic.OnEvent = func(ctx context.Context, event string, data map[string]any) error {
		if event == "cached_managed_cert" {
			sans, ok := data["sans"]
			if !ok {
				return nil
			}
			sanList, ok := sans.([]string)
			if !ok {
				return nil
			}

			name := certName(hostFn().ID(), mgrCfg.forgeDomain)
			for _, san := range sanList {
				if san == name {
					mgr.certCheckMx.Lock()
					mgr.hasCert = true
					mgr.certCheckMx.Unlock()
					// Signal cert readiness (idempotent via sync.Once)
					mgr.certReadyOnce.Do(func() { close(mgr.certReady) })
					break
				}
			}
			return nil
		}

		// Execute user function for certificate renewal
		if event == "cert_obtained" && mgrCfg.onCertRenewed != nil {
			if renewal, ok := data["renewal"].(bool); ok && renewal {
				name := certName(hostFn().ID(), mgrCfg.forgeDomain)
				if id, ok := data["identifier"].(string); ok && id == name {
					mgrCfg.onCertRenewed()
				}
			}
			return nil
		}

		return nil
	}

	return mgr, nil
}

func (m *P2PForgeCertMgr) Start() error {
	if m.certmagic == nil || m.hostFn == nil {
		return errors.New("unable to start without a certmagic and libp2p host")
	}
	if m.certmagic.Storage == nil {
		return errors.New("unable to start without a certmagic Cache and Storage set up")
	}
	m.ctx, m.cancel = context.WithCancel(context.Background())
	go func() {
		start := time.Now()
		log := m.log.Named("start")
		h := m.hostFn()
		name := certName(h.ID(), m.forgeDomain)
		needsReachability := !m.allowPrivateForgeAddresses

		// === Certificate Path Determination ===
		//
		// We have two distinct paths based on certificate state:
		//
		// 1. OBTAIN PATH (no cert in storage, or cert needs renewal):
		//    - CertMagic will contact p2p-forge to register and obtain/renew cert
		//    - p2p-forge verifies node is reachable before setting DNS records
		//    - We MUST wait for AutoNAT to confirm reachability first
		//    - This prevents wasted registration attempts on unreachable nodes
		//
		// 2. CACHED PATH (valid cert in storage, no renewal needed):
		//    - CertMagic just loads cert from disk, no network requests
		//    - Callback fires immediately after cert is loaded
		//    - Address factory's ConfirmedAddrs() filters unreachable addrs dynamically
		//    - This makes subsequent startups near-instant
		//
		certInStorage := m.localCertExists(m.ctx, name)
		certNeedsRenewal := certInStorage && m.localCertNeedsRenewal(m.ctx, name)

		// willObtainCert is true when CertMagic will attempt ACME flow (new or renewal).
		// This requires network requests to p2p-forge, so we must verify reachability first.
		willObtainCert := !certInStorage || certNeedsRenewal

		startCertManagement := func() {
			// Respect WithRegistrationDelay when obtaining new cert
			if willObtainCert && m.registrationDelay != 0 {
				remainingDelay := m.registrationDelay - time.Since(start)
				if remainingDelay > 0 {
					log.Infof("registration delay set to %s, sleeping for remaining %s", m.registrationDelay, remainingDelay)
					time.Sleep(remainingDelay)
				}
			}
			// Start internal certmagic instance
			if err := m.certmagic.ManageAsync(m.ctx, []string{name}); err != nil {
				log.Error(err)
				return
			}
			// On cached path: explicitly set hasCert flag and signal readiness.
			// This handles the race where cached_managed_cert event may not
			// fire if the cert was already in certmagic's in-memory cache.
			// NOTE: We set hasCert immediately for cached path - no reachability
			// blocking. The address factory's ConfirmedAddrs() filtering will
			// dynamically remove unreachable addresses once AutoNAT runs.
			if !willObtainCert {
				m.certCheckMx.Lock()
				m.hasCert = true
				m.certCheckMx.Unlock()
				m.certReadyOnce.Do(func() { close(m.certReady) })
				log.Info("certificate loaded from cache")
			}
		}

		// waitCertReady blocks until cert is available or context cancelled
		waitCertReady := func() bool {
			select {
			case <-m.certReady:
				return true
			case <-m.ctx.Done():
				return false
			}
		}

		// fireCallback invokes user's onCertLoaded if set
		fireCallback := func() {
			if m.onCertLoaded != nil {
				m.onCertLoaded()
			}
		}

		// Log which path we're on
		if !certInStorage {
			log.Infof("no cert found for %q, will obtain from CA", name)
		} else if certNeedsRenewal {
			log.Infof("cert for %q needs renewal, will obtain from CA", name)
		} else {
			log.Infof("valid cert for %q found in storage, using cached path", name)
		}

		// === Flow ===
		//
		// OBTAIN PATH (new cert or renewal):
		//   1. Wait for AutoNAT reachability
		//   2. Start cert management (triggers ACME flow)
		//   3. Wait for cert to be ready
		//   4. Fire callback
		//
		// CACHED PATH (valid cert exists):
		//   1. Load cert from storage, set hasCert immediately
		//   2. Fire callback
		//
		// Address factory's ConfirmedAddrs() filtering handles reachability
		// dynamically - unreachable addresses are filtered as AutoNAT runs.

		// Obtain path: wait for AutoNAT before requesting cert
		if willObtainCert && needsReachability {
			if !waitForAutoNATReachability(m.ctx, log, h) {
				return
			}
		}

		// Start certificate management
		startCertManagement()

		// Obtain path: wait for cert to be ready
		if willObtainCert {
			if !waitCertReady() {
				return
			}
		}

		fireCallback()
	}()
	return nil
}

// waitForAutoNATReachability blocks until AutoNAT confirms public reachability.
// Used for new cert path where we must verify reachability before requesting cert.
// Returns true if reachability was confirmed, false if context was cancelled.
func waitForAutoNATReachability(ctx context.Context, log *zap.SugaredLogger, h host.Host) bool {
	log.Infof("waiting for AutoNAT to confirm public reachability")

	// Subscribe to AutoNAT v2 event for per-address reachability
	addrsReachabilitySub, err := h.EventBus().Subscribe(new(event.EvtHostReachableAddrsChanged))
	if err != nil {
		log.Error(err)
		return false
	}
	defer addrsReachabilitySub.Close()

	for {
		select {
		case e := <-addrsReachabilitySub.Out():
			evt := e.(event.EvtHostReachableAddrsChanged)
			log.Infof("AutoNAT v2 reachable addrs changed: %v", evt.Reachable)
			for _, a := range evt.Reachable {
				if !isRelayAddr(a) && isTCPAddr(a) { // guaranteed to be public
					return true
				}
			}
			log.Infof("no reachable tcp addrs yet")
		case <-ctx.Done():
			if ctx.Err() != context.Canceled {
				log.Error(fmt.Errorf("aborted while waiting for public reachability: %w", ctx.Err()))
			}
			return false
		}
	}
}

func (m *P2PForgeCertMgr) Stop() {
	m.cancel()
}

// TLSConfig returns a tls.Config that managed by the P2PForgeCertMgr
func (m *P2PForgeCertMgr) TLSConfig() *tls.Config {
	tlsCfg := m.certmagic.TLSConfig()
	tlsCfg.NextProtos = nil // remove the ACME ALPN
	tlsCfg.GetCertificate = m.certmagic.GetCertificate
	return tlsCfg
}

func (m *P2PForgeCertMgr) AddrStrings() []string {
	return []string{
		fmt.Sprintf("/ip4/0.0.0.0/tcp/0/tls/sni/*.%s/ws", m.forgeDomain),
		fmt.Sprintf("/ip6/::/tcp/0/tls/sni/*.%s/ws", m.forgeDomain),
	}
}

// AddressFactory returns a function that rewrites a set of forge managed multiaddresses.
// This should be used with the libp2p.AddrsFactory option to ensure that a libp2p host with forge managed addresses
// only announces those that are active and valid.
func (m *P2PForgeCertMgr) AddressFactory() config.AddrsFactory {
	tlsCfg := m.certmagic.TLSConfig()
	tlsCfg.NextProtos = []string{"h2", "http/1.1"} // remove the ACME ALPN and set the HTTP 1.1 and 2 ALPNs

	return m.createAddrsFactory(m.allowPrivateForgeAddresses, m.produceShortAddrs)
}

// localCertExists returns true if a certificate matching passed name is already present in certmagic.Storage
func (m *P2PForgeCertMgr) localCertExists(ctx context.Context, name string) bool {
	cfg := m.certmagic
	if cfg == nil || cfg.Storage == nil || len(cfg.Issuers) == 0 {
		return false
	}
	acmeIssuer, ok := cfg.Issuers[0].(*certmagic.ACMEIssuer)
	if !ok {
		m.log.Errorf("unexpected issuer type %T, expected *certmagic.ACMEIssuer", cfg.Issuers[0])
		return false
	}
	certKey := certmagic.StorageKeys.SiteCert(acmeIssuer.IssuerKey(), name)
	return cfg.Storage.Exists(ctx, certKey)
}

// localCertNeedsRenewal checks if the certificate in storage is within the
// renewal window. CertMagic renews certificates when 1/3 of their lifetime
// remains (~30 days for Let's Encrypt 90-day certs).
//
// We check this to determine if CertMagic will attempt renewal on startup.
// If renewal is needed, the node is effectively on the "obtain path" and we
// should wait for AutoNAT before starting cert management to avoid wasted
// p2p-forge registration attempts on nodes that aren't publicly reachable.
//
// Returns false if cert doesn't exist, can't be loaded, or can't be parsed.
// Caller should use localCertExists() first to distinguish "no cert" from
// "valid cert that doesn't need renewal".
func (m *P2PForgeCertMgr) localCertNeedsRenewal(ctx context.Context, name string) bool {
	cfg := m.certmagic
	if cfg == nil || cfg.Storage == nil || len(cfg.Issuers) == 0 {
		return false
	}

	// Load cert from storage
	acmeIssuer, ok := cfg.Issuers[0].(*certmagic.ACMEIssuer)
	if !ok {
		m.log.Errorf("unexpected issuer type %T, expected *certmagic.ACMEIssuer", cfg.Issuers[0])
		return false
	}
	certKey := certmagic.StorageKeys.SiteCert(acmeIssuer.IssuerKey(), name)
	certData, err := cfg.Storage.Load(ctx, certKey)
	if err != nil {
		m.log.Errorf("failed to load cert for renewal check: %v", err)
		return false
	}

	// Parse PEM-encoded certificate
	block, _ := pem.Decode(certData)
	if block == nil {
		m.log.Errorf("failed to PEM-decode cert for renewal check")
		return false
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		m.log.Errorf("failed to parse cert for renewal check: %v", err)
		return false
	}

	// Check if within renewal window (1/3 of lifetime remaining, matching CertMagic default)
	lifetime := cert.NotAfter.Sub(cert.NotBefore)
	renewalWindow := lifetime / 3
	renewalStart := cert.NotAfter.Add(-renewalWindow)

	return time.Now().After(renewalStart)
}

// certName returns a string with DNS wildcard for use in TLS cert ("*.peerid.forgeDomain")
func certName(id peer.ID, suffixDomain string) string {
	pb36 := peer.ToCid(id).Encode(multibase.MustNewEncoder(multibase.Base36))
	return fmt.Sprintf("*.%s.%s", pb36, suffixDomain)
}

func (m *P2PForgeCertMgr) createAddrsFactory(allowPrivateForgeAddrs bool, produceShortAddrs bool) config.AddrsFactory {
	p2pForgeWssComponent := ma.StringCast(fmt.Sprintf("/tls/sni/*.%s/ws", m.forgeDomain))

	return func(multiaddrs []ma.Multiaddr) []ma.Multiaddr {
		var skipForgeAddrs bool
		if !m.hasHost() {
			skipForgeAddrs = true
		}
		m.certCheckMx.RLock()
		if !m.hasCert {
			skipForgeAddrs = true
		}
		m.certCheckMx.RUnlock()

		return addrFactoryFn(
			skipForgeAddrs,
			m.hostFn,
			m.forgeDomain,
			allowPrivateForgeAddrs,
			produceShortAddrs,
			p2pForgeWssComponent,
			multiaddrs,
			m.log,
		)
	}
}

type dns01P2PForgeSolver struct {
	forgeRegistrationEndpoint  string
	forgeAuth                  string
	hostFn                     func() host.Host
	modifyForgeRequest         func(r *http.Request) error
	userAgent                  string
	allowPrivateForgeAddresses bool
	log                        *zap.SugaredLogger
	resolver                   *net.Resolver
}

func (d *dns01P2PForgeSolver) Wait(ctx context.Context, challenge acme.Challenge) error {
	// Try as long the challenge remains valid.
	// This acts both as sensible timeout and as a way to rate-limit clients using this library.
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()

	// Extract the domain and expected TXT record value from the challenge
	domain := fmt.Sprintf("_acme-challenge.%s", challenge.Identifier.Value)
	expectedTXT := challenge.DNS01KeyAuthorization()
	d.log.Infow("waiting for DNS-01 TXT record to be set", "domain", domain)

	// Check if DNS-01 TXT record is correctly published by the p2p-forge
	// backend. This step ensures we are good citizens: we don't want to move
	// further and bother ACME endpoint with work if we are not confident
	// DNS-01 chalelnge will be successful.
	// We check fast, with backoff to avoid spamming DNS.
	pollInterval := 1 * time.Second
	maxPollInterval := 1 * time.Minute
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("timed out waiting for DNS-01 TXT record to be set at %q: %v", domain, ctx.Err())
		case <-ticker.C:
			pollInterval *= 2
			if pollInterval > maxPollInterval {
				pollInterval = maxPollInterval
			}
			ticker.Reset(pollInterval)
			txtRecords, err := d.resolver.LookupTXT(ctx, domain)
			if err != nil {
				d.log.Debugw("dns lookup error", "domain", domain, "error", err)
				continue
			}
			for _, txt := range txtRecords {
				if txt == expectedTXT {
					d.log.Infow("confirmed TXT record for DNS-01 challenge is set", "domain", domain)
					return nil
				}
			}
			d.log.Debugw("no matching TXT record found yet, sleeping", "domain", domain)
		}
	}
}

func (d *dns01P2PForgeSolver) Present(ctx context.Context, challenge acme.Challenge) error {
	d.log.Debugw("getting DNS-01 challenge value from CA", "acme_challenge", challenge)
	dns01value := challenge.DNS01KeyAuthorization()
	h := d.hostFn()
	addrs := h.Addrs()

	var advertisedAddrs []ma.Multiaddr

	if !d.allowPrivateForgeAddresses {
		var publicAddrs []ma.Multiaddr
		for _, addr := range addrs {
			if isPublicAddr(addr) {
				publicAddrs = append(publicAddrs, addr)
			}
		}

		if len(publicAddrs) == 0 {
			return fmt.Errorf("no public address found")
		}
		advertisedAddrs = publicAddrs
	} else {
		advertisedAddrs = addrs
	}
	d.log.Debugw("advertised libp2p addrs for p2p-forge broker to try", "addrs", advertisedAddrs)

	d.log.Debugw("asking p2p-forge broker to set DNS-01 TXT record", "url", d.forgeRegistrationEndpoint, "dns01_value", dns01value)
	err := SendChallenge(ctx,
		d.forgeRegistrationEndpoint,
		h.Peerstore().PrivKey(h.ID()),
		dns01value,
		advertisedAddrs,
		d.forgeAuth,
		d.userAgent,
		d.modifyForgeRequest,
	)
	if err != nil {
		return fmt.Errorf("p2p-forge broker registration error: %w", err)
	}

	return nil
}

func (d *dns01P2PForgeSolver) CleanUp(ctx context.Context, challenge acme.Challenge) error {
	// TODO: Should we implement this, or is doing delete and Last-Writer-Wins enough?
	return nil
}

var (
	_ acmez.Solver = (*dns01P2PForgeSolver)(nil)
	_ acmez.Waiter = (*dns01P2PForgeSolver)(nil)
)

func addrFactoryFn(skipForgeAddrs bool, hostFn func() host.Host, forgeDomain string, allowPrivateForgeAddrs bool, produceShortAddrs bool, p2pForgeWssComponent ma.Multiaddr, multiaddrs []ma.Multiaddr, log *zap.SugaredLogger) []ma.Multiaddr {
	retAddrs := make([]ma.Multiaddr, 0, len(multiaddrs))
	var unreachableAddrs []ma.Multiaddr
	var peerID peer.ID
	if !skipForgeAddrs {
		// This is pretty ugly. We want the host for determining unreachable addrs. The host wants the address
		// factory to set the signed peer record.
		// Ideally, it'll be fixed with: https://github.com/libp2p/go-libp2p/issues/3300
		h := hostFn()
		if h, ok := h.(interface {
			ConfirmedAddrs() ([]ma.Multiaddr, []ma.Multiaddr, []ma.Multiaddr)
		}); ok {
			_, unreachableAddrs, _ = h.ConfirmedAddrs()
		}
		peerID = h.ID()
	}
OUTER:
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

		// Extract forge address components using the utility function
		forgeAddrInfo, err := ExtractForgeAddrInfo(withoutForgeWSS, peerID)
		if err != nil {
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

		for _, ua := range unreachableAddrs {
			// if the tcp component is unreachable, skip processing this entire multiaddr (continue to next multiaddr in outer loop)
			if ua.Equal(withoutForgeWSS) {
				continue OUTER
			}
		}

		var newMaStr string
		if produceShortAddrs {
			newMaStr = BuildShortForgeMultiaddr(forgeAddrInfo, forgeDomain)
		} else {
			newMaStr = BuildLongForgeMultiaddr(forgeAddrInfo, forgeDomain)
		}
		newMA, err := ma.NewMultiaddr(newMaStr)
		if err != nil {
			log.Errorf("error creating new multiaddr from %q: %s", newMaStr, err.Error())
			retAddrs = append(retAddrs, a)
			continue
		}
		retAddrs = append(retAddrs, newMA)
	}
	return retAddrs
}
