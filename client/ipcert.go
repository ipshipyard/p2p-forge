package client

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/libp2p/go-libp2p/core/event"
	"github.com/libp2p/go-libp2p/core/host"
	ma "github.com/multiformats/go-multiaddr"
	manet "github.com/multiformats/go-multiaddr/net"
	"go.uber.org/zap"
)

const (
	// DefaultIPCertPort is the TCP port a CA connects to when it validates an
	// IP address with the ACME TLS-ALPN-01 challenge. The challenge is defined
	// on port 443 only (RFC 8737, section 3), and CAs cannot offer DNS-01 for
	// an IP address because there is no name to put the record under
	// (RFC 8738, section 4).
	//
	// A libp2p host therefore has to listen on this port, and be dialable on
	// it from the internet, for any of this to apply. Listening on it is also
	// what decides the path: a host that does, certifies its own address and
	// uses no broker; a host that does not, registers a name with one. See
	// WithIPCerts.
	DefaultIPCertPort = 443

	// DefaultIPCertProfile is the ACME profile requested for IP certificates.
	// Let's Encrypt issues them only under its short-lived profile, valid for
	// 160 hours: https://letsencrypt.org/docs/profiles/
	DefaultIPCertProfile = "shortlived"
)

const (
	// ipCertObtainWindow bounds one issuance attempt. certmagic retries inside
	// the window on its own ladder (first retry after a minute), so the window
	// decides how many ACME authorizations a single failure can spend: at most
	// two here, and only the first goes to the production CA because certmagic
	// switches to the CA's staging endpoint on every retry. Let's Encrypt
	// allows five failed authorizations per address per hour, and
	// ipCertRetryInterval keeps consecutive windows an hour apart.
	ipCertObtainWindow = 2 * time.Minute

	// ipCertRetryInterval is the wait after a failed attempt before the same
	// address is tried again, doubling per consecutive failure up to
	// ipCertRetryIntervalMax. Slow on purpose: an address that fails
	// validation is almost always one the CA cannot reach, which retrying does
	// not fix, and every attempt spends part of the CA's failure budget.
	ipCertRetryInterval = 1 * time.Hour

	// ipCertRetryIntervalMax caps the backoff so an address that becomes
	// reachable again is picked up within a day.
	ipCertRetryIntervalMax = 24 * time.Hour

	// ipCertReconcileInterval re-evaluates addresses even when libp2p reports
	// no change, so an address whose backoff has expired is retried and a
	// certificate that went away is noticed.
	ipCertReconcileInterval = 5 * time.Minute

	// ipCertNoAddressGrace is how long a node gets to learn a public address
	// before the absence of one is worth reporting. libp2p has nothing to say
	// at the moment a daemon starts, and a node behind a router hears its
	// address from other peers a few minutes in.
	ipCertNoAddressGrace = 2 * time.Minute

	// ipCertNoAddressInterval is how often a node that listens on the ACME port
	// but has no public address there says so. It is an error an operator has
	// to act on, usually a closed port or a missing forward, and there is no
	// second path to fall back to, so it is repeated rather than mentioned
	// once and lost in the scrollback.
	ipCertNoAddressInterval = 1 * time.Hour

	// ipCertBackoffPrefix is where per-address backoff state is kept in
	// certmagic storage. It has to survive process restarts: nothing else
	// does, and a node that crash-loops would otherwise start a fresh attempt
	// on every boot and blow through the CA's failure budget in minutes.
	ipCertBackoffPrefix = "ipcert_backoff"
)

// ipCertMgr obtains and maintains certificates for the node's own public IP
// addresses (RFC 8738). Validation is answered by the TLS listener the node
// already runs: the CA connects to the very address it is being asked to
// certify, so there is no broker, no DNS name, and no third party involved.
//
// A host on this path has no second source of certificates. When issuance
// fails it is retried with a growing wait and reported as an error, rather
// than quietly swapped for a brokered name nobody asked for.
type ipCertMgr struct {
	cfg          *certmagic.Config
	cache        *certmagic.Cache
	storage      certmagic.Storage
	issuerKey    string
	port         int
	obtainWindow time.Duration // ipCertObtainWindow, shortened by tests
	allowPrivate bool
	notBefore    time.Time // no first-time issuance before this, see WithRegistrationDelay
	log          *zap.SugaredLogger

	wg sync.WaitGroup // in-flight issuance attempts

	// direct records whether this host certifies its own address. It starts
	// true, because that is what enabling the option asks for, and Start turns
	// it off if the host turns out to have no listener to validate on. Getting
	// it wrong in that direction is the safe one: while it is true a TLS
	// listener with no certificate yet is withheld rather than announced as
	// something clients cannot complete a handshake with.
	direct atomic.Bool

	mu            sync.Mutex
	reachable     map[string]struct{}      // addresses libp2p confirmed dialable from outside
	haveEvent     bool                     // a reachability event has arrived
	addrs         map[string]*ipCertStatus // keyed by IP
	lastNoAddrLog time.Time                // rate limit for the no-address error
	started       time.Time                // when this manager began looking
}

// ipCertStatus is the per-address bookkeeping that keeps us inside the CA's
// rate limits: certmagic tracks the certificate, we track how hard we are
// allowed to ask for it.
type ipCertStatus struct {
	managed   bool // handed to certmagic for renewal
	obtaining bool // an attempt is in flight
	backoff   ipCertBackoff
}

// ipCertBackoff is the part of the status that outlives the process.
type ipCertBackoff struct {
	Failures   int       `json:"failures"`
	RetryAfter time.Time `json:"retryAfter"`
}

// newIPCertMgr wires a certmagic config that issues IP certificates through
// the ACME TLS-ALPN-01 challenge only. HTTP-01 is left disabled: it is served
// on port 80, one more port to expose and one more listener to run, while
// TLS-ALPN-01 is answered by the TLS listener the node already has. Leaving
// both enabled also lets the ACME client pick HTTP-01 first and spend a failed
// authorization before falling back.
func newIPCertMgr(cache *certmagic.Cache, mgrCfg *P2PForgeCertMgrConfig, log *zap.SugaredLogger) *ipCertMgr {
	cfg := certmagic.New(cache, certmagic.Config{
		Storage: mgrCfg.storage,
		Logger:  log.Desugar(),
	})
	issuer := certmagic.NewACMEIssuer(cfg, certmagic.ACMEIssuer{
		CA:      mgrCfg.caEndpoint,
		Email:   mgrCfg.userEmail,
		Agreed:  true,
		Profile: *mgrCfg.ipCertProfile,
		// The CA always dials the port the challenge is defined on, so
		// pointing certmagic's own challenge listener at the port we already
		// listen on makes its bind fail, and certmagic then leaves answering
		// to that listener. This is how certmagic is meant to share a port.
		AltTLSALPNPort:       mgrCfg.ipCertPort,
		DisableHTTPChallenge: true,
		TrustedRoots:         mgrCfg.trustedRoots,
		Logger:               log.Desugar(),
	})
	cfg.Issuers = []certmagic.Issuer{issuer}

	// WithOnCertLoaded and WithOnCertRenewed mean the same thing on this path
	// as on the brokered one, so they fire here too. The brokered config has
	// its own handler and matches on the forge name; this one matches on any
	// address, which is all this config ever holds.
	cfg.OnEvent = func(_ context.Context, event string, data map[string]any) error {
		switch event {
		case "cached_managed_cert":
			if mgrCfg.onCertLoaded == nil {
				return nil
			}
			if sans, ok := data["sans"].([]string); ok && containsIP(sans) {
				mgrCfg.onCertLoaded()
			}
		case "cert_obtained":
			if mgrCfg.onCertRenewed == nil {
				return nil
			}
			renewal, _ := data["renewal"].(bool)
			id, _ := data["identifier"].(string)
			if renewal && certmagic.SubjectIsIP(id) {
				mgrCfg.onCertRenewed()
			}
		}
		return nil
	}

	m := &ipCertMgr{
		cfg:          cfg,
		cache:        cache,
		storage:      mgrCfg.storage,
		issuerKey:    issuer.IssuerKey(),
		port:         mgrCfg.ipCertPort,
		obtainWindow: ipCertObtainWindow,
		allowPrivate: mgrCfg.allowPrivateForgeAddresses,
		notBefore:    time.Now().Add(mgrCfg.registrationDelay),
		started:      time.Now(),
		log:          log,
		addrs:        make(map[string]*ipCertStatus),
	}
	m.direct.Store(true)
	// Serve an IP certificate to clients that dial an IP literal, which send
	// no SNI, even when the socket they reach is bound to a different address.
	cfg.CertSelection = m
	return m
}

// start runs the reconcile loop until ctx is canceled, and returns once every
// issuance attempt it started has finished. Attempts are bounded by
// ipCertObtainWindow and cut short when ctx is canceled, so shutdown does not
// hang on a slow CA.
func (m *ipCertMgr) start(ctx context.Context, h host.Host) {
	defer m.wg.Wait()

	var events <-chan any
	sub, err := h.EventBus().Subscribe([]any{
		new(event.EvtLocalAddressesUpdated),
		new(event.EvtHostReachableAddrsChanged),
	})
	if err != nil {
		// The ticker still reconciles, just with more lag, so this is not fatal.
		m.log.Errorf("could not subscribe to libp2p address events, polling every %s instead: %s", ipCertReconcileInterval, err)
	} else {
		defer sub.Close()
		events = sub.Out()
	}

	ticker := time.NewTicker(ipCertReconcileInterval)
	defer ticker.Stop()

	// Wake up when the registration delay is over rather than waiting for the
	// next tick, so a node that opted in gets its certificate promptly.
	delay := time.NewTimer(time.Until(m.notBefore))
	defer delay.Stop()

	m.reconcile(ctx, h)
	for {
		select {
		case <-ctx.Done():
			return
		case <-delay.C:
			m.reconcile(ctx, h)
		case <-ticker.C:
			m.reconcile(ctx, h)
		case e, ok := <-events:
			if !ok {
				events = nil
				continue
			}
			if evt, ok := e.(event.EvtHostReachableAddrsChanged); ok {
				m.setReachable(evt.Reachable)
			}
			m.reconcile(ctx, h)
		}
	}
}

// setReachable records the addresses libp2p has confirmed are dialable from
// outside. Once autonat has spoken we trust nothing else: an address the node
// merely believes it has is not worth spending a CA failure budget on.
func (m *ipCertMgr) setReachable(addrs []ma.Multiaddr) {
	reachable := make(map[string]struct{}, len(addrs))
	for _, a := range addrs {
		if key, ok := endpointKey(a); ok {
			reachable[key] = struct{}{}
		}
	}
	m.mu.Lock()
	m.reachable = reachable
	m.haveEvent = true
	m.mu.Unlock()
}

// candidateAddrs returns the addresses to consider for certification: the ones
// the host found for itself, and the ones its operator told it to announce.
//
// The two sources answer different questions and both are needed. What the
// host found includes addresses learned from other peers, which is the only
// place a node behind a port mapping sees its public address, and it is taken
// before the address factory runs: a listener whose only announced form is a
// TLS WebSocket address is withheld until a certificate exists, so reading the
// announced set alone would hide the very address that qualifies the node.
// What the operator announced covers the other direction, a node that has been
// told its public address because nothing on the box can discover it.
//
// An address the host discovered is dropped once libp2p reports it as not
// reachable from outside, since asking a CA to validate it would only spend
// the failure budget. An address the operator put in the config is left alone:
// that is a deliberate statement about reachability, and getting it wrong
// costs a backed-off retry rather than anything worse.
func (m *ipCertMgr) candidateAddrs(h host.Host) []ma.Multiaddr {
	announced := h.Addrs()
	discovered := announced
	if allAddrs, ok := h.(interface{ AllAddrs() []ma.Multiaddr }); ok {
		discovered = allAddrs.AllAddrs()
	}

	m.mu.Lock()
	haveEvent, reachable := m.haveEvent, m.reachable
	m.mu.Unlock()

	// allowPrivate is the same escape hatch as WithAllowPrivateForgeAddrs: it
	// skips the connectivity checks entirely, which is what a test on loopback
	// needs. An empty reachable set is also not something to act on, since it
	// is what a node reports before autonat has an opinion.
	filter := haveEvent && !m.allowPrivate && len(reachable) > 0

	out := make([]ma.Multiaddr, 0, len(discovered)+len(announced))
	seen := make(map[string]struct{}, len(discovered)+len(announced))
	for _, a := range discovered {
		if filter {
			key, ok := endpointKey(a)
			if !ok {
				continue
			}
			if _, ok := reachable[key]; !ok {
				continue
			}
		}
		seen[string(a.Bytes())] = struct{}{}
		out = append(out, a)
	}
	for _, a := range announced {
		if _, ok := seen[string(a.Bytes())]; ok {
			continue
		}
		seen[string(a.Bytes())] = struct{}{}
		out = append(out, a)
	}
	return out
}

// endpointKey names the socket an address points at: its IP and TCP port, with
// everything layered on top left out. libp2p reports the same socket under
// different addresses depending on what runs over it, so comparing whole
// addresses would drop one libp2p confirmed as reachable purely because it
// carries a TLS WebSocket suffix and our copy does not.
func endpointKey(a ma.Multiaddr) (string, bool) {
	ip, err := manet.ToIP(a)
	if err != nil {
		return "", false
	}
	port, err := a.ValueForProtocol(ma.P_TCP)
	if err != nil {
		return "", false
	}
	return ip.String() + "/tcp/" + port, true
}

// reconcile brings the managed set in line with the addresses the host
// currently has, and starts an issuance attempt for every address that needs
// one and is out of backoff.
func (m *ipCertMgr) reconcile(ctx context.Context, h host.Host) {
	eligible := eligibleIPs(m.candidateAddrs(h), m.port, m.allowPrivate)

	var obtain []string
	now := time.Now()

	m.mu.Lock()
	for ip, st := range m.addrs {
		if _, ok := eligible[ip]; ok {
			continue
		}
		if st.obtaining {
			// An attempt is still running for this address. Dropping it now
			// would lose the outcome, including a certificate that certmagic
			// would then renew forever with nobody left to stop it. The next
			// pass cleans it up.
			continue
		}
		// The host no longer has this address, so stop renewing its
		// certificate. The certificate stays in storage: an address that comes
		// back, which is what a dynamic IP does, is adopted again without
		// asking the CA for anything.
		delete(m.addrs, ip)
		m.cache.RemoveManaged([]certmagic.SubjectIssuer{{Subject: ip, IssuerKey: m.issuerKey}})
		m.log.Infow("stopped maintaining a certificate, the address is gone", "ip", ip)
	}
	for ip := range eligible {
		st, ok := m.addrs[ip]
		if !ok {
			st = &ipCertStatus{backoff: m.loadBackoff(ctx, ip)}
			m.addrs[ip] = st
		}
		if st.managed && m.certExpired(ip) {
			// certmagic owns renewal, and it has given up or never managed
			// it. Nothing else is going to fix this, so take the address back
			// and let the attempt path have another go under its own backoff.
			m.log.Errorw("our certificate for this address ran out and was not renewed, asking for a new one",
				"ip", ip)
			st.managed = false
			st.backoff = ipCertBackoff{}
		}
		if st.managed || st.obtaining || now.Before(st.backoff.RetryAfter) {
			continue
		}
		// A node that has not been up for long yet may not be up for long at
		// all, and a certificate spent on it is one the CA cannot hand out
		// again this week. An address we already hold a certificate for skips
		// the wait: adopting it costs the CA nothing.
		if now.Before(m.notBefore) && !localCertExists(ctx, m.cfg, ip) {
			m.log.Debugw("waiting before asking for a certificate for our own address",
				"ip", ip, "waiting_for", time.Until(m.notBefore).Round(time.Second))
			continue
		}
		st.obtaining = true
		obtain = append(obtain, ip)
	}
	m.mu.Unlock()

	for _, ip := range obtain {
		m.wg.Go(func() { m.obtain(ctx, ip) })
	}
	if len(eligible) == 0 {
		m.reportNoAddress()
	}
}

// obtain runs one issuance attempt for ip and records the outcome. On success
// the certificate is handed to certmagic, which renews it from then on.
func (m *ipCertMgr) obtain(ctx context.Context, ip string) {
	m.mu.Lock()
	before := m.backoffFor(ip)
	m.mu.Unlock()

	// Write the failure that this attempt would earn before making it, so a
	// process killed mid-attempt leaves the wait behind. Without it a node
	// that keeps dying on boot spends an ACME order every time it comes up,
	// which is the one thing this backoff exists to prevent. Success and a
	// clean shutdown both undo it below.
	failed := nextBackoff(before)
	m.saveBackoff(ctx, ip, failed)

	err := m.ensureCert(ctx, ip)
	shuttingDown := ctx.Err() != nil

	outcome := failed
	switch {
	case err == nil:
		outcome = ipCertBackoff{}
	case shuttingDown:
		// We are stopping, which says nothing about this address, so put back
		// the wait it had before. A restart then picks up where it left off
		// rather than sitting out an hour it did not earn.
		outcome = before
	}

	// The status may be gone: an address can leave the eligible set while an
	// attempt runs. The outcome is still recorded on disk, and in memory when
	// the address is still tracked.
	m.mu.Lock()
	if st, ok := m.addrs[ip]; ok {
		st.obtaining = false
		st.backoff = outcome
		st.managed = err == nil
	}
	m.mu.Unlock()

	switch {
	case err == nil:
		m.clearBackoff(ctx, ip)
		m.log.Infow("serving our own certificate for this address", "ip", ip)
	case shuttingDown:
		if outcome.Failures == 0 {
			m.clearBackoff(ctx, ip)
		} else {
			m.saveBackoff(ctx, ip, outcome)
		}
	default:
		m.log.Errorw("could not get a certificate for our own address",
			"ip", ip, "attempt", outcome.Failures,
			"retry_in", time.Until(outcome.RetryAfter).Round(time.Second), "error", err)
	}
}

// backoffFor returns the wait ip is currently under. Callers hold m.mu.
func (m *ipCertMgr) backoffFor(ip string) ipCertBackoff {
	if st, ok := m.addrs[ip]; ok {
		return st.backoff
	}
	return ipCertBackoff{}
}

// nextBackoff returns the wait that follows one more failed attempt: an hour
// after the first, doubling from there, and never more than a day so an
// address that becomes reachable again is picked up the same day.
func nextBackoff(current ipCertBackoff) ipCertBackoff {
	failures := current.Failures + 1
	wait := min(ipCertRetryInterval*time.Duration(1<<min(failures-1, 16)), ipCertRetryIntervalMax)
	return ipCertBackoff{Failures: failures, RetryAfter: time.Now().Add(wait)}
}

// ensureCert makes ip's certificate exist and stay maintained. An address
// whose certificate is already in storage, after a restart or when a dynamic
// address comes back, is adopted without contacting the CA.
func (m *ipCertMgr) ensureCert(ctx context.Context, ip string) error {
	// One bounded attempt, whichever kind is called for. The async calls
	// otherwise retry for up to a month on certmagic's own ladder, which for an
	// address the CA cannot reach means a steady stream of failed
	// authorizations; the deadline caps how much of that ladder runs before our
	// own backoff takes over. The sync calls are not an alternative: they
	// prompt on the terminal for an account email when none is configured.
	obtainCtx, cancel := context.WithTimeout(ctx, m.obtainWindow)
	defer cancel()

	switch {
	case !localCertExists(ctx, m.cfg, ip):
		if err := m.cfg.ObtainCertAsync(obtainCtx, ip); err != nil {
			return err
		}
	case m.expiredInCache(ip):
		// Asking to obtain would do nothing here. certmagic treats a name
		// whose files are already in storage as settled, however long ago the
		// certificate ran out, so replacing it has to be asked for as a
		// renewal.
		if err := m.cfg.RenewCertAsync(obtainCtx, ip, false); err != nil {
			return err
		}
	}
	// Hand the certificate to certmagic's maintenance loop, which renews it
	// from here on. IP certificates are short-lived (160 hours at Let's
	// Encrypt), so a node has to stay online to keep one fresh.
	return m.cfg.ManageAsync(ctx, []string{ip})
}

// backoffKey is where ip's backoff record lives in certmagic storage.
func backoffKey(ip string) string {
	return ipCertBackoffPrefix + "/" + certmagic.StorageKeys.Safe(ip) + ".json"
}

// loadBackoff reads ip's persisted backoff. A missing or unreadable record
// means no backoff, which is the same state a first-time address is in.
func (m *ipCertMgr) loadBackoff(ctx context.Context, ip string) ipCertBackoff {
	b, err := m.storage.Load(ctx, backoffKey(ip))
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			m.log.Debugw("could not read the stored backoff for an address", "ip", ip, "error", err)
		}
		return ipCertBackoff{}
	}
	var backoff ipCertBackoff
	if err := json.Unmarshal(b, &backoff); err != nil {
		m.log.Debugw("could not parse the stored backoff for an address", "ip", ip, "error", err)
		return ipCertBackoff{}
	}
	return backoff
}

func (m *ipCertMgr) saveBackoff(ctx context.Context, ip string, backoff ipCertBackoff) {
	b, err := json.Marshal(backoff)
	if err != nil {
		return
	}
	if err := m.storage.Store(ctx, backoffKey(ip), b); err != nil {
		m.log.Debugw("could not store the backoff for an address", "ip", ip, "error", err)
	}
}

func (m *ipCertMgr) clearBackoff(ctx context.Context, ip string) {
	if err := m.storage.Delete(ctx, backoffKey(ip)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		m.log.Debugw("could not clear the backoff for an address", "ip", ip, "error", err)
	}
}

// certExpired reports whether every certificate cached for ip has run out,
// which is where a node that was offline past renewal ends up.
//
// Holding nothing is deliberately not the same answer. A certificate handed to
// certmagic takes a moment to land in the cache, and reading that gap as expiry
// would have this ask for a replacement seconds after a successful issuance.
//
// Callers hold m.mu.
func (m *ipCertMgr) certExpired(ip string) bool {
	return m.expiredInCache(ip)
}

// expiredInCache is certExpired without the locking convention, for callers
// that hold nothing.
func (m *ipCertMgr) expiredInCache(ip string) bool {
	certs := m.cache.AllMatchingCertificates(ip)
	if len(certs) == 0 {
		return false
	}
	for _, cert := range certs {
		if !cert.Expired() {
			return false
		}
	}
	return true
}

// hasCertFor reports whether an unexpired certificate for ip is loaded and
// ready to serve. Called for every address announcement, so it only consults
// the in-memory cache.
func (m *ipCertMgr) hasCertFor(ip string) bool {
	for _, cert := range m.cache.AllMatchingCertificates(ip) {
		if !cert.Expired() {
			return true
		}
	}
	return false
}

// containsIP reports whether any of names is an IP address.
func containsIP(names []string) bool {
	for _, name := range names {
		if certmagic.SubjectIsIP(name) {
			return true
		}
	}
	return false
}

// SelectCertificate implements certmagic.CertSelection.
//
// certmagic reaches this only when its own lookup came up empty. The case that
// matters is a client dialing an IP literal: those carry no SNI, so certmagic
// matches on the local address of the accepted connection, which is not the
// certified address on a node behind NAT or a cloud one-to-one mapping. Any
// unexpired certificate we hold for an address of the same family is a better
// answer than none.
func (m *ipCertMgr) SelectCertificate(hello *tls.ClientHelloInfo, choices []certmagic.Certificate) (certmagic.Certificate, error) {
	// A name was asked for. certmagic looked for one covering it before
	// asking us, so the choices here may well be for something else entirely;
	// handing one of those out just moves the failure to the client, which is
	// what certmagic does without a selector installed.
	if hello.ServerName != "" {
		for _, cert := range choices {
			if !cert.Expired() && hello.SupportsCertificate(&cert.Certificate) == nil {
				return cert, nil
			}
		}
		return certmagic.Certificate{}, fmt.Errorf("no certificate for %q", hello.ServerName)
	}

	// No name: the client dialed an address. Pick a certificate for an address
	// of the same family, lowest first so a node holding several makes the
	// same choice every time rather than one at the mercy of map ordering.
	var best *certmagic.Certificate
	wantV4 := localIPIsV4(hello)
	for i, cert := range choices {
		if cert.Expired() || !certCoversIPFamily(cert, wantV4) {
			continue
		}
		if hello.SupportsCertificate(&cert.Certificate) != nil {
			continue
		}
		if best == nil || cert.Names[0] < best.Names[0] {
			best = &choices[i]
		}
	}
	if best != nil {
		return *best, nil
	}
	return certmagic.DefaultCertificateSelector(hello, choices)
}

// certCoversIPFamily reports whether cert has an IP address of the wanted
// family among its names.
func certCoversIPFamily(cert certmagic.Certificate, wantV4 bool) bool {
	for _, name := range cert.Names {
		ip := net.ParseIP(name)
		if ip == nil {
			continue
		}
		if (ip.To4() != nil) == wantV4 {
			return true
		}
	}
	return false
}

// localIPIsV4 reports whether the handshake arrived on an IPv4 socket.
func localIPIsV4(hello *tls.ClientHelloInfo) bool {
	if hello.Conn == nil {
		return true
	}
	host, _, err := net.SplitHostPort(hello.Conn.LocalAddr().String())
	if err != nil {
		return true
	}
	ip := net.ParseIP(host)
	return ip == nil || ip.To4() != nil
}

// rewriteAddr replaces a TLS WebSocket listener address with the form clients
// can dial using the certificate we hold for that address: no DNS name, no
// SNI, just the IP. The second return value reports whether addr was handled
// here; when false the caller applies its usual broker rewrite.
//
// A certificate covers an address, not a port, so every TLS listener on that
// address can be announced this way, not only the one the CA validated
// against.
func (m *ipCertMgr) rewriteAddr(addr ma.Multiaddr) (ma.Multiaddr, bool) {
	ip, port, ok := tlsWSEndpoint(addr)
	if !ok || !m.hasCertFor(ip) {
		return nil, false
	}
	rewritten, err := ma.NewMultiaddr(fmt.Sprintf("/ip%s/%s/tcp/%d/tls/ws", ipVersion(ip), ip, port))
	if err != nil {
		m.log.Errorw("could not build an address for our own certificate", "ip", ip, "error", err)
		return nil, false
	}
	return rewritten, true
}

// covers reports whether addr is a TLS WebSocket listener on the port we
// certify ourselves on. Such an address is not announced until the certificate
// exists: a TLS endpoint without one cannot complete a handshake, so
// announcing it early only earns failed dials.
func (m *ipCertMgr) covers(addr ma.Multiaddr) bool {
	if !m.direct.Load() {
		// This host took the broker path, so no certificate for an address is
		// ever coming and withholding the listener would silence it for good.
		return false
	}
	_, port, ok := tlsWSEndpoint(addr)
	return ok && port == m.port
}

// useBroker records that this host has no listener to be validated on, so its
// addresses are announced as libp2p reports them rather than withheld while a
// certificate that is never coming is waited for.
func (m *ipCertMgr) useBroker() {
	m.direct.Store(false)
}

// reportNoAddress complains that this node listens where a certificate
// authority would validate it but has no public address there to certify.
//
// There is nowhere else to go from here: this node opted out of the broker by
// listening on the port, so the only outcomes are that the address turns up or
// that somebody fixes the network. Saying so once at startup would bury it, so
// it repeats every ipCertNoAddressInterval until the situation changes.
func (m *ipCertMgr) reportNoAddress() {
	m.mu.Lock()
	if time.Since(m.started) < ipCertNoAddressGrace {
		m.mu.Unlock()
		return
	}
	due := time.Since(m.lastNoAddrLog) >= ipCertNoAddressInterval || m.lastNoAddrLog.IsZero()
	if due {
		m.lastNoAddrLog = time.Now()
	}
	m.mu.Unlock()

	if !due {
		return
	}
	m.log.Errorw("no public address on the port a certificate authority validates, so this node has no certificate and browsers cannot reach it; check that the port is open to the internet and forwarded to this node",
		"port", m.port, "next_report_in", ipCertNoAddressInterval)
}

// listensOnPort reports whether this host can answer a TLS-ALPN-01 challenge on
// port, which is what commits it to certifying its own address.
//
// It takes more than a TCP listener on the right number. The challenge is
// answered inside a TLS handshake, so the listener has to be one that
// terminates TLS; a plain libp2p TCP listener on the same port cannot, and a
// host with only that would be asking a CA for something it can never prove.
// The bind address matters too: a listener on loopback is not somewhere a
// public CA can reach, so it counts only when the caller has asked for the
// connectivity checks to be skipped.
func listensOnPort(h host.Host, port int, allowPrivate bool) bool {
	for _, a := range h.Network().ListenAddresses() {
		ip, listenPort, ok := tlsWSEndpoint(a)
		if !ok || listenPort != port {
			continue
		}
		if allowPrivate {
			return true
		}
		// A wildcard bind covers every interface this host has, including
		// whichever one the world reaches it on.
		if parsed := net.ParseIP(ip); parsed != nil && (parsed.IsUnspecified() || !parsed.IsLoopback()) {
			return true
		}
	}
	return false
}

// eligibleIPs returns the public IP addresses this node can be validated at:
// the CA has to reach them from the internet on the port it connects to.
//
// The port here is the announced one. A node behind a port mapping has its
// public address nowhere on its interfaces, so the address has to come from
// what other peers observed. The node does still have to listen on the same
// port locally, which listensOnPort checks separately: the ACME client refuses
// to leave the challenge to a port nothing is bound to.
func eligibleIPs(addrs []ma.Multiaddr, port int, allowPrivate bool) map[string]struct{} {
	out := make(map[string]struct{}, len(addrs))
	for _, a := range addrs {
		if isRelayAddr(a) {
			continue
		}
		if !allowPrivate && !isPublicAddr(a) {
			continue
		}
		p, err := a.ValueForProtocol(ma.P_TCP)
		if err != nil || p != strconv.Itoa(port) {
			continue
		}
		ip, err := manet.ToIP(a)
		if err != nil {
			continue
		}
		out[ip.String()] = struct{}{}
	}
	return out
}

// tlsWSEndpoint reports the IP and TCP port of a TLS WebSocket listener
// address, in either the plain /tls/ws form or the /tls/sni/<name>/ws one.
// Anything else is not ours to rewrite.
func tlsWSEndpoint(addr ma.Multiaddr) (ip string, port int, ok bool) {
	var hasTLS, hasWS bool
	for _, c := range addr {
		switch c.Protocol().Code {
		case ma.P_TLS:
			hasTLS = true
		case ma.P_WS:
			hasWS = true
		case ma.P_WSS:
			hasTLS, hasWS = true, true
		}
	}
	if !hasTLS || !hasWS {
		return "", 0, false
	}
	netIP, err := manet.ToIP(addr)
	if err != nil {
		return "", 0, false
	}
	p, err := addr.ValueForProtocol(ma.P_TCP)
	if err != nil {
		return "", 0, false
	}
	port, err = strconv.Atoi(p)
	if err != nil {
		return "", 0, false
	}
	return netIP.String(), port, true
}

// ipVersion returns the multiaddr protocol suffix for an IP address, 4 or 6.
func ipVersion(ip string) string {
	if parsed := net.ParseIP(ip); parsed != nil && parsed.To4() != nil {
		return "4"
	}
	return "6"
}
