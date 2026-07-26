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
	// it from the internet, for any of this to apply. One that cannot needs
	// the broker and a name-based certificate instead. See WithIPCerts.
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

	// ipCertFallbackGrace bounds how long a node that listens on the ACME port
	// waits for a public address to appear before giving up and using the
	// broker. A node behind a port mapping or a cloud one-to-one NAT does not
	// have its public address on any interface and only learns it from other
	// peers, which takes a few minutes. Deciding before that would send a node
	// that is about to qualify to the broker for good.
	ipCertFallbackGrace = 10 * time.Minute

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
// Certificates land in the same certmagic cache as the brokered wildcard
// certificate, so one tls.Config serves both.
type ipCertMgr struct {
	cfg          *certmagic.Config
	cache        *certmagic.Cache
	storage      certmagic.Storage
	issuerKey    string
	port         int
	allowPrivate bool
	notBefore    time.Time // no first-time issuance before this, see WithRegistrationDelay
	log          *zap.SugaredLogger

	wg sync.WaitGroup // in-flight issuance attempts

	mu             sync.Mutex
	evaluated      bool                     // addresses have been looked at at least once
	listensLocally bool                     // something of ours is bound to the ACME port
	decideBy       time.Time                // when to stop waiting for a public address
	reachable      map[string]struct{}      // addresses libp2p confirmed dialable from outside
	haveEvent      bool                     // a reachability event has arrived
	addrs          map[string]*ipCertStatus // keyed by IP

	fallbackOnce sync.Once
	fallback     chan struct{}
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
		Profile: mgrCfg.ipCertProfile,
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

	m := &ipCertMgr{
		cfg:          cfg,
		cache:        cache,
		storage:      mgrCfg.storage,
		issuerKey:    issuer.IssuerKey(),
		port:         mgrCfg.ipCertPort,
		allowPrivate: mgrCfg.allowPrivateForgeAddresses,
		notBefore:    time.Now().Add(mgrCfg.registrationDelay),
		decideBy:     time.Now().Add(ipCertFallbackGrace),
		log:          log,
		addrs:        make(map[string]*ipCertStatus),
		fallback:     make(chan struct{}),
	}
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
	// next tick, so a node that opted in gets its certificate promptly, and
	// again when the wait for a public address runs out, so a node that never
	// learned one reaches the broker without another full interval of silence.
	delay := time.NewTimer(time.Until(m.notBefore))
	defer delay.Stop()
	decide := time.NewTimer(time.Until(m.decideBy))
	defer decide.Stop()

	m.reconcile(ctx, h)
	for {
		select {
		case <-ctx.Done():
			return
		case <-delay.C:
			m.reconcile(ctx, h)
		case <-decide.C:
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
		reachable[string(a.Bytes())] = struct{}{}
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
		key := string(a.Bytes())
		if filter {
			if _, ok := reachable[key]; !ok {
				continue
			}
		}
		seen[key] = struct{}{}
		out = append(out, a)
	}
	for _, a := range announced {
		key := string(a.Bytes())
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, a)
	}
	return out
}

// reconcile brings the managed set in line with the addresses the host
// currently has, and starts an issuance attempt for every address that needs
// one and is out of backoff.
func (m *ipCertMgr) reconcile(ctx context.Context, h host.Host) {
	eligible := eligibleIPs(m.candidateAddrs(h), m.port, m.allowPrivate)
	listensLocally := listensOnPort(h, m.port)

	var obtain []string
	now := time.Now()

	m.mu.Lock()
	m.evaluated = true
	m.listensLocally = listensLocally
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
	m.checkFallback()
}

// obtain runs one issuance attempt for ip and records the outcome. On success
// the certificate is handed to certmagic, which renews it from then on.
func (m *ipCertMgr) obtain(ctx context.Context, ip string) {
	// Record that an attempt is under way before making it. A process killed
	// mid-attempt leaves this behind, so the next boot waits out the window
	// instead of starting over: without it a crash loop would spend one ACME
	// order per restart, which is the failure the backoff exists to prevent.
	// The real outcome overwrites it below.
	m.mu.Lock()
	inFlight := ipCertBackoff{Failures: m.attemptCount(ip), RetryAfter: time.Now().Add(ipCertObtainWindow)}
	m.mu.Unlock()
	m.saveBackoff(ctx, ip, inFlight)

	err := m.ensureCert(ctx, ip)
	shuttingDown := ctx.Err() != nil

	backoff := inFlight
	var wait time.Duration
	switch {
	case err == nil:
		backoff = ipCertBackoff{}
	case shuttingDown:
		// Not this address's fault. The in-flight record stands and expires
		// on its own within one window.
	default:
		backoff.Failures = inFlight.Failures + 1
		wait = min(ipCertRetryInterval*time.Duration(1<<min(backoff.Failures-1, 16)), ipCertRetryIntervalMax)
		backoff.RetryAfter = time.Now().Add(wait)
	}

	// The status may be gone: the address can leave the eligible set while an
	// attempt runs. The outcome still has to be recorded, both on disk and,
	// when the address is still tracked, in memory.
	m.mu.Lock()
	if st, ok := m.addrs[ip]; ok {
		st.obtaining = false
		if !shuttingDown {
			st.backoff = backoff
			st.managed = err == nil
		}
	}
	m.mu.Unlock()

	switch {
	case err == nil:
		m.clearBackoff(ctx, ip)
		m.log.Infow("serving our own certificate for this address, no broker needed", "ip", ip)
	case shuttingDown:
	default:
		m.saveBackoff(ctx, ip, backoff)
		m.log.Errorw("could not get a certificate for our own address",
			"ip", ip, "attempt", backoff.Failures, "retry_in", wait, "error", err)
	}
	m.checkFallback()
}

// attemptCount returns how many consecutive failures ip has on record.
// Callers hold m.mu.
func (m *ipCertMgr) attemptCount(ip string) int {
	if st, ok := m.addrs[ip]; ok {
		return st.backoff.Failures
	}
	return 0
}

// ensureCert makes ip's certificate exist and stay maintained. An address
// whose certificate is already in storage, after a restart or when a dynamic
// address comes back, is adopted without contacting the CA.
func (m *ipCertMgr) ensureCert(ctx context.Context, ip string) error {
	if !localCertExists(ctx, m.cfg, ip) {
		// One bounded attempt. ObtainCertAsync otherwise retries for up to a
		// month on its own ladder, which for an address the CA cannot reach
		// means a steady stream of failed authorizations; the deadline caps
		// how much of that ladder runs before our own backoff takes over.
		// ObtainCertSync is not an alternative: it prompts on the terminal for
		// an account email when none is configured.
		obtainCtx, cancel := context.WithTimeout(ctx, ipCertObtainWindow)
		defer cancel()
		if err := m.cfg.ObtainCertAsync(obtainCtx, ip); err != nil {
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

// certExpired reports whether every certificate cached for ip has run out,
// which is where a node that was offline past renewal ends up.
//
// Holding nothing is deliberately not the same answer. A certificate handed to
// certmagic takes a moment to land in the cache, and reading that gap as
// expiry would send a node to the broker in the seconds after it successfully
// certified its own address.
func (m *ipCertMgr) certExpired(ip string) bool {
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
	_, port, ok := tlsWSEndpoint(addr)
	return ok && port == m.port
}

// waitForFallback blocks until the broker is needed, which is the case as soon
// as this node has no address it can certify on its own or every such address
// has failed. It returns false when ctx is canceled first.
func (m *ipCertMgr) waitForFallback(ctx context.Context) bool {
	select {
	case <-ctx.Done():
		return false
	case <-m.fallback:
		return true
	}
}

// checkFallback signals for the broker once the addresses we have cannot be
// certified on our own. It fires at most once: from then on the broker
// certificate is worth keeping, while announcements still prefer an address we
// certified ourselves whenever one is available.
//
// The broker is not needed as long as one address is covered or still on its
// way to being covered. A certificate that expired without renewing counts as
// neither, which is what gets a node that was offline past expiry back onto
// the broker rather than leaving it with nothing to announce.
func (m *ipCertMgr) checkFallback() {
	m.mu.Lock()
	needed := m.evaluated
	for ip, st := range m.addrs {
		covered := st.managed && !m.certExpired(ip)
		onTheWay := st.obtaining || (!st.managed && st.backoff.Failures == 0)
		if covered || onTheWay {
			needed = false
			break
		}
	}
	if needed && m.waitingForAddr() {
		needed = false
	}
	m.mu.Unlock()

	if needed {
		m.fallbackOnce.Do(func() { close(m.fallback) })
	}
}

// waitingForAddr reports whether it is too early to say this node cannot
// certify itself. A node that terminates TLS on the port the CA connects to
// qualifies as soon as it learns a public address for that port, and behind a
// port mapping that only happens once other peers have observed it. Deciding
// on the first pass, when nothing is known yet, would commit such a node to
// the broker permanently.
//
// Callers hold m.mu.
func (m *ipCertMgr) waitingForAddr() bool {
	if len(m.addrs) > 0 || !m.listensLocally {
		return false
	}
	// allowPrivate means the caller asked for connectivity checks to be
	// skipped, so there is nothing to wait for.
	return !m.allowPrivate && time.Now().Before(m.decideBy)
}

// listensOnPort reports whether the host has a TCP listener bound to port.
// Validation needs one: the CA connects to that port, and the ACME client
// checks it is in use before trusting somebody else to answer the challenge on
// it.
func listensOnPort(h host.Host, port int) bool {
	want := strconv.Itoa(port)
	for _, a := range h.Network().ListenAddresses() {
		if p, err := a.ValueForProtocol(ma.P_TCP); err == nil && p == want {
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
