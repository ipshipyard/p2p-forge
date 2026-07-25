package client

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"slices"
	"time"

	"github.com/mholt/acmez/v3"
	"github.com/mholt/acmez/v3/acme"
	"go.uber.org/zap"
)

// waitForTXT polls DNS until the DNS-01 TXT record for challenge appears, or a
// deadline passes. It lets the client confirm the forge published the record
// before telling the CA to validate, so a failed publish does not burn an ACME
// attempt. Shared by the /v1 and /v2 solvers.
func waitForTXT(ctx context.Context, resolver *net.Resolver, log *zap.SugaredLogger, challenge acme.Challenge) error {
	// Bound the wait: a sensible timeout and a light rate limit on this client.
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()

	domain := fmt.Sprintf("_acme-challenge.%s", challenge.Identifier.Value)
	expectedTXT := challenge.DNS01KeyAuthorization()
	log.Infow("waiting for DNS-01 TXT record to be set", "domain", domain)

	// Poll with backoff to avoid spamming DNS.
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
			txtRecords, err := resolver.LookupTXT(ctx, domain)
			if err != nil {
				log.Debugw("dns lookup error", "domain", domain, "error", err)
				continue
			}
			if slices.Contains(txtRecords, expectedTXT) {
				log.Infow("confirmed TXT record for DNS-01 challenge is set", "domain", domain)
				return nil
			}
			log.Debugw("no matching TXT record found yet, sleeping", "domain", domain)
		}
	}
}

// HTTPBrokeredDNS01SolverConfig configures NewHTTPBrokeredDNS01Solver. Only the
// first three fields are required.
type HTTPBrokeredDNS01SolverConfig struct {
	// ForgeEndpoint is the forge registration base URL, e.g.
	// https://registration.libp2p.direct.
	ForgeEndpoint string
	// Key signs the registration request.
	Key SigningKey
	// Origins are the node's public http(s) origins where it serves its
	// ownership proof (mount OwnershipProofHandler there). The forge fetches
	// the proof from one of them.
	Origins []string

	// ForgeAuth is the optional Forge-Authorization access token.
	ForgeAuth string
	// UserAgent overrides the client's default User-Agent.
	UserAgent string
	// HTTPClient issues the registration request; defaults to http.DefaultClient.
	HTTPClient *http.Client
	// ModifyRequest runs before signing and may set req.Host.
	ModifyRequest func(*http.Request) error
	// Resolver checks the published TXT record; defaults to net.DefaultResolver.
	Resolver *net.Resolver
	// Logger, defaults to a no-op logger.
	Logger *zap.SugaredLogger
}

// NewHTTPBrokeredDNS01Solver returns a certmagic DNS-01 solver that registers
// with the forge over the /v2 (HTTP-only) API. It has no libp2p dependency and
// mirrors the /v1 solver, so a caller can plug either into a certmagic config.
//
// The node MUST already serve its ownership proof (see OwnershipProofHandler)
// at one of cfg.Origins when the solver runs.
func NewHTTPBrokeredDNS01Solver(cfg HTTPBrokeredDNS01SolverConfig) (acmez.Solver, error) {
	if cfg.ForgeEndpoint == "" {
		return nil, fmt.Errorf("HTTPBrokeredDNS01SolverConfig: ForgeEndpoint is required")
	}
	if cfg.Key.didKey == "" {
		return nil, fmt.Errorf("HTTPBrokeredDNS01SolverConfig: Key is required")
	}
	if len(cfg.Origins) == 0 {
		return nil, fmt.Errorf("HTTPBrokeredDNS01SolverConfig: at least one Origin is required")
	}
	resolver := cfg.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	logger := cfg.Logger
	if logger == nil {
		logger = zap.NewNop().Sugar()
	}
	return &httpBrokeredDNS01Solver{cfg: cfg, resolver: resolver, log: logger}, nil
}

// httpBrokeredDNS01Solver is the /v2 (HTTP-only) certmagic DNS-01 solver.
type httpBrokeredDNS01Solver struct {
	cfg      HTTPBrokeredDNS01SolverConfig
	resolver *net.Resolver
	log      *zap.SugaredLogger
}

func (d *httpBrokeredDNS01Solver) Present(ctx context.Context, challenge acme.Challenge) error {
	dns01value := challenge.DNS01KeyAuthorization()
	var sendOpts []SendChallengeOption
	if d.cfg.HTTPClient != nil {
		sendOpts = append(sendOpts, WithChallengeHTTPClient(d.cfg.HTTPClient))
	}
	if err := SendChallengeV2(ctx, d.cfg.ForgeEndpoint, d.cfg.Key, dns01value, d.cfg.Origins,
		d.cfg.ForgeAuth, d.cfg.UserAgent, d.cfg.ModifyRequest, sendOpts...); err != nil {
		return fmt.Errorf("p2p-forge broker registration error: %w", err)
	}
	return nil
}

func (d *httpBrokeredDNS01Solver) Wait(ctx context.Context, challenge acme.Challenge) error {
	return waitForTXT(ctx, d.resolver, d.log, challenge)
}

func (d *httpBrokeredDNS01Solver) CleanUp(context.Context, acme.Challenge) error {
	// Last-writer-wins on the TXT record; nothing to undo.
	return nil
}

var (
	_ acmez.Solver = (*httpBrokeredDNS01Solver)(nil)
	_ acmez.Waiter = (*httpBrokeredDNS01Solver)(nil)
)
