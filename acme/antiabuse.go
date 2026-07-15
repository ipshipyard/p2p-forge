package acme

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/ipfs/go-datastore"
	"github.com/ipshipyard/p2p-forge/internal/httpsig"
	"github.com/libp2p/go-libp2p/core/peer"
	"golang.org/x/time/rate"
)

// Anti-abuse tunables. Exported-style named constants so docs and operators can
// reference them rather than a drifting literal.
const (
	// nonceTTL is how long a used nonce is remembered. It must exceed the
	// maximum signature lifetime plus clock skew on both sides so a nonce
	// cannot expire from the store while its signature is still valid.
	nonceTTL = 20 * time.Minute

	// registrationsPerMinute and registrationBurst bound registrations per
	// source IP. A cert order needs ~2 requests, so this is generous for
	// legitimate renewals while capping abuse.
	registrationsPerMinute = 10
	registrationBurst      = 20

	// rateLimiterEntryTTL evicts idle per-IP limiters so the map stays bounded.
	rateLimiterEntryTTL = 15 * time.Minute
)

// errReplay signals a nonce that has already been used.
var errReplay = errors.New("nonce already used")

// initAntiAbuse constructs the per-instance rate limiter and the nonce store.
// It is idempotent and safe to call from OnStartup and from tests.
func (c *acmeWriter) initAntiAbuse() {
	// A nonce must outlive the longest window in which its signature is still
	// valid, or a replay could land after the nonce expired from the store.
	if min := httpsig.MaxSignatureLifetime + 2*httpsig.MaxClockSkew; nonceTTL <= min {
		panic(fmt.Sprintf("nonceTTL (%s) must exceed max signature lifetime + 2x skew (%s)", nonceTTL, min))
	}
	if c.rateLimiter == nil {
		c.rateLimiter = newIPRateLimiter(registrationsPerMinute, registrationBurst, rateLimiterEntryTTL)
	}
	if c.nonces == nil && c.Datastore != nil {
		c.nonces = newNonceStore(c.Datastore, nonceTTL)
	}
}

// primaryClientIP returns the single client IP used for rate limiting: the
// configured trusted header when set (e.g. CF-Connecting-IP behind Cloudflare),
// otherwise the direct connection address. It never trusts a leftmost
// X-Forwarded-For, which any client can forge.
func primaryClientIP(r *http.Request, trustedHeader string) (netip.Addr, bool) {
	if trustedHeader != "" {
		if v := strings.TrimSpace(r.Header.Get(trustedHeader)); v != "" {
			if ip, err := netip.ParseAddr(v); err == nil {
				return ip, true
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip, err := netip.ParseAddr(host)
	return ip, err == nil
}

// ipRateLimiter is a per-source-IP token-bucket limiter with lazy eviction of
// idle buckets. It is in-memory per instance; behind a load balancer the real
// cap is the front proxy plus the shared datastore-backed guards.
type ipRateLimiter struct {
	mu       sync.Mutex
	buckets  map[netip.Addr]*rateBucket
	limit    rate.Limit
	burst    int
	entryTTL time.Duration
	lastGC   time.Time
}

type rateBucket struct {
	limiter *rate.Limiter
	seen    time.Time
}

func newIPRateLimiter(perMinute, burst int, entryTTL time.Duration) *ipRateLimiter {
	return &ipRateLimiter{
		buckets:  make(map[netip.Addr]*rateBucket),
		limit:    rate.Every(time.Minute / time.Duration(perMinute)),
		burst:    burst,
		entryTTL: entryTTL,
	}
}

// allow reports whether a request from ip is permitted at time now.
func (rl *ipRateLimiter) allow(ip netip.Addr, now time.Time) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	if now.Sub(rl.lastGC) > rl.entryTTL {
		for k, b := range rl.buckets {
			if now.Sub(b.seen) > rl.entryTTL {
				delete(rl.buckets, k)
			}
		}
		rl.lastGC = now
	}

	b := rl.buckets[ip]
	if b == nil {
		b = &rateBucket{limiter: rate.NewLimiter(rl.limit, rl.burst)}
		rl.buckets[ip] = b
	}
	b.seen = now
	return b.limiter.AllowN(now, 1)
}

// nonceStore records used nonces so a captured signed request cannot be
// replayed within its validity window. Reservation is atomic within one
// instance via the mutex; across load-balanced instances two truly simultaneous
// replays can both pass, which is low-harm because the resulting write is
// idempotent. It fails closed if the datastore is unavailable.
type nonceStore struct {
	ds  datastore.TTLDatastore
	ttl time.Duration
	mu  sync.Mutex
}

func newNonceStore(ds datastore.TTLDatastore, ttl time.Duration) *nonceStore {
	return &nonceStore{ds: ds, ttl: ttl}
}

// reserve records (peerID, nonce) as used, returning errReplay if it was already
// present. The peer.ID is a server-derived internal key, never on the wire.
func (n *nonceStore) reserve(ctx context.Context, peerID peer.ID, nonce string) error {
	sum := sha256.Sum256([]byte(nonce))
	key := datastore.NewKey("/v2/nonce/" + peerID.String() + "/" + hex.EncodeToString(sum[:]))

	n.mu.Lock()
	defer n.mu.Unlock()

	has, err := n.ds.Has(ctx, key)
	if err != nil {
		return fmt.Errorf("nonce store unavailable: %w", err)
	}
	if has {
		return errReplay
	}
	if err := n.ds.PutWithTTL(ctx, key, []byte{}, n.ttl); err != nil {
		return fmt.Errorf("nonce store write failed: %w", err)
	}
	return nil
}
