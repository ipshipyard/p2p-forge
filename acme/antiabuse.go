package acme

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/ipfs/go-datastore"
	"github.com/ipshipyard/p2p-forge/internal/httpsig"
	"github.com/libp2p/go-libp2p/core/peer"
)

// nonceTTL is how long a used nonce is remembered. It must exceed the maximum
// signature lifetime plus clock skew on both sides so a nonce cannot expire from
// the store while its signature is still valid.
const nonceTTL = 20 * time.Minute

// errReplay signals a nonce that has already been used.
var errReplay = errors.New("nonce already used")

// initAntiAbuse constructs the per-instance nonce store. Request rate limiting
// is intentionally not done here; it belongs on the fronting reverse proxy, CDN,
// or load balancer. It is idempotent and safe to call from OnStartup and tests.
func (c *acmeWriter) initAntiAbuse() {
	if min := httpsig.MaxSignatureLifetime + 2*httpsig.MaxClockSkew; nonceTTL <= min {
		panic(fmt.Sprintf("nonceTTL (%s) must exceed max signature lifetime + 2x skew (%s)", nonceTTL, min))
	}
	if c.nonces == nil && c.Datastore != nil {
		c.nonces = newNonceStore(c.Datastore, nonceTTL)
	}
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
