package client

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/ipshipyard/p2p-forge/internal/httpsig"
	"github.com/libp2p/go-libp2p/core/crypto"
)

// WellKnownProofPath is the path prefix where a node serves its ownership
// proof; the full path is this prefix followed by the node's did:key. The path
// is keyed by did:key (not a peerid) to keep the v2 surface libp2p-agnostic.
const WellKnownProofPath = "/.well-known/p2p-forge/"

// HTTPOrigin is the canonical form of an http(s) endpoint used by the ownership
// proof: an origin string the proof binds, plus the pieces needed to connect.
type HTTPOrigin struct {
	Origin string // scheme://host:port, lowercase host, explicit port
	Scheme string
	Host   string
	Port   string
}

// CanonicalOrigin parses an origin-only http(s) URL into its canonical form.
// It rejects userinfo, a path, query, or fragment so the signed origin is
// unambiguous and cannot be widened by trailing URL components.
func CanonicalOrigin(rawURL string) (HTTPOrigin, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return HTTPOrigin{}, fmt.Errorf("parsing origin URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return HTTPOrigin{}, fmt.Errorf("origin scheme must be http or https, got %q", u.Scheme)
	}
	if u.User != nil {
		return HTTPOrigin{}, fmt.Errorf("origin must not contain userinfo")
	}
	if u.Path != "" && u.Path != "/" {
		return HTTPOrigin{}, fmt.Errorf("origin must not contain a path")
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return HTTPOrigin{}, fmt.Errorf("origin must not contain a query or fragment")
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return HTTPOrigin{}, fmt.Errorf("origin must contain a host")
	}
	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	return HTTPOrigin{
		Origin: u.Scheme + "://" + host + ":" + port,
		Scheme: u.Scheme,
		Host:   host,
		Port:   port,
	}, nil
}

// OwnershipProofHandler returns an http.Handler that serves the node's ownership
// proof at WellKnownProofPath+<did:key> for the given origin. Mount it on the
// node's existing HTTP server. The signed proof is cached and refreshed before
// it expires, so it stays cacheable and the signing key is used rarely.
//
// rawURL is the public origin the node is registering (e.g. https://gw.example).
func OwnershipProofHandler(privKey crypto.PrivKey, rawURL string) (http.Handler, error) {
	o, err := CanonicalOrigin(rawURL)
	if err != nil {
		return nil, err
	}
	did, err := httpsig.EncodeDIDKey(privKey.GetPublic())
	if err != nil {
		return nil, err
	}
	signer := &ownershipSigner{priv: privKey, origin: o.Origin, window: httpsig.DefaultOwnershipWindow}
	wantPath := WellKnownProofPath + did

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if r.URL.Path != wantPath {
			http.NotFound(w, r)
			return
		}
		hdr, err := signer.headers(time.Now())
		if err != nil {
			http.Error(w, "could not produce ownership proof", http.StatusInternalServerError)
			return
		}
		for k, vs := range hdr {
			for _, v := range vs {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(http.StatusOK)
	}), nil
}

// ownershipSigner caches a signed proof and re-signs it before expiry.
type ownershipSigner struct {
	priv   crypto.PrivKey
	origin string
	window time.Duration

	mu      sync.Mutex
	cached  http.Header
	expires time.Time
}

func (s *ownershipSigner) headers(now time.Time) (http.Header, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Refresh once we are into the last quarter of the window.
	if s.cached == nil || now.After(s.expires.Add(-s.window/4)) {
		created := now.Add(-1 * time.Minute) // small backdate for verifier clock skew
		expires := now.Add(s.window)
		h, err := httpsig.SignOwnership(s.priv, s.origin, created.Unix(), expires.Unix())
		if err != nil {
			return nil, err
		}
		s.cached = h
		s.expires = expires
	}
	return s.cached, nil
}
