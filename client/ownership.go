package client

import (
	"crypto/ed25519"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/ipshipyard/p2p-forge/internal/httpsig"
	"github.com/ipshipyard/p2p-forge/internal/ownership"
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
// unambiguous and cannot be widened by trailing URL components. An IP-literal
// host is normalized to its canonical textual form, and an IPv6 literal is
// bracketed in Origin ("https://[2001:db8::1]:443"), so both sides of the
// proof derive the same origin string and the string stays valid in a URL.
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
	if ip, err := netip.ParseAddr(host); err == nil {
		// A zone (fe80::1%eth0) names an interface on one host: it can never
		// be a publicly verifiable origin, and its "%" is not URL-safe.
		if ip.Zone() != "" {
			return HTTPOrigin{}, fmt.Errorf("origin must not contain an IPv6 zone")
		}
		host = ip.Unmap().String()
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
		Origin: u.Scheme + "://" + net.JoinHostPort(host, port),
		Scheme: u.Scheme,
		Host:   host,
		Port:   port,
	}, nil
}

// OwnershipProofHandler returns an http.Handler that serves the node's ownership
// proof (a compact EdDSA JWT) at WellKnownProofPath+<did:key> for the given
// origin. Mount it on the node's existing HTTP server. The proof is cached and
// refreshed before it expires, so it stays cacheable and the key is used rarely.
//
// rawURL is the public origin the node is registering (e.g. https://gw.example).
func OwnershipProofHandler(privKey crypto.PrivKey, rawURL string) (http.Handler, error) {
	o, err := CanonicalOrigin(rawURL)
	if err != nil {
		return nil, err
	}
	did, err := httpsig.EncodeDIDKey(privKey.GetPublic()) // also rejects non-Ed25519 keys
	if err != nil {
		return nil, err
	}
	raw, err := privKey.Raw()
	if err != nil {
		return nil, fmt.Errorf("reading private key: %w", err)
	}
	signer := &ownershipSigner{priv: ed25519.PrivateKey(raw), origin: o.Origin}
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
		proof, err := signer.token(time.Now())
		if err != nil {
			http.Error(w, "could not produce ownership proof", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/jwt")
		if r.Method == http.MethodHead {
			return
		}
		_, _ = io.WriteString(w, proof)
	}), nil
}

// ownershipSigner caches a signed proof JWT and re-signs it before expiry.
type ownershipSigner struct {
	priv   ed25519.PrivateKey
	origin string

	mu      sync.Mutex
	cached  string
	expires time.Time
}

func (s *ownershipSigner) token(now time.Time) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Refresh once we are into the last quarter of the window.
	if s.cached == "" || now.After(s.expires.Add(-ownership.DefaultWindow/4)) {
		tok, err := ownership.Sign(s.priv, s.origin, now, ownership.DefaultWindow)
		if err != nil {
			return "", err
		}
		s.cached = tok
		s.expires = now.Add(ownership.DefaultWindow)
	}
	return s.cached, nil
}
