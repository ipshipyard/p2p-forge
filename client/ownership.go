package client

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
)

// WellKnownProofPath is the path prefix where a node serves its ownership
// proof; the full path is this prefix followed by the node's did:key. The path
// is keyed by did:key (not a peerid) to keep the v2 surface libp2p-agnostic.
const WellKnownProofPath = "/.well-known/autotls/"

// HTTPOrigin is the canonical form of an http(s) server the ownership proof is
// bound to: its origin string plus the parts needed to connect.
type HTTPOrigin struct {
	// URL is the server's origin serialized per RFC 6454 section 6.2:
	// scheme://host, with the port only when it is not the scheme default.
	URL string
	// Scheme, Host, and Port are the connection parameters. Port is always
	// concrete (the scheme default when the URL omits it).
	Scheme string
	Host   string
	Port   string
}

// CanonicalOrigin parses a scheme://host[:port] URL into its origin form.
// It rejects userinfo, a path, query, or fragment so the signed server string
// is unambiguous and cannot be widened by trailing URL components. The origin
// follows RFC 6454 section 6.2: lowercase host, and the port omitted when it is
// the scheme default (443 for https, 80 for http).
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
		port = defaultPort(u.Scheme)
	}

	// RFC 6454 origin: keep the port only when it is not the scheme default.
	origin := u.Scheme + "://" + bracketHost(host)
	if port != defaultPort(u.Scheme) {
		origin = u.Scheme + "://" + net.JoinHostPort(host, port)
	}
	return HTTPOrigin{URL: origin, Scheme: u.Scheme, Host: host, Port: port}, nil
}

func defaultPort(scheme string) string {
	if scheme == "https" {
		return "443"
	}
	return "80"
}

// bracketHost wraps an IPv6 literal in brackets so the origin stays a valid URL.
func bracketHost(host string) string {
	if strings.Contains(host, ":") {
		return "[" + host + "]"
	}
	return host
}

// OwnershipProofHandler returns an http.Handler that answers
// POST /.well-known/autotls/<did:key> with an RFC 9421-signed response proving
// key controls origin. Mount it on the node's public HTTP server. POST
// (not GET) keeps the proof uncacheable, so every check gets a fresh signature.
//
// origin is the public origin the node is registering (e.g.
// https://gw.example).
func OwnershipProofHandler(key SigningKey, origin string) (http.Handler, error) {
	o, err := CanonicalOrigin(origin)
	if err != nil {
		return nil, err
	}
	wantPath := WellKnownProofPath + key.DIDKey()

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if r.URL.Path != wantPath {
			http.NotFound(w, r)
			return
		}
		if err := key.signOwnershipResponse(w, r, o.URL); err != nil {
			http.Error(w, "could not sign ownership proof", http.StatusInternalServerError)
			return
		}
	}), nil
}
