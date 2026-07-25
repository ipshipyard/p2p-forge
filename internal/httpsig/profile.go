// Package httpsig pins the p2p-forge /v2 request-signing profile and the
// did:key key identifier. The RFC 9421 signing and verification themselves are
// delegated to github.com/yaronf/httpsign; this package only fixes the profile
// (covered components, parameters, clock bounds) so client and server agree.
package httpsig

import (
	"net"
	"strings"
	"time"
)

const (
	// SigLabel is the fixed Signature-Input / Signature dictionary label.
	SigLabel = "sig1"
	// RegistrationTag domain-separates a registration signature from any other
	// RFC 9421 use.
	RegistrationTag = "autotls-reg"

	// MaxSignatureLifetime bounds expires-created. No extra grace for client
	// clock skew is needed: a skewed clock shifts created and expires by the
	// same amount, so the expires check covers it.
	MaxSignatureLifetime = 5 * time.Minute
	// MaxForwardDrift is how far in the future `created` may be.
	MaxForwardDrift = 30 * time.Second
	// MinNonceBytes is the minimum nonce entropy: 128 bits, carried as
	// unpadded base64url in the nonce parameter.
	MinNonceBytes = 16

	// OwnershipTag domain-separates the ownership proof signature from a
	// registration request signature.
	OwnershipTag = "autotls-ownership"
	// OwnershipProofLifetime bounds how long a proof stays valid after signing.
	OwnershipProofLifetime = 5 * time.Minute
)

// RegistrationComponents is the fixed, ordered set of covered components for a
// /v2 registration request.
var RegistrationComponents = []string{"@method", "@authority", "@path", "content-type", "content-digest"}

// OwnershipComponents is the fixed set of covered components for the
// ownership proof response signature. content-digest binds the response
// body, which carries the canonical scheme://host:port the proof is for.
var OwnershipComponents = []string{"@status", "content-digest"}

// CanonicalAuthority lowercases an authority and strips a default http/https
// port, so the server can compare @authority against its configured domain.
func CanonicalAuthority(a string) string {
	a = strings.ToLower(strings.TrimSpace(a))
	if host, port, err := net.SplitHostPort(a); err == nil && (port == "80" || port == "443") {
		return host
	}
	return a
}
