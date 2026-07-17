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
	RegistrationTag = "p2p-forge-reg"

	// MaxSignatureLifetime bounds expires-created.
	MaxSignatureLifetime = 5 * time.Minute
	// MaxClockSkew extends the accepted age of `created` beyond
	// MaxSignatureLifetime, tolerating a slow client clock. `expires` gets no
	// such grace: a signature past its own deadline is rejected outright.
	MaxClockSkew = 2 * time.Minute
	// MaxForwardDrift is how far in the future `created` may be.
	MaxForwardDrift = 30 * time.Second
	// MinNonceLen is the minimum accepted nonce length in base64url
	// characters: 22 characters is the shortest encoding of the required 128
	// bits of entropy.
	MinNonceLen = 22
)

// RegistrationComponents is the fixed, ordered set of covered components for a
// /v2 registration request.
var RegistrationComponents = []string{"@method", "@authority", "@path", "content-type", "content-digest"}

// CanonicalAuthority lowercases an authority and strips a default http/https
// port, so the server can compare @authority against its configured domain.
func CanonicalAuthority(a string) string {
	a = strings.ToLower(strings.TrimSpace(a))
	if host, port, err := net.SplitHostPort(a); err == nil && (port == "80" || port == "443") {
		return host
	}
	return a
}
