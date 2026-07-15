// Package ownership implements the p2p-forge /v2 http-ownership proof: a small
// EdDSA JWT a node serves at a well-known path to prove its key controls an HTTP
// origin. Using a JWT keeps the proof a standard, offline-signable, cacheable
// artifact rather than a bespoke signature format.
package ownership

import (
	"crypto/ed25519"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Proof validity bounds. The signer picks a window up to MaxWindow; the verifier
// caps it. Freshness comes from the forge fetching the proof live, so the window
// only bounds how long a proof stays valid after the key holder loses the origin.
const (
	DefaultWindow = 24 * time.Hour
	MaxWindow     = 14 * 24 * time.Hour
	clockSkew     = 5 * time.Minute
	backdate      = time.Minute // small backdate of iat to tolerate verifier skew
)

// claims is the proof payload: the standard registered claims plus the origin
// the key controls.
type claims struct {
	Origin string `json:"origin"`
	jwt.RegisteredClaims
}

// Sign returns a compact EdDSA JWT proving priv controls origin, valid for ttl
// (clamped to MaxWindow).
func Sign(priv ed25519.PrivateKey, origin string, now time.Time, ttl time.Duration) (string, error) {
	if ttl <= 0 || ttl > MaxWindow {
		ttl = DefaultWindow
	}
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims{
		Origin: origin,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(now.Add(-backdate)),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		},
	})
	s, err := token.SignedString(priv)
	if err != nil {
		return "", fmt.Errorf("signing ownership proof: %w", err)
	}
	return s, nil
}

// Verify checks the proof under pub (the registration key, never a key the token
// names), confirms the origin matches, and enforces the validity window. now is
// injectable for tests.
func Verify(token string, pub ed25519.PublicKey, expectedOrigin string, now time.Time) error {
	var c claims
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{"EdDSA"}),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
		jwt.WithLeeway(clockSkew),
		jwt.WithTimeFunc(func() time.Time { return now }),
	)
	if _, err := parser.ParseWithClaims(token, &c, func(*jwt.Token) (any, error) {
		return pub, nil
	}); err != nil {
		return fmt.Errorf("ownership proof invalid: %w", err)
	}
	if c.IssuedAt == nil || c.ExpiresAt == nil {
		return fmt.Errorf("ownership proof missing iat/exp")
	}
	if c.ExpiresAt.Sub(c.IssuedAt.Time) > MaxWindow+backdate {
		return fmt.Errorf("ownership proof window exceeds %s", MaxWindow)
	}
	if c.Origin != expectedOrigin {
		return fmt.Errorf("ownership proof origin %q does not match %q", c.Origin, expectedOrigin)
	}
	return nil
}
