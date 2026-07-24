package ownership

import (
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
)

func mustKeys(t *testing.T) (ed25519.PrivateKey, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil) // crypto/rand
	require.NoError(t, err)
	return priv, pub
}

func TestOwnershipRoundTrip(t *testing.T) {
	priv, pub := mustKeys(t)
	now := time.Unix(1_700_000_000, 0)
	origin := "https://gw.example:443"

	tok, err := Sign(priv, origin, now, DefaultWindow)
	require.NoError(t, err)
	require.NoError(t, Verify(tok, pub, origin, now))
}

func TestOwnershipRejects(t *testing.T) {
	priv, pub := mustKeys(t)
	_, otherPub := mustKeys(t)
	now := time.Unix(1_700_000_000, 0)
	origin := "https://gw.example:443"

	tok, err := Sign(priv, origin, now, time.Hour)
	require.NoError(t, err)

	t.Run("origin mismatch", func(t *testing.T) {
		require.ErrorContains(t, Verify(tok, pub, "https://evil.example:443", now), "origin")
	})
	t.Run("scheme or port mismatch", func(t *testing.T) {
		require.Error(t, Verify(tok, pub, "http://gw.example:80", now))
	})
	t.Run("wrong verification key", func(t *testing.T) {
		require.Error(t, Verify(tok, otherPub, origin, now))
	})
	t.Run("expired", func(t *testing.T) {
		require.ErrorContains(t, Verify(tok, pub, origin, now.Add(2*time.Hour)), "invalid")
	})
	t.Run("garbage token", func(t *testing.T) {
		require.Error(t, Verify("not.a.jwt", pub, origin, now))
	})
}

func TestOwnershipWindowCap(t *testing.T) {
	priv, pub := mustKeys(t)
	now := time.Unix(1_700_000_000, 0)
	origin := "https://gw.example:443"

	t.Run("full window verifies", func(t *testing.T) {
		tok, err := Sign(priv, origin, now, MaxWindow)
		require.NoError(t, err)
		require.NoError(t, Verify(tok, pub, origin, now))
	})

	t.Run("window over the cap rejected", func(t *testing.T) {
		// Sign clamps, so forge the too-wide token directly.
		wide := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims{
			Origin: origin,
			RegisteredClaims: jwt.RegisteredClaims{
				IssuedAt:  jwt.NewNumericDate(now),
				ExpiresAt: jwt.NewNumericDate(now.Add(MaxWindow + time.Hour)),
			},
		})
		wide.Header["typ"] = proofType
		s, err := wide.SignedString(priv)
		require.NoError(t, err)
		require.ErrorContains(t, Verify(s, pub, origin, now), "window exceeds")
	})
}

func TestOwnershipRequiresExplicitType(t *testing.T) {
	priv, pub := mustKeys(t)
	now := time.Unix(1_700_000_000, 0)
	origin := "https://gw.example:443"

	// A JWT with the right claims but the default typ must not pass as an
	// ownership proof.
	untyped := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims{
		Origin: origin,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
		},
	})
	s, err := untyped.SignedString(priv)
	require.NoError(t, err)
	require.ErrorContains(t, Verify(s, pub, origin, now), "typ")
}
