package ownership

import (
	"crypto/ed25519"
	"testing"
	"time"

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
