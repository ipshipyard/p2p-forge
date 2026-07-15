package httpsig

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestOwnershipRoundTrip(t *testing.T) {
	priv := fixedKey(t, 0x11)
	keyID, err := EncodeDIDKey(priv.GetPublic())
	require.NoError(t, err)
	now := time.Unix(1_700_000_000, 0)
	origin := "https://gateway.example:8443"

	hdr, err := SignOwnership(priv, origin, now.Unix(), now.Add(DefaultOwnershipWindow).Unix())
	require.NoError(t, err)

	err = VerifyOwnership(hdr, nil, OwnershipVerifyConfig{
		KeyID:          keyID,
		ExpectedOrigin: origin,
		Now:            now,
	})
	require.NoError(t, err)
}

func TestOwnershipRejects(t *testing.T) {
	priv := fixedKey(t, 0x12)
	other := fixedKey(t, 0x13)
	keyID, err := EncodeDIDKey(priv.GetPublic())
	require.NoError(t, err)
	otherID, err := EncodeDIDKey(other.GetPublic())
	require.NoError(t, err)
	now := time.Unix(1_700_000_000, 0)
	origin := "https://gateway.example"

	base, err := SignOwnership(priv, origin, now.Unix(), now.Add(time.Hour).Unix())
	require.NoError(t, err)

	t.Run("origin mismatch", func(t *testing.T) {
		err := VerifyOwnership(base, nil, OwnershipVerifyConfig{KeyID: keyID, ExpectedOrigin: "https://evil.example", Now: now})
		require.ErrorContains(t, err, "origin")
	})

	t.Run("scheme mismatch (http vs https)", func(t *testing.T) {
		err := VerifyOwnership(base, nil, OwnershipVerifyConfig{KeyID: keyID, ExpectedOrigin: "http://gateway.example", Now: now})
		require.ErrorContains(t, err, "origin")
	})

	t.Run("verified under wrong registration key", func(t *testing.T) {
		// The proof is signed by priv but named keyID; verifying against a
		// different registration key must fail the keyid cross-check.
		err := VerifyOwnership(base, nil, OwnershipVerifyConfig{KeyID: otherID, ExpectedOrigin: origin, Now: now})
		require.ErrorContains(t, err, "keyid")
	})

	t.Run("proof signed by a different key than it names", func(t *testing.T) {
		// Craft a proof for origin signed by `other` but the forge expects it
		// under `other`'s did:key; a proof that names other but is served for a
		// registration under keyID would be caught by the keyid check above.
		// Here we confirm a genuine other-signed proof still verifies under its
		// own key, so the security rests on binding keyid to the registration.
		otherProof, err := SignOwnership(other, origin, now.Unix(), now.Add(time.Hour).Unix())
		require.NoError(t, err)
		require.NoError(t, VerifyOwnership(otherProof, nil, OwnershipVerifyConfig{KeyID: otherID, ExpectedOrigin: origin, Now: now}))
		// ...but not under keyID.
		require.Error(t, VerifyOwnership(otherProof, nil, OwnershipVerifyConfig{KeyID: keyID, ExpectedOrigin: origin, Now: now}))
	})

	t.Run("expired", func(t *testing.T) {
		err := VerifyOwnership(base, nil, OwnershipVerifyConfig{KeyID: keyID, ExpectedOrigin: origin, Now: now.Add(2 * time.Hour)})
		require.ErrorContains(t, err, "expired")
	})

	t.Run("window too long", func(t *testing.T) {
		tooLong, err := SignOwnership(priv, origin, now.Unix(), now.Add(MaxOwnershipWindow+time.Hour).Unix())
		require.NoError(t, err)
		err = VerifyOwnership(tooLong, nil, OwnershipVerifyConfig{KeyID: keyID, ExpectedOrigin: origin, Now: now})
		require.ErrorContains(t, err, "window")
	})

	t.Run("body tampered", func(t *testing.T) {
		err := VerifyOwnership(base, []byte("unexpected body"), OwnershipVerifyConfig{KeyID: keyID, ExpectedOrigin: origin, Now: now})
		require.ErrorContains(t, err, "content-digest")
	})
}
