package httpsig

import (
	"bytes"
	"testing"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
)

func TestDIDKeyRoundTrip(t *testing.T) {
	priv, pub, err := crypto.GenerateEd25519Key(bytes.NewReader(bytes.Repeat([]byte{0x07}, 64)))
	require.NoError(t, err)
	_ = priv

	did, err := EncodeDIDKey(pub)
	require.NoError(t, err)
	// Ed25519 did:keys always start with z6Mk (multicodec 0xed01 prefix).
	require.True(t, len(did) > len("did:key:z6Mk"))
	require.Contains(t, did, "did:key:z6Mk")

	got, err := DecodeDIDKey(did)
	require.NoError(t, err)
	require.True(t, got.Equals(pub))

	// The derived peer.ID must match the one libp2p derives, so v2 and the DNS
	// layer agree on identity.
	wantPID, err := peer.IDFromPublicKey(pub)
	require.NoError(t, err)
	gotPID, err := peer.IDFromPublicKey(got)
	require.NoError(t, err)
	require.Equal(t, wantPID, gotPID)
}

func TestDecodeDIDKeyRejects(t *testing.T) {
	cases := map[string]string{
		"missing prefix":   "z6MkfooBar",
		"not base58btc":    "did:key:f7b22",
		"wrong multicodec": "did:key:z2Dd", // secp/p256-ish prefix, not ed25519
		"garbage":          "did:key:z!!!!",
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := DecodeDIDKey(in)
			require.Error(t, err)
		})
	}
}

func TestEncodeDIDKeyRejectsNonEd25519(t *testing.T) {
	_, pub, err := crypto.GenerateSecp256k1Key(bytes.NewReader(bytes.Repeat([]byte{0x09}, 64)))
	require.NoError(t, err)
	_, err = EncodeDIDKey(pub)
	require.ErrorContains(t, err, "Ed25519")
}
