package acme

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ipshipyard/p2p-forge/client"
	"github.com/ipshipyard/p2p-forge/internal/httpsig"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/stretchr/testify/require"
)

// newProofServer starts a loopback HTTP server that serves priv's ownership
// proof for its own origin, and returns the server plus the signer's did:key.
func newProofServer(t *testing.T, priv crypto.PrivKey) (*httptest.Server, string) {
	t.Helper()
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	handler, err := client.OwnershipProofHandler(priv, srv.URL)
	require.NoError(t, err)
	mux.Handle("/", handler)

	did, err := httpsig.EncodeDIDKey(priv.GetPublic())
	require.NoError(t, err)
	return srv, did
}

func TestHTTPOwnershipVerify(t *testing.T) {
	priv, _, err := crypto.GenerateEd25519Key(rand.Reader)
	require.NoError(t, err)
	srv, did := newProofServer(t, priv)

	c := newTestWriter() // AllowPrivateAddrs=true: loopback + non-standard port

	t.Run("valid proof verifies", func(t *testing.T) {
		require.NoError(t, c.verifyHTTPOwnership(t.Context(), did, []string{srv.URL}))
	})

	t.Run("wrong registration key fails", func(t *testing.T) {
		other, _, err := crypto.GenerateEd25519Key(rand.Reader)
		require.NoError(t, err)
		otherDID, err := httpsig.EncodeDIDKey(other.GetPublic())
		require.NoError(t, err)
		// The endpoint serves priv's proof; verifying it as otherDID must fail
		// (the served path is priv's did:key, so this 404s or key-mismatches).
		require.Error(t, c.verifyHTTPOwnership(t.Context(), otherDID, []string{srv.URL}))
	})

	t.Run("no proof served fails", func(t *testing.T) {
		bare := httptest.NewServer(http.NotFoundHandler())
		t.Cleanup(bare.Close)
		require.Error(t, c.verifyHTTPOwnership(t.Context(), did, []string{bare.URL}))
	})
}

func TestHTTPOwnershipTLSFallback(t *testing.T) {
	// A node registering because it has no CA-valid cert yet serves the proof
	// over HTTPS with a self-signed cert; verification must fall back from
	// WebPKI to the pinned-IP + signature path.
	priv, _, err := crypto.GenerateEd25519Key(rand.Reader)
	require.NoError(t, err)
	mux := http.NewServeMux()
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	handler, err := client.OwnershipProofHandler(priv, srv.URL)
	require.NoError(t, err)
	mux.Handle("/", handler)
	did, err := httpsig.EncodeDIDKey(priv.GetPublic())
	require.NoError(t, err)

	c := newTestWriter()
	require.NoError(t, c.verifyHTTPOwnership(t.Context(), did, []string{srv.URL}))
}

func TestV2HTTPOwnershipEndToEnd(t *testing.T) {
	initMetrics()
	priv, _, err := crypto.GenerateEd25519Key(rand.Reader)
	require.NoError(t, err)
	srv, _ := newProofServer(t, priv)

	c := newTestWriter()
	value := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x07}, 32))
	req := signedV2Request(t, priv, value, []string{srv.URL})
	rec := httptest.NewRecorder()

	c.handleV2Challenge(rec, req)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	var resp v2Response
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	require.Equal(t, "http-ownership", resp.Verification.Mode)
}

func TestCanonicalOriginServer(t *testing.T) {
	// A path or userinfo in the address is rejected, so the signed origin
	// cannot be widened.
	for _, bad := range []string{
		"https://gw.example/some/path",
		"https://user@gw.example",
		"ftp://gw.example",
		"https://gw.example?x=1",
	} {
		_, err := client.CanonicalOrigin(bad)
		require.Error(t, err, bad)
	}
	o, err := client.CanonicalOrigin("https://GW.Example")
	require.NoError(t, err)
	require.Equal(t, "https://gw.example:443", o.Origin)
}
