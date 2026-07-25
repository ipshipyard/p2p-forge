package acme

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ipshipyard/p2p-forge/client"
	"github.com/ipshipyard/p2p-forge/internal/httpsig"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/stretchr/testify/require"
)

// ed25519Pub returns priv's public key in the form verifyHTTPOwnership takes.
func ed25519Pub(t *testing.T, priv crypto.PrivKey) ed25519.PublicKey {
	t.Helper()
	raw, err := priv.GetPublic().Raw()
	require.NoError(t, err)
	return ed25519.PublicKey(raw)
}

// signingKey wraps a libp2p Ed25519 key as the libp2p-free client.SigningKey.
func signingKey(t *testing.T, priv crypto.PrivKey) client.SigningKey {
	t.Helper()
	raw, err := priv.Raw()
	require.NoError(t, err)
	sk, err := client.NewEd25519SigningKey(ed25519.PrivateKey(raw))
	require.NoError(t, err)
	return sk
}

// newProofServer starts a loopback HTTP server that serves priv's ownership
// proof for its own server, and returns the server plus the signer's did:key.
func newProofServer(t *testing.T, priv crypto.PrivKey) (*httptest.Server, string) {
	t.Helper()
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	handler, err := client.OwnershipProofHandler(signingKey(t, priv), srv.URL)
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
		require.NoError(t, c.verifyHTTPOwnership(t.Context(), ed25519Pub(t, priv), did, []string{srv.URL}))
	})

	t.Run("wrong registration key fails", func(t *testing.T) {
		other, _, err := crypto.GenerateEd25519Key(rand.Reader)
		require.NoError(t, err)
		otherDID, err := httpsig.EncodeDIDKey(other.GetPublic())
		require.NoError(t, err)
		// The endpoint serves priv's proof; verifying it as other must fail
		// (the served path is priv's did:key, so this 404s or key-mismatches).
		require.Error(t, c.verifyHTTPOwnership(t.Context(), ed25519Pub(t, other), otherDID, []string{srv.URL}))
	})

	t.Run("no proof served fails", func(t *testing.T) {
		bare := httptest.NewServer(http.NotFoundHandler())
		t.Cleanup(bare.Close)
		require.Error(t, c.verifyHTTPOwnership(t.Context(), ed25519Pub(t, priv), did, []string{bare.URL}))
	})

	t.Run("redirect is not followed", func(t *testing.T) {
		redirecting := httptest.NewServer(http.RedirectHandler(srv.URL, http.StatusMovedPermanently))
		t.Cleanup(redirecting.Close)
		require.Error(t, c.verifyHTTPOwnership(t.Context(), ed25519Pub(t, priv), did, []string{redirecting.URL}))
	})
}

func TestHTTPOwnershipSelfSignedTLS(t *testing.T) {
	// A node registering because it has no CA-valid cert yet serves the proof
	// over HTTPS with a self-signed cert; verification rests on the proof
	// signature and the pinned IP, never on WebPKI.
	priv, _, err := crypto.GenerateEd25519Key(rand.Reader)
	require.NoError(t, err)
	mux := http.NewServeMux()
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	handler, err := client.OwnershipProofHandler(signingKey(t, priv), srv.URL)
	require.NoError(t, err)
	mux.Handle("/", handler)
	did, err := httpsig.EncodeDIDKey(priv.GetPublic())
	require.NoError(t, err)

	c := newTestWriter()
	require.NoError(t, c.verifyHTTPOwnership(t.Context(), ed25519Pub(t, priv), did, []string{srv.URL}))
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
	require.Equal(t, "http-ownership", resp.Verification)
}

func TestCanonicalOrigin(t *testing.T) {
	// A path or userinfo in the address is rejected, so the signed server
	// string cannot be widened.
	for _, bad := range []string{
		"https://gw.example/some/path",
		"https://user@gw.example",
		"ftp://gw.example",
		"https://gw.example?x=1",
	} {
		_, err := client.CanonicalOrigin(bad)
		require.Error(t, err, bad)
	}

	// RFC 6454 origin: lowercase host, default port omitted, custom port kept.
	for _, tc := range []struct{ in, want, port string }{
		{"https://GW.Example", "https://gw.example", "443"},
		{"https://gw.example:443", "https://gw.example", "443"},
		{"https://gw.example:8443", "https://gw.example:8443", "8443"},
		{"http://gw.example", "http://gw.example", "80"},
		{"http://gw.example:8080", "http://gw.example:8080", "8080"},
		{"https://[2001:DB8::1]", "https://[2001:db8::1]", "443"},
		{"https://[2001:db8::1]:8443", "https://[2001:db8::1]:8443", "8443"},
	} {
		s, err := client.CanonicalOrigin(tc.in)
		require.NoError(t, err, tc.in)
		require.Equal(t, tc.want, s.URL, tc.in)
		require.Equal(t, tc.port, s.Port, tc.in)
	}
}

func TestHTTPOwnershipIPv6Literal(t *testing.T) {
	// An IPv6-literal endpoint must produce a fetchable proof URL and a
	// matching server claim on both sides.
	ln, err := net.Listen("tcp", "[::1]:0")
	require.NoError(t, err)
	mux := http.NewServeMux()
	srv := httptest.NewUnstartedServer(mux)
	srv.Listener.Close()
	srv.Listener = ln
	srv.Start()
	t.Cleanup(srv.Close)

	priv, _, err := crypto.GenerateEd25519Key(rand.Reader)
	require.NoError(t, err)
	handler, err := client.OwnershipProofHandler(signingKey(t, priv), srv.URL)
	require.NoError(t, err)
	mux.Handle("/", handler)
	did, err := httpsig.EncodeDIDKey(priv.GetPublic())
	require.NoError(t, err)

	// Pin the bracketed form itself: without this, both sides would agree on
	// even a malformed server string (they derive it through the same call)
	// and the fetch, which dials the pinned IP rather than the URL host,
	// would pass regardless.
	s, err := client.CanonicalOrigin(srv.URL)
	require.NoError(t, err)
	require.Equal(t, "http://"+srv.Listener.Addr().String(), s.URL)
	require.Contains(t, s.URL, "[::1]")

	c := newTestWriter()
	require.NoError(t, c.verifyHTTPOwnership(t.Context(), ed25519Pub(t, priv), did, []string{srv.URL}))
}
