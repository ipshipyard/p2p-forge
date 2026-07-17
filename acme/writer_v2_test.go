package acme

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ipfs/go-datastore"
	"github.com/ipshipyard/p2p-forge/internal/httpsig"
	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
	"github.com/yaronf/httpsign"
)

const v2TestDomain = "registration.example"

// ttlDatastore adapts an in-memory datastore to the TTLDatastore interface the
// writer needs; TTL is irrelevant for these tests.
type ttlDatastore struct {
	datastore.Datastore
}

func (t ttlDatastore) PutWithTTL(ctx context.Context, k datastore.Key, v []byte, _ time.Duration) error {
	return t.Put(ctx, k, v)
}
func (ttlDatastore) SetTTL(context.Context, datastore.Key, time.Duration) error { return nil }
func (ttlDatastore) GetExpiration(context.Context, datastore.Key) (time.Time, error) {
	return time.Time{}, nil
}

// newRegistrantHost starts a loopback libp2p host whose identity is the Ed25519
// key returned, so the dialback in testAddresses can authenticate it.
func newRegistrantHost(t *testing.T) (host.Host, crypto.PrivKey) {
	t.Helper()
	priv, _, err := crypto.GenerateEd25519Key(rand.Reader)
	require.NoError(t, err)
	h, err := libp2p.New(libp2p.Identity(priv), libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = h.Close() })
	return h, priv
}

func signedV2Request(t *testing.T, priv crypto.PrivKey, value string, addrs []string) *http.Request {
	return signedV2RequestOpts(t, priv, value, addrs, v2SignOpts{})
}

// v2SignOpts tweaks how signedV2RequestOpts signs so tests can produce
// requests that violate the profile; the zero value is fully conforming.
type v2SignOpts struct {
	omitCreated bool
	omitExpires bool
	expiresIn   time.Duration // 0 means httpsig.MaxSignatureLifetime
	nonce       string        // "" means a fresh 22-character nonce
	keyID       string        // "" means the did:key of the signing key
}

func signedV2RequestOpts(t *testing.T, priv crypto.PrivKey, value string, addrs []string, opts v2SignOpts) *http.Request {
	t.Helper()
	body, err := json.Marshal(map[string]any{"value": value, "addresses": addrs})
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "https://"+v2TestDomain+"/v2/_acme-challenge", bytes.NewReader(body))
	req.Host = v2TestDomain
	req.Header.Set("Content-Type", "application/json")

	raw, err := priv.Raw()
	require.NoError(t, err)
	keyID := opts.keyID
	if keyID == "" {
		keyID, err = httpsig.EncodeDIDKey(priv.GetPublic())
		require.NoError(t, err)
	}

	digestBody := io.NopCloser(bytes.NewReader(body))
	cd, err := httpsign.GenerateContentDigestHeader(&digestBody, []string{httpsign.DigestSha256})
	require.NoError(t, err)
	req.Header.Set("Content-Digest", cd)

	nonce := opts.nonce
	if nonce == "" {
		nb := make([]byte, 16)
		_, err = rand.Read(nb)
		require.NoError(t, err)
		nonce = base64.RawURLEncoding.EncodeToString(nb)
	}
	cfg := httpsign.NewSignConfig().SignCreated(!opts.omitCreated).
		SetNonce(nonce).
		SetKeyID(keyID).
		SetTag(httpsig.RegistrationTag)
	if !opts.omitExpires {
		expiresIn := opts.expiresIn
		if expiresIn == 0 {
			expiresIn = httpsig.MaxSignatureLifetime
		}
		cfg = cfg.SetExpires(time.Now().Add(expiresIn).Unix())
	}
	signer, err := httpsign.NewEd25519Signer(ed25519.PrivateKey(raw), cfg, httpsign.Headers(httpsig.RegistrationComponents...))
	require.NoError(t, err)
	sigInput, sig, err := httpsign.SignRequest(httpsig.SigLabel, *signer, req)
	require.NoError(t, err)
	req.Header.Set("Signature-Input", sigInput)
	req.Header.Set("Signature", sig)
	return req
}

func addrStrings(h host.Host) []string {
	out := make([]string, 0, len(h.Addrs()))
	for _, a := range h.Addrs() {
		out = append(out, a.String())
	}
	return out
}

func newTestWriter() *acmeWriter {
	c := &acmeWriter{
		Domain:      v2TestDomain,
		ForgeDomain: "libp2p.direct",
		Datastore:   ttlDatastore{datastore.NewMapDatastore()},
		// Tests dial loopback hosts, which destination-IP vetting would reject.
		AllowPrivateAddrs: true,
	}
	c.initAntiAbuse()
	return c
}

func TestV2ChallengeHandlerRoundTrip(t *testing.T) {
	initMetrics()
	h, priv := newRegistrantHost(t)
	c := newTestWriter()

	value := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0xab}, 32))
	req := signedV2Request(t, priv, value, addrStrings(h))
	rec := httptest.NewRecorder()

	c.handleV2Challenge(rec, req)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	pid, err := peer.IDFromPublicKey(priv.GetPublic())
	require.NoError(t, err)
	got, err := c.Datastore.Get(context.Background(), datastore.NewKey(pid.String()))
	require.NoError(t, err)
	require.Equal(t, value, string(got))

	wantDID, err := httpsig.EncodeDIDKey(priv.GetPublic())
	require.NoError(t, err)
	var resp v2Response
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	require.Equal(t, wantDID, resp.DID)
	require.Contains(t, resp.Name, ".libp2p.direct")
	require.Equal(t, "libp2p-dialback", resp.Verification.Mode)
}

func TestV2ChallengeHandlerRejects(t *testing.T) {
	initMetrics()
	value := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x01}, 32))

	t.Run("tampered body", func(t *testing.T) {
		h, priv := newRegistrantHost(t)
		req := signedV2Request(t, priv, value, addrStrings(h))
		// Swap the body after signing: the digest no longer matches, and a
		// body contradicting its own digest is a malformed request (400).
		bad := []byte(`{"value":"` + value + `","addresses":[]}`)
		req.Body = io.NopCloser(bytes.NewReader(bad))
		req.ContentLength = int64(len(bad))
		rec := httptest.NewRecorder()
		newTestWriter().handleV2Challenge(rec, req)
		require.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("missing created", func(t *testing.T) {
		h, priv := newRegistrantHost(t)
		req := signedV2RequestOpts(t, priv, value, addrStrings(h), v2SignOpts{omitCreated: true})
		rec := httptest.NewRecorder()
		newTestWriter().handleV2Challenge(rec, req)
		require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
	})

	t.Run("missing expires", func(t *testing.T) {
		h, priv := newRegistrantHost(t)
		req := signedV2RequestOpts(t, priv, value, addrStrings(h), v2SignOpts{omitExpires: true})
		rec := httptest.NewRecorder()
		newTestWriter().handleV2Challenge(rec, req)
		require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
	})

	t.Run("expires-created over the lifetime", func(t *testing.T) {
		h, priv := newRegistrantHost(t)
		req := signedV2RequestOpts(t, priv, value, addrStrings(h), v2SignOpts{expiresIn: httpsig.MaxSignatureLifetime + time.Minute})
		rec := httptest.NewRecorder()
		newTestWriter().handleV2Challenge(rec, req)
		require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
	})

	t.Run("nonce below 128 bits", func(t *testing.T) {
		h, priv := newRegistrantHost(t)
		// 12 bytes encode to 16 base64url characters, under the 22 minimum.
		shortNonce := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 12))
		req := signedV2RequestOpts(t, priv, value, addrStrings(h), v2SignOpts{nonce: shortNonce})
		rec := httptest.NewRecorder()
		newTestWriter().handleV2Challenge(rec, req)
		require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
	})

	t.Run("expired signature", func(t *testing.T) {
		h, priv := newRegistrantHost(t)
		// A conforming grammar (delta under the lifetime) whose deadline has
		// passed: the profile checks admit it, the verifier's clock policy
		// must reject it as unauthenticated (401), not malformed.
		req := signedV2RequestOpts(t, priv, value, addrStrings(h), v2SignOpts{expiresIn: -time.Minute})
		rec := httptest.NewRecorder()
		newTestWriter().handleV2Challenge(rec, req)
		require.Equal(t, http.StatusUnauthorized, rec.Code, rec.Body.String())
	})

	t.Run("keyid of a different key", func(t *testing.T) {
		// The security-critical property: claiming someone else's did:key
		// with a signature from another key must fail verification.
		h, priv := newRegistrantHost(t)
		victim, _, err := crypto.GenerateEd25519Key(rand.Reader)
		require.NoError(t, err)
		victimDID, err := httpsig.EncodeDIDKey(victim.GetPublic())
		require.NoError(t, err)
		req := signedV2RequestOpts(t, priv, value, addrStrings(h), v2SignOpts{keyID: victimDID})
		rec := httptest.NewRecorder()
		newTestWriter().handleV2Challenge(rec, req)
		require.Equal(t, http.StatusUnauthorized, rec.Code, rec.Body.String())
	})

	t.Run("wrong authority", func(t *testing.T) {
		h, priv := newRegistrantHost(t)
		req := signedV2Request(t, priv, value, addrStrings(h))
		c := newTestWriter()
		c.Domain = "other.example"
		rec := httptest.NewRecorder()
		c.handleV2Challenge(rec, req)
		require.Equal(t, http.StatusUnauthorized, rec.Code)
	})

	t.Run("bad value length", func(t *testing.T) {
		h, priv := newRegistrantHost(t)
		short := base64.RawURLEncoding.EncodeToString([]byte("too short"))
		req := signedV2Request(t, priv, short, addrStrings(h))
		rec := httptest.NewRecorder()
		newTestWriter().handleV2Challenge(rec, req)
		require.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("unreachable address", func(t *testing.T) {
		_, priv := newRegistrantHost(t)
		// A well-formed but dead address: nothing listens here.
		req := signedV2Request(t, priv, value, []string{"/ip4/127.0.0.1/tcp/1"})
		rec := httptest.NewRecorder()
		newTestWriter().handleV2Challenge(rec, req)
		require.Equal(t, http.StatusUnprocessableEntity, rec.Code)
	})

	t.Run("empty registration domain fails closed", func(t *testing.T) {
		h, priv := newRegistrantHost(t)
		req := signedV2Request(t, priv, value, addrStrings(h))
		c := newTestWriter()
		c.Domain = ""
		rec := httptest.NewRecorder()
		c.handleV2Challenge(rec, req)
		require.Equal(t, http.StatusInternalServerError, rec.Code)
	})

	t.Run("query string rejected", func(t *testing.T) {
		h, priv := newRegistrantHost(t)
		req := signedV2Request(t, priv, value, addrStrings(h))
		req.URL.RawQuery = "foo=bar"
		rec := httptest.NewRecorder()
		newTestWriter().handleV2Challenge(rec, req)
		require.Equal(t, http.StatusBadRequest, rec.Code)
	})
}

func TestV2ProfileHandler(t *testing.T) {
	rec := httptest.NewRecorder()
	newTestWriter().handleV2Profile(rec, httptest.NewRequest(http.MethodGet, "/v2", nil))
	require.Equal(t, http.StatusOK, rec.Code)

	var p v2Profile
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &p))
	require.Equal(t, httpsig.RegistrationTag, p.SignatureTag)
	require.Equal(t, registrationV2ApiPath, p.Endpoint)
}
