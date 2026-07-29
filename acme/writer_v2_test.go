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
	"strings"
	"testing"
	"time"

	"github.com/ipfs/go-datastore"
	"github.com/ipshipyard/p2p-forge/client"
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

func signedV2Request(t *testing.T, priv crypto.PrivKey, value string, origins []string) *http.Request {
	return signedV2RequestOpts(t, priv, value, origins, v2SignOpts{})
}

// v2SignOpts tweaks how signedV2RequestOpts signs so tests can produce
// requests that violate the profile; the zero value is fully conforming.
type v2SignOpts struct {
	omitCreated bool
	omitExpires bool
	expiresIn   time.Duration // 0 means httpsig.MaxSignatureLifetime
	nonce       string        // "" means a fresh 22-character nonce
	keyID       string        // "" means the did:key of the signing key
	components  []string      // nil means httpsig.RegistrationComponents
}

func signedV2RequestOpts(t *testing.T, priv crypto.PrivKey, value string, origins []string, opts v2SignOpts) *http.Request {
	t.Helper()
	body, err := json.Marshal(map[string]any{"value": value, "origins": origins})
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
	components := opts.components
	if components == nil {
		components = httpsig.RegistrationComponents
	}
	signer, err := httpsign.NewEd25519Signer(ed25519.PrivateKey(raw), cfg, httpsign.Headers(components...))
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
	return c
}

// TestV2ResubmitIsIdempotent locks in the replay stance: the server does not
// track nonces, so resubmitting a captured request within its expires window
// repeats the same registration and changes nothing.
func TestV2ResubmitIsIdempotent(t *testing.T) {
	initMetrics()
	priv, _, err := crypto.GenerateEd25519Key(rand.Reader)
	require.NoError(t, err)
	srv, _ := newProofServer(t, priv)
	c := newTestWriter()

	value := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x05}, 32))
	signed := signedV2Request(t, priv, value, []string{srv.URL})
	body, err := io.ReadAll(signed.Body)
	require.NoError(t, err)
	header := signed.Header.Clone()

	resubmit := func() *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "https://"+v2TestDomain+"/v2/_acme-challenge", bytes.NewReader(body))
		r.Host = v2TestDomain
		r.Header = header.Clone()
		rec := httptest.NewRecorder()
		c.handleV2Challenge(rec, r)
		return rec
	}

	require.Equal(t, http.StatusOK, resubmit().Code, "first submission succeeds")
	require.Equal(t, http.StatusOK, resubmit().Code, "resubmission succeeds too")
}

func TestV2ChallengeHandlerRoundTrip(t *testing.T) {
	initMetrics()
	priv, _, err := crypto.GenerateEd25519Key(rand.Reader)
	require.NoError(t, err)
	srv, _ := newProofServer(t, priv)
	c := newTestWriter()

	value := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0xab}, 32))
	req := signedV2Request(t, priv, value, []string{srv.URL})
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
	require.Equal(t, "HTTP-BROKERED-DNS-01", resp.Challenge)
}

// TestV2ExtraSignatureIgnored confirms a request that carries a second
// signature under another label still verifies: the server reads only sig1.
func TestV2ExtraSignatureIgnored(t *testing.T) {
	initMetrics()
	priv, _, err := crypto.GenerateEd25519Key(rand.Reader)
	require.NoError(t, err)
	srv, _ := newProofServer(t, priv)
	c := newTestWriter()

	value := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x0c}, 32))
	req := signedV2Request(t, priv, value, []string{srv.URL})
	req.Header.Add("Signature-Input", `sig2=("@method");created=1700000000`)
	req.Header.Add("Signature", "sig2=:AAAA:")
	rec := httptest.NewRecorder()

	c.handleV2Challenge(rec, req)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
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
		// 12 bytes decode fine but fall short of the 16-byte minimum.
		shortNonce := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 12))
		req := signedV2RequestOpts(t, priv, value, addrStrings(h), v2SignOpts{nonce: shortNonce})
		rec := httptest.NewRecorder()
		newTestWriter().handleV2Challenge(rec, req)
		require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
	})

	t.Run("nonce not base64url", func(t *testing.T) {
		h, priv := newRegistrantHost(t)
		// 22 characters, but outside the unpadded base64url alphabet.
		req := signedV2RequestOpts(t, priv, value, addrStrings(h), v2SignOpts{nonce: "!!!!!!!!!!!!!!!!!!!!!!"})
		rec := httptest.NewRecorder()
		newTestWriter().handleV2Challenge(rec, req)
		require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
	})

	t.Run("extra covered component", func(t *testing.T) {
		h, priv := newRegistrantHost(t)
		extra := append(append([]string{}, httpsig.RegistrationComponents...), "@scheme")
		req := signedV2RequestOpts(t, priv, value, addrStrings(h), v2SignOpts{components: extra})
		rec := httptest.NewRecorder()
		newTestWriter().handleV2Challenge(rec, req)
		require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
	})

	t.Run("reordered covered components", func(t *testing.T) {
		h, priv := newRegistrantHost(t)
		reordered := append([]string{}, httpsig.RegistrationComponents...)
		reordered[0], reordered[1] = reordered[1], reordered[0]
		req := signedV2RequestOpts(t, priv, value, addrStrings(h), v2SignOpts{components: reordered})
		rec := httptest.NewRecorder()
		newTestWriter().handleV2Challenge(rec, req)
		require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
	})

	t.Run("missing covered component", func(t *testing.T) {
		h, priv := newRegistrantHost(t)
		// Dropping content-digest would unbind the body from the signature.
		short := httpsig.RegistrationComponents[:len(httpsig.RegistrationComponents)-1]
		req := signedV2RequestOpts(t, priv, value, addrStrings(h), v2SignOpts{components: short})
		rec := httptest.NewRecorder()
		newTestWriter().handleV2Challenge(rec, req)
		require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
	})

	t.Run("missing sig1", func(t *testing.T) {
		h, priv := newRegistrantHost(t)
		req := signedV2Request(t, priv, value, addrStrings(h))
		// Rename sig1 to sig2: the server looks only for sig1.
		si := strings.Replace(req.Header.Get("Signature-Input"), "sig1=", "sig2=", 1)
		sig := strings.Replace(req.Header.Get("Signature"), "sig1=", "sig2=", 1)
		req.Header.Set("Signature-Input", si)
		req.Header.Set("Signature", sig)
		rec := httptest.NewRecorder()
		newTestWriter().handleV2Challenge(rec, req)
		require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
	})

	t.Run("alg other than ed25519", func(t *testing.T) {
		h, priv := newRegistrantHost(t)
		req := signedV2Request(t, priv, value, addrStrings(h))
		// The test signer emits alg="ed25519"; swap the value in place.
		si := strings.Replace(req.Header.Get("Signature-Input"), `alg="ed25519"`, `alg="rsa-v1_5-sha256"`, 1)
		require.Contains(t, si, `alg="rsa-v1_5-sha256"`)
		req.Header.Set("Signature-Input", si)
		rec := httptest.NewRecorder()
		newTestWriter().handleV2Challenge(rec, req)
		require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
	})

	t.Run("wrong content type", func(t *testing.T) {
		h, priv := newRegistrantHost(t)
		req := signedV2Request(t, priv, value, addrStrings(h))
		req.Header.Set("Content-Type", "text/plain")
		rec := httptest.NewRecorder()
		newTestWriter().handleV2Challenge(rec, req)
		require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
		require.Contains(t, rec.Body.String(), "application/json")
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

	t.Run("wrong forge auth token", func(t *testing.T) {
		c := newTestWriter()
		c.forgeAuthKey = "test-secret"

		post := func(token string) *httptest.ResponseRecorder {
			r := httptest.NewRequest(http.MethodPost, "https://"+v2TestDomain+"/v2/_acme-challenge", nil)
			r.Host = v2TestDomain
			if token != "" {
				r.Header.Set(client.ForgeAuthHeader, token)
			}
			rec := httptest.NewRecorder()
			c.handleV2Challenge(rec, r)
			return rec
		}

		require.Equal(t, http.StatusForbidden, post("").Code, "missing token")
		require.Equal(t, http.StatusForbidden, post("not-the-secret").Code, "wrong token")
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

	t.Run("unreachable origin", func(t *testing.T) {
		_, priv := newRegistrantHost(t)
		// A well-formed but dead origin: nothing listens here.
		req := signedV2Request(t, priv, value, []string{"http://127.0.0.1:1"})
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
