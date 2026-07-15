package acme

import (
	"bytes"
	"context"
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
	t.Helper()
	body, err := json.Marshal(map[string]any{"value": value, "addresses": addrs})
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "https://"+v2TestDomain+"/v2/_acme-challenge", bytes.NewReader(body))
	req.Host = v2TestDomain
	params, err := httpsig.NewSignParams(time.Now(), httpsig.MaxSignatureLifetime)
	require.NoError(t, err)
	require.NoError(t, httpsig.SignRequest(req, priv, body, params))
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
	return &acmeWriter{
		Domain:      v2TestDomain,
		ForgeDomain: "libp2p.direct",
		Datastore:   ttlDatastore{datastore.NewMapDatastore()},
	}
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
		// Swap the body after signing: the digest (covered by the signature)
		// no longer matches.
		bad := []byte(`{"value":"` + value + `","addresses":[]}`)
		req.Body = io.NopCloser(bytes.NewReader(bad))
		req.ContentLength = int64(len(bad))
		rec := httptest.NewRecorder()
		newTestWriter().handleV2Challenge(rec, req)
		require.Equal(t, http.StatusUnauthorized, rec.Code)
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
