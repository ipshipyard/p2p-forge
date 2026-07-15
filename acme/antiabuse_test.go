package acme

import (
	"bytes"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ipfs/go-datastore"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
)

func TestNonceStoreReplay(t *testing.T) {
	ns := newNonceStore(ttlDatastore{datastore.NewMapDatastore()}, time.Minute)
	_, priv := newRegistrantHost(t)
	pid, err := peer.IDFromPublicKey(priv.GetPublic())
	require.NoError(t, err)

	require.NoError(t, ns.reserve(t.Context(), pid, "nonce-abc"))
	require.ErrorIs(t, ns.reserve(t.Context(), pid, "nonce-abc"), errReplay)
	require.NoError(t, ns.reserve(t.Context(), pid, "nonce-xyz"), "different nonce is fresh")
}

func TestV2NonceReplayRejected(t *testing.T) {
	initMetrics()
	h, priv := newRegistrantHost(t)
	c := newTestWriter()

	value := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x05}, 32))
	signed := signedV2Request(t, priv, value, addrStrings(h))
	body, err := readAndRestore(signed)
	require.NoError(t, err)
	header := signed.Header.Clone()

	replay := func() *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "https://"+v2TestDomain+"/v2/_acme-challenge", bytes.NewReader(body))
		r.Host = v2TestDomain
		r.Header = header.Clone()
		rec := httptest.NewRecorder()
		c.handleV2Challenge(rec, r)
		return rec
	}

	require.Equal(t, http.StatusOK, replay().Code, "first submission succeeds")
	require.Equal(t, http.StatusConflict, replay().Code, "replay of the same nonce is rejected")
}

// readAndRestore reads a request body and refills it so the request stays usable.
func readAndRestore(r *http.Request) ([]byte, error) {
	buf := new(bytes.Buffer)
	if _, err := buf.ReadFrom(r.Body); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
