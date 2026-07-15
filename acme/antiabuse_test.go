package acme

import (
	"bytes"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/ipfs/go-datastore"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
)

func TestIPRateLimiter(t *testing.T) {
	rl := newIPRateLimiter(60, 2, time.Minute) // 1/sec, burst 2
	ip := netip.MustParseAddr("203.0.113.4")
	now := time.Unix(1_700_000_000, 0)

	require.True(t, rl.allow(ip, now))
	require.True(t, rl.allow(ip, now))
	require.False(t, rl.allow(ip, now), "burst exhausted")
	require.True(t, rl.allow(ip, now.Add(time.Second)), "refilled after 1s")

	// A different IP has its own bucket.
	require.True(t, rl.allow(netip.MustParseAddr("198.51.100.9"), now))
}

func TestNonceStoreReplay(t *testing.T) {
	ns := newNonceStore(ttlDatastore{datastore.NewMapDatastore()}, time.Minute)
	_, priv := newRegistrantHost(t)
	pid, err := peer.IDFromPublicKey(priv.GetPublic())
	require.NoError(t, err)

	require.NoError(t, ns.reserve(t.Context(), pid, "nonce-abc"))
	require.ErrorIs(t, ns.reserve(t.Context(), pid, "nonce-abc"), errReplay)
	require.NoError(t, ns.reserve(t.Context(), pid, "nonce-xyz"), "different nonce is fresh")
}

func TestPrimaryClientIP(t *testing.T) {
	t.Run("no trusted header uses RemoteAddr, ignores XFF", func(t *testing.T) {
		r := &http.Request{Header: http.Header{"X-Forwarded-For": {"6.6.6.6"}}, RemoteAddr: "9.9.9.9:80"}
		ip, ok := primaryClientIP(r, "")
		require.True(t, ok)
		require.Equal(t, "9.9.9.9", ip.String())
	})
	t.Run("trusted header wins", func(t *testing.T) {
		r := &http.Request{Header: http.Header{"Cf-Connecting-Ip": {"1.2.3.4"}}, RemoteAddr: "9.9.9.9:80"}
		ip, ok := primaryClientIP(r, "CF-Connecting-IP")
		require.True(t, ok)
		require.Equal(t, "1.2.3.4", ip.String())
	})
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

func TestV2RateLimited(t *testing.T) {
	initMetrics()
	c := newTestWriter()
	c.rateLimiter = newIPRateLimiter(1, 1, time.Minute) // burst 1

	// Requests need no valid signature: the rate limit runs before verification.
	mk := func() *http.Request {
		r := httptest.NewRequest(http.MethodPost, "https://"+v2TestDomain+"/v2/_acme-challenge", nil)
		r.Host = v2TestDomain
		r.RemoteAddr = "203.0.113.7:2222"
		return r
	}

	first := httptest.NewRecorder()
	c.handleV2Challenge(first, mk())
	require.NotEqual(t, http.StatusTooManyRequests, first.Code, "first passes the limiter")

	second := httptest.NewRecorder()
	c.handleV2Challenge(second, mk())
	require.Equal(t, http.StatusTooManyRequests, second.Code)
	require.NotEmpty(t, second.Header().Get("Retry-After"))
}

// readAndRestore reads a request body and refills it so the request stays usable.
func readAndRestore(r *http.Request) ([]byte, error) {
	buf := new(bytes.Buffer)
	if _, err := buf.ReadFrom(r.Body); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
