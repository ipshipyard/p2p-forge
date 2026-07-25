package client

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

// testSigningKey returns a fresh Ed25519 SigningKey for tests.
func testSigningKey(t *testing.T) SigningKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	k, err := NewEd25519SigningKey(priv)
	require.NoError(t, err)
	return k
}

func TestNewEd25519SigningKey(t *testing.T) {
	k := testSigningKey(t)
	require.Contains(t, k.DIDKey(), "did:key:z")

	_, err := NewEd25519SigningKey(ed25519.PrivateKey("too short"))
	require.Error(t, err)
}

// respondingClient returns an *http.Client whose transport answers every
// request with the given status and body.
func respondingClient(status int, body string) *http.Client {
	return &http.Client{
		Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: status,
				Status:     http.StatusText(status),
				Body:       io.NopCloser(bytes.NewReader([]byte(body))),
				Header:     make(http.Header),
				Request:    req,
			}, nil
		}),
	}
}

func TestSendChallengeV2StatusMapping(t *testing.T) {
	key := testSigningKey(t)

	send := func(status int, body string) error {
		return SendChallengeV2(
			context.Background(),
			"http://forge.example.invalid",
			key, "test-challenge-value", []string{"https://gw.example"},
			"", "", nil,
			WithChallengeHTTPClient(respondingClient(status, body)),
		)
	}

	t.Run("200 succeeds", func(t *testing.T) {
		require.NoError(t, send(http.StatusOK, `{"did":"did:key:z"}`))
	})
	t.Run("404 maps to ErrV2Unsupported", func(t *testing.T) {
		require.ErrorIs(t, send(http.StatusNotFound, "not found"), ErrV2Unsupported)
	})
	t.Run("405 maps to ErrV2Unsupported", func(t *testing.T) {
		require.ErrorIs(t, send(http.StatusMethodNotAllowed, "nope"), ErrV2Unsupported)
	})
	t.Run("422 surfaces the body, not ErrV2Unsupported", func(t *testing.T) {
		err := send(http.StatusUnprocessableEntity, "no origin verified")
		require.Error(t, err)
		require.NotErrorIs(t, err, ErrV2Unsupported)
		require.ErrorContains(t, err, "no origin verified")
	})
}
