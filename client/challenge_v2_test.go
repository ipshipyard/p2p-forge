package client

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"net/http"
	"testing"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/stretchr/testify/require"
)

func TestIsEd25519(t *testing.T) {
	ed, _, err := crypto.GenerateEd25519Key(rand.Reader)
	require.NoError(t, err)
	require.True(t, isEd25519(ed))

	secp, _, err := crypto.GenerateSecp256k1Key(rand.Reader)
	require.NoError(t, err)
	require.False(t, isEd25519(secp))
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
	sk, _, err := crypto.GenerateEd25519Key(rand.Reader)
	require.NoError(t, err)

	send := func(status int, body string) error {
		return SendChallengeV2(
			context.Background(),
			"http://forge.example.invalid",
			sk, "test-challenge-value", nil,
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
		err := send(http.StatusUnprocessableEntity, "no address verified")
		require.Error(t, err)
		require.NotErrorIs(t, err, ErrV2Unsupported)
		require.ErrorContains(t, err, "no address verified")
	})
}

func TestSendChallengeV2RejectsNonEd25519(t *testing.T) {
	secp, _, err := crypto.GenerateSecp256k1Key(rand.Reader)
	require.NoError(t, err)
	err = SendChallengeV2(
		context.Background(),
		"http://forge.example.invalid",
		secp, "test-challenge-value", nil,
		"", "", nil,
	)
	require.ErrorContains(t, err, "Ed25519")
}
