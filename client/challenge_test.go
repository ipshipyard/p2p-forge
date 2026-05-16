package client

import (
	"crypto/rand"
	"errors"
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/stretchr/testify/require"
)

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestWithHTTPClient(t *testing.T) {
	t.Run("rejects nil client", func(t *testing.T) {
		cfg := &P2PForgeCertMgrConfig{}
		err := WithHTTPClient(nil)(cfg)
		require.Error(t, err)
		require.Nil(t, cfg.httpClient)
	})

	t.Run("stores client on config", func(t *testing.T) {
		cfg := &P2PForgeCertMgrConfig{}
		c := &http.Client{}
		require.NoError(t, WithHTTPClient(c)(cfg))
		require.Same(t, c, cfg.httpClient)
	})
}

func TestWithChallengeHTTPClient(t *testing.T) {
	t.Run("rejects nil client", func(t *testing.T) {
		o := &sendChallengeOptions{}
		err := WithChallengeHTTPClient(nil)(o)
		require.Error(t, err)
		require.Nil(t, o.httpClient)
	})

	t.Run("stores client on options", func(t *testing.T) {
		o := &sendChallengeOptions{}
		c := &http.Client{}
		require.NoError(t, WithChallengeHTTPClient(c)(o))
		require.Same(t, c, o.httpClient)
	})
}

// TestSendChallengeUsesProvidedClient locks down the wiring: the *http.Client
// supplied via WithChallengeHTTPClient must be the one that actually issues
// the registration request. Without this, a future refactor could silently
// drop the client and fall back to http.DefaultClient.
func TestSendChallengeUsesProvidedClient(t *testing.T) {
	sk, _, err := crypto.GenerateEd25519Key(rand.Reader)
	require.NoError(t, err)

	sentinel := errors.New("transport invoked")
	var called atomic.Bool
	var gotURL atomic.Value // string

	httpClient := &http.Client{
		Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			called.Store(true)
			gotURL.Store(req.URL.String())
			return nil, sentinel
		}),
	}

	err = SendChallenge(
		t.Context(),
		"http://forge.example.invalid",
		sk,
		"test-challenge-value",
		nil, // no advertised addresses needed for this wiring test
		"",  // forgeAuth
		"",  // userAgent (falls back to default)
		nil, // modifyForgeRequest
		WithChallengeHTTPClient(httpClient),
	)
	require.Error(t, err, "transport returns sentinel, so SendChallenge must fail")
	require.True(t, called.Load(), "custom transport was not invoked; SendChallenge is ignoring the supplied client")
	require.Equal(t, "http://forge.example.invalid/v1/_acme-challenge", gotURL.Load())
}

// TestSendChallengeBackwardCompatible verifies the legacy positional-only
// signature still compiles and runs when no options are supplied.
func TestSendChallengeBackwardCompatible(t *testing.T) {
	sk, _, err := crypto.GenerateEd25519Key(rand.Reader)
	require.NoError(t, err)

	// Unroutable address fails fast at dial time; we only care that the
	// no-options call path still works (no panic, no compile change).
	err = SendChallenge(
		t.Context(),
		"http://127.0.0.1:1", // reserved port, connection refused
		sk,
		"test-challenge-value",
		nil,
		"",
		"",
		nil,
	)
	require.Error(t, err)
}
