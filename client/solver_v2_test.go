package client

import (
	"context"
	"net/http"
	"testing"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/mholt/acmez/v3/acme"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// TestManagerSolverSelection confirms the manager picks the /v1 libp2p solver
// by default and the /v2 HTTP solver once WithHTTPBrokeredDNS01 is set.
func TestManagerSolverSelection(t *testing.T) {
	nop := zap.NewNop().Sugar()
	noHost := func() host.Host { return nil }

	cfg := &P2PForgeCertMgrConfig{forgeRegistrationEndpoint: "https://forge.example"}
	s, err := cfg.newDNS01Solver(noHost, nop)
	require.NoError(t, err)
	require.IsType(t, &dns01P2PForgeSolver{}, s)

	require.NoError(t, WithHTTPBrokeredDNS01(testSigningKey(t), []string{"https://gw.example"})(cfg))
	s, err = cfg.newDNS01Solver(noHost, nop)
	require.NoError(t, err)
	require.IsType(t, &httpBrokeredDNS01Solver{}, s)
}

func TestWithHTTPBrokeredDNS01Validation(t *testing.T) {
	cfg := &P2PForgeCertMgrConfig{}
	require.Error(t, WithHTTPBrokeredDNS01(SigningKey{}, []string{"https://gw.example"})(cfg), "empty key")
	require.Error(t, WithHTTPBrokeredDNS01(testSigningKey(t), nil)(cfg), "no origins")
	require.NoError(t, WithHTTPBrokeredDNS01(testSigningKey(t), []string{"https://gw.example"})(cfg))
}

func TestNewHTTPBrokeredDNS01SolverValidation(t *testing.T) {
	key := testSigningKey(t)
	good := HTTPBrokeredDNS01SolverConfig{ForgeEndpoint: "https://forge.example", Key: key, Origins: []string{"https://gw.example"}}

	_, err := NewHTTPBrokeredDNS01Solver(good)
	require.NoError(t, err)

	for name, cfg := range map[string]HTTPBrokeredDNS01SolverConfig{
		"no endpoint": {Key: key, Origins: []string{"https://gw.example"}},
		"no key":      {ForgeEndpoint: "https://forge.example", Origins: []string{"https://gw.example"}},
		"no origins":  {ForgeEndpoint: "https://forge.example", Key: key},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := NewHTTPBrokeredDNS01Solver(cfg)
			require.Error(t, err)
		})
	}
}

// TestHTTPDNS01SolverPresent confirms Present POSTs to /v2 with the configured
// origins and surfaces the forge's response.
func TestHTTPDNS01SolverPresent(t *testing.T) {
	key := testSigningKey(t)
	var gotPath string
	client := &http.Client{Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		gotPath = req.URL.Path
		return respondingClient(http.StatusOK, "ok").Transport.RoundTrip(req)
	})}

	solver, err := NewHTTPBrokeredDNS01Solver(HTTPBrokeredDNS01SolverConfig{
		ForgeEndpoint: "http://forge.example.invalid",
		Key:           key,
		Origins:       []string{"https://gw.example"},
		HTTPClient:    client,
	})
	require.NoError(t, err)

	challenge := acme.Challenge{KeyAuthorization: "test-key-auth"}
	require.NoError(t, solver.Present(context.Background(), challenge))
	require.Equal(t, "/v2/_acme-challenge", gotPath)

	// A rejection surfaces as an error.
	solver2, err := NewHTTPBrokeredDNS01Solver(HTTPBrokeredDNS01SolverConfig{
		ForgeEndpoint: "http://forge.example.invalid",
		Key:           key,
		Origins:       []string{"https://gw.example"},
		HTTPClient:    respondingClient(http.StatusUnprocessableEntity, "no origin verified"),
	})
	require.NoError(t, err)
	require.Error(t, solver2.Present(context.Background(), challenge))
}
