package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
)

// ErrV2Unsupported reports that the forge does not expose the /v2 endpoint, so
// a caller can tell a missing endpoint from a rejected registration.
var ErrV2Unsupported = errors.New("v2 registration endpoint not available")

// SendChallengeV2 submits the DNS-01 challenge value to the forge /v2 endpoint,
// authenticated by a single RFC 9421 request signature over key. Unlike v1 it
// is one HTTP request with no libp2p: no PeerID-auth handshake, no cookie jar,
// no multiaddrs. origins lists the node's public HTTP origins where it serves
// the ownership proof (see OwnershipProofHandler); the forge fetches the proof
// from one of them.
func SendChallengeV2(ctx context.Context, baseURL string, key SigningKey, challenge string, origins []string, forgeAuth string, userAgent string, modifyForgeRequest func(r *http.Request) error, opts ...SendChallengeOption) error {
	o := sendChallengeOptions{}
	for _, opt := range opts {
		if err := opt(&o); err != nil {
			return err
		}
	}

	registrationURL := fmt.Sprintf("%s/v2/_acme-challenge", baseURL)
	body, err := marshalV2Body(challenge, origins)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, registrationURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("creating request to %s: %w", registrationURL, err)
	}
	req.Header.Set("Content-Type", "application/json")
	// decorateForgeRequest runs the modifyForgeRequest hook, which may set
	// req.Host (the covered @authority component), so it must run before
	// signing. Content-Type is also covered and is set above.
	if err := decorateForgeRequest(req, forgeAuth, userAgent, modifyForgeRequest); err != nil {
		return err
	}

	if err := key.signRequest(req, body); err != nil {
		return err
	}

	httpClient := o.httpClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("sending v2 registration request to %s: %w", registrationURL, err)
	}
	defer resp.Body.Close()

	// A forge without /v2 answers 404 (path absent) or 405 (v1-only mux); map
	// those to ErrV2Unsupported so a caller can tell it apart from a rejection.
	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusMethodNotAllowed {
		return fmt.Errorf("%w: %s", ErrV2Unsupported, resp.Status)
	}
	if resp.StatusCode != http.StatusOK {
		return renderChallengeError(resp, registrationURL)
	}
	return nil
}

func marshalV2Body(challenge string, origins []string) ([]byte, error) {
	body, err := json.Marshal(&struct {
		Value   string   `json:"value"`
		Origins []string `json:"origins"`
	}{
		Value:   challenge,
		Origins: origins,
	})
	if err != nil {
		return nil, fmt.Errorf("marshaling challenge body: %w", err)
	}
	return body, nil
}
