package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/ipshipyard/p2p-forge/internal/httpsig"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/multiformats/go-multiaddr"
)

// RegistrationAPIVersion selects which forge registration API the client uses.
type RegistrationAPIVersion string

const (
	// RegistrationV1 uses the libp2p PeerID-auth handshake (/v1).
	RegistrationV1 RegistrationAPIVersion = "v1"
	// RegistrationV2 uses RFC 9421 request signatures (/v2). Requires an
	// Ed25519 identity key.
	RegistrationV2 RegistrationAPIVersion = "v2"
	// RegistrationAuto tries /v2 for Ed25519 keys and falls back to /v1 when
	// the endpoint is unavailable.
	RegistrationAuto RegistrationAPIVersion = "auto"
)

// ErrV2Unsupported reports that the forge does not expose the /v2 endpoint, so
// a caller may fall back to /v1.
var ErrV2Unsupported = errors.New("v2 registration endpoint not available")

// SendChallengeV2 submits the DNS-01 challenge value to the forge /v2 endpoint,
// authenticated by a single RFC 9421 request signature over the peer's Ed25519
// key. Unlike v1 it is one request: no PeerID-auth handshake, no cookie jar.
func SendChallengeV2(ctx context.Context, baseURL string, privKey crypto.PrivKey, challenge string, addrs []multiaddr.Multiaddr, forgeAuth string, userAgent string, modifyForgeRequest func(r *http.Request) error, opts ...SendChallengeOption) error {
	o := sendChallengeOptions{}
	for _, opt := range opts {
		if err := opt(&o); err != nil {
			return err
		}
	}

	registrationURL := fmt.Sprintf("%s/v2/_acme-challenge", baseURL)
	body, err := marshalChallengeBody(challenge, addrs)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, registrationURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("creating request to %s: %w", registrationURL, err)
	}
	req.Header.Set("Content-Type", "application/json")
	if userAgent == "" {
		userAgent = defaultUserAgent
	}
	req.Header.Set("User-Agent", userAgent)
	if forgeAuth != "" {
		req.Header.Set(ForgeAuthHeader, forgeAuth)
	}

	// modifyForgeRequest runs before signing: it may set req.Host, which is a
	// covered component (@authority).
	if modifyForgeRequest != nil {
		if err := modifyForgeRequest(req); err != nil {
			return err
		}
	}

	params, err := httpsig.NewSignParams(time.Now(), httpsig.MaxSignatureLifetime)
	if err != nil {
		return err
	}
	if err := httpsig.SignRequest(req, privKey, body, params); err != nil {
		return fmt.Errorf("signing v2 registration request: %w", err)
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

	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusMethodNotAllowed {
		return fmt.Errorf("%w: %s", ErrV2Unsupported, resp.Status)
	}
	if resp.StatusCode != http.StatusOK {
		respBody, readErr := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		if readErr != nil {
			return fmt.Errorf("%s from %s (reading error body failed: %w)", resp.Status, registrationURL, readErr)
		}
		return fmt.Errorf("%s error from %s: %q", resp.Status, registrationURL, respBody)
	}
	return nil
}

func marshalChallengeBody(challenge string, addrs []multiaddr.Multiaddr) ([]byte, error) {
	maStrs := make([]string, len(addrs))
	for i, addr := range addrs {
		maStrs[i] = addr.String()
	}
	body, err := json.Marshal(&struct {
		Value     string   `json:"value"`
		Addresses []string `json:"addresses"`
	}{
		Value:     challenge,
		Addresses: maStrs,
	})
	if err != nil {
		return nil, fmt.Errorf("marshaling challenge body: %w", err)
	}
	return body, nil
}

// isEd25519 reports whether k is an Ed25519 key, the only type /v2 accepts.
func isEd25519(k crypto.PrivKey) bool {
	_, ok := k.(*crypto.Ed25519PrivateKey)
	return ok
}
