package acme

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/ipfs/go-datastore"
	"github.com/ipshipyard/p2p-forge/client"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multibase"
)

// v2 registration API paths, mounted beside the unchanged v1 endpoints.
const (
	registrationV2ApiPath = "/v2/_acme-challenge"
	healthV2ApiPath       = "/v2/health"
)

// maxV2BodySize bounds the registration request body.
const maxV2BodySize = 8 << 10 // 8 KiB

// handleV2Challenge verifies an RFC 9421-signed registration and, on success,
// stores the DNS-01 TXT value for the peer derived from the signing key. It
// replaces the v1 libp2p PeerID-auth handshake with a single signed request.
func (c *acmeWriter) handleV2Challenge(w http.ResponseWriter, r *http.Request) {
	// The signature binds @authority to the registration domain. Without a
	// configured domain that binding is empty and would match any request, so
	// refuse to serve v2 rather than fail open.
	if c.Domain == "" {
		writeProblem(w, http.StatusInternalServerError, "misconfigured", "registration domain is not configured")
		log.Error("v2: registration-domain is not configured; refusing v2 registration")
		return
	}
	// Closed grammar: the signature does not cover the query string, so reject
	// any request that carries one.
	if r.URL.RawQuery != "" {
		writeProblem(w, http.StatusBadRequest, "unexpected-query", "query strings are not allowed")
		return
	}

	// Cheapest gate first: optional shared-secret access token.
	if c.forgeAuthKey != "" && !constantTimeEqual(r.Header.Get(client.ForgeAuthHeader), c.forgeAuthKey) {
		writeProblem(w, http.StatusForbidden, "forbidden", fmt.Sprintf("missing or invalid %s header", client.ForgeAuthHeader))
		return
	}

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxV2BodySize))
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			writeProblem(w, http.StatusRequestEntityTooLarge, "body-too-large", "request body exceeds limit")
		} else {
			writeProblem(w, http.StatusBadRequest, "malformed-body", "error reading request body")
		}
		return
	}

	// Verify the signature, digest, freshness window, and authority. Identity is
	// derived from the signing key in keyid, never from the body. A request
	// that does not conform to the profile grammar is 400; one that conforms
	// but fails authentication is 401.
	verified, err := verifyV2Request(r, body, c.Domain)
	if err != nil {
		if errors.Is(err, errMalformed) {
			writeProblem(w, http.StatusBadRequest, "malformed-signature", err.Error())
		} else {
			writeProblem(w, http.StatusUnauthorized, "signature-invalid", err.Error())
		}
		return
	}
	peerID := verified.peerID

	typedBody, err := decodeV2Body(body)
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "malformed-body", err.Error())
		return
	}
	if err := validateChallengeValue(typedBody.Value); err != nil {
		writeProblem(w, http.StatusBadRequest, "malformed-value", err.Error())
		return
	}

	if blocked, reason := checkDenylist(clientIPs(r, c.ClientIPHeader), typedBody.Addresses); blocked {
		writeProblem(w, http.StatusForbidden, "denylisted", reason)
		return
	}

	// Prove the key controls a real, reachable endpoint: the http-ownership
	// proof (no libp2p) when an http(s) address is given, else the libp2p
	// dialback.
	mode, err := c.verifyReachable(r.Context(), verified.keyID, peerID, typedBody.Addresses, r.Header.Get("User-Agent"))
	if err != nil {
		log.Debugf("v2: address verification failed for %s: %v", peerID, err)
		writeProblem(w, http.StatusUnprocessableEntity, "verification-failed", "no submitted address could be verified")
		return
	}

	if err := c.Datastore.PutWithTTL(r.Context(), datastore.NewKey(peerID.String()), []byte(typedBody.Value), time.Hour); err != nil {
		writeProblem(w, http.StatusInternalServerError, "storage-error", "failed to store challenge")
		log.Errorf("v2: storing challenge for %s: %v", peerID, err)
		return
	}

	writeJSON(w, http.StatusOK, v2Response{
		DID:          verified.keyID,
		Name:         certWildcard(peerID, c.ForgeDomain),
		Verification: v2Verification{Mode: mode},
		TTL:          int(time.Hour / time.Second),
	})
}

type v2Response struct {
	// DID is the did:key that registered (libp2p-agnostic; no raw peerid).
	DID string `json:"did"`
	// Name is the wildcard cert name; peerid-b36 belongs to the DNS/cert layer.
	Name         string         `json:"name"`
	Verification v2Verification `json:"verification"`
	TTL          int            `json:"ttl"`
}

type v2Verification struct {
	Mode string `json:"mode"`
}

// decodeV2Body parses the registration body, rejecting unknown fields and any
// trailing data.
func decodeV2Body(body []byte) (*requestBody, error) {
	tb := &requestBody{}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(tb); err != nil {
		return nil, fmt.Errorf("decoding body: %w", err)
	}
	if dec.More() {
		return nil, fmt.Errorf("unexpected trailing data after JSON body")
	}
	return tb, nil
}

// validateChallengeValue enforces the RFC 8555 §8.4 shape: base64url of a
// 32-byte SHA-256 digest, no padding.
func validateChallengeValue(value string) error {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return fmt.Errorf("value is not unpadded base64url: %w", err)
	}
	if len(decoded) != 32 {
		return fmt.Errorf("value is not a base64url of a SHA-256 digest")
	}
	return nil
}

// certWildcard returns the wildcard cert name for a peer, e.g.
// "*.<peerid-b36>.libp2p.direct". peerid-b36 lives only in this DNS/cert layer,
// never in the v2 request or proof.
func certWildcard(id peer.ID, forgeDomain string) string {
	b36 := peer.ToCid(id).Encode(multibase.MustNewEncoder(multibase.Base36))
	return fmt.Sprintf("*.%s.%s", b36, forgeDomain)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// problemTypeBase prefixes every problem+json "type" URI. The fragment is the
// type slug; the Errors section of the linked document lists them all.
const problemTypeBase = "https://github.com/ipshipyard/p2p-forge/blob/main/docs/registration-v2.md#"

// writeProblem emits an RFC 9457 problem+json response.
func writeProblem(w http.ResponseWriter, status int, problemType, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"type":   problemTypeBase + problemType,
		"title":  http.StatusText(status),
		"status": status,
		"detail": detail,
	})
}
