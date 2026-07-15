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
	"github.com/ipshipyard/p2p-forge/internal/httpsig"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multibase"
)

// v2 registration API paths, mounted beside the unchanged v1 endpoints.
const (
	registrationV2ApiPath = "/v2/_acme-challenge"
	healthV2ApiPath       = "/v2/health"
	profileV2ApiPath      = "/v2"
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
	if c.forgeAuthKey != "" && r.Header.Get(client.ForgeAuthHeader) != c.forgeAuthKey {
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

	// Verify the signature, digest, freshness window, and authority. This
	// yields the authenticated public key; identity is derived from it, never
	// from the body.
	verified, err := httpsig.VerifyRequest(r, body, httpsig.VerifyConfig{
		Authority: c.Domain,
		Now:       time.Now(),
	})
	if err != nil {
		writeProblem(w, http.StatusUnauthorized, "signature-invalid", err.Error())
		return
	}
	peerID, err := peer.IDFromPublicKey(verified.PubKey)
	if err != nil {
		writeProblem(w, http.StatusUnauthorized, "signature-invalid", fmt.Sprintf("deriving peer ID: %s", err))
		return
	}

	typedBody, err := decodeV2Body(body)
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "malformed-body", err.Error())
		return
	}
	if err := validateChallengeValue(typedBody.Value); err != nil {
		writeProblem(w, http.StatusBadRequest, "malformed-value", err.Error())
		return
	}

	if blocked, reason := checkDenylist(clientIPs(r), typedBody.Addresses); blocked {
		writeProblem(w, http.StatusForbidden, "denylisted", reason)
		return
	}

	// "Real node" check. For now this is the (unchanged) libp2p dialback; the
	// hardened dialback and the http-ownership proof land in later commits.
	if err := c.testAddresses(r.Context(), peerID, typedBody.Addresses, r.Header.Get("User-Agent")); err != nil {
		writeProblem(w, http.StatusUnprocessableEntity, "verification-failed", fmt.Sprintf("no address verified: %s", err))
		return
	}

	if err := c.Datastore.PutWithTTL(r.Context(), datastore.NewKey(peerID.String()), []byte(typedBody.Value), time.Hour); err != nil {
		writeProblem(w, http.StatusInternalServerError, "storage-error", "failed to store challenge")
		log.Errorf("v2: storing challenge for %s: %v", peerID, err)
		return
	}

	writeJSON(w, http.StatusOK, v2Response{
		DID:  verified.KeyID,
		Name: certWildcard(peerID, c.ForgeDomain),
		Verification: v2Verification{
			Mode: "libp2p-dialback",
		},
		TTL: int(time.Hour / time.Second),
	})
}

// handleV2Profile serves a static descriptor so a generic signer can discover
// the required covered components and limits without reading source.
func (c *acmeWriter) handleV2Profile(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, v2Profile{
		Endpoint:          registrationV2ApiPath,
		KeyTypes:          []string{"did:key (Ed25519)"},
		CoveredComponents: []string{"@method", "@authority", "@path", "content-type", "content-digest"},
		SignatureParams:   []string{"created", "expires", "nonce", "keyid", "tag"},
		SignatureTag:      httpsig.RegistrationTag,
		MaxBodyBytes:      maxV2BodySize,
		MaxSignatureAgeS:  int(httpsig.MaxSignatureLifetime / time.Second),
		ContentDigest:     "sha-256 (RFC 9530), required, covered by the signature",
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
	Addr string `json:"addr,omitempty"`
}

type v2Profile struct {
	Endpoint          string   `json:"endpoint"`
	KeyTypes          []string `json:"keyTypes"`
	CoveredComponents []string `json:"coveredComponents"`
	SignatureParams   []string `json:"signatureParams"`
	SignatureTag      string   `json:"signatureTag"`
	MaxBodyBytes      int      `json:"maxBodyBytes"`
	MaxSignatureAgeS  int      `json:"maxSignatureAgeSeconds"`
	ContentDigest     string   `json:"contentDigest"`
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

// writeProblem emits an RFC 9457 problem+json response.
func writeProblem(w http.ResponseWriter, status int, problemType, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"type":   "https://specs.ipfs.tech/p2p-forge/v2/errors#" + problemType,
		"title":  http.StatusText(status),
		"status": status,
		"detail": detail,
	})
}
