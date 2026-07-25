package client

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/ipshipyard/p2p-forge/internal/httpsig"
	"github.com/yaronf/httpsign"
)

// SigningKey is a node's /v2 signing identity. Only Ed25519 is supported today;
// wrapping the key keeps the public API stable if more key types are added
// later (a new NewXxxSigningKey constructor, not a changed function signature).
type SigningKey struct {
	priv   ed25519.PrivateKey
	didKey string
}

// NewEd25519SigningKey wraps an Ed25519 private key as a v2 SigningKey.
func NewEd25519SigningKey(priv ed25519.PrivateKey) (SigningKey, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return SigningKey{}, fmt.Errorf("invalid Ed25519 private key length %d", len(priv))
	}
	did, err := httpsig.EncodeDIDKeyEd25519(priv.Public().(ed25519.PublicKey))
	if err != nil {
		return SigningKey{}, err
	}
	return SigningKey{priv: priv, didKey: did}, nil
}

// DIDKey returns the did:key identifier the forge derives identity from.
func (k SigningKey) DIDKey() string { return k.didKey }

// signRequest signs req in place for the /v2 registration profile: an RFC 9421
// signature over the fixed components plus an RFC 9530 Content-Digest over body.
func (k SigningKey) signRequest(req *http.Request, body []byte) error {
	nonce, err := generateNonce()
	if err != nil {
		return err
	}
	digestBody := io.NopCloser(bytes.NewReader(body))
	cd, err := httpsign.GenerateContentDigestHeader(&digestBody, []string{httpsign.DigestSha256})
	if err != nil {
		return fmt.Errorf("generating content-digest: %w", err)
	}
	req.Header.Set("Content-Digest", cd)

	// SignAlg(false) keeps the wire minimal: the key in keyid decides the
	// algorithm, and the server rejects any alg other than ed25519.
	cfg := httpsign.NewSignConfig().
		SignAlg(false).
		SignCreated(true).
		SetExpiresAfter(int64(httpsig.MaxSignatureLifetime / time.Second)).
		SetNonce(nonce).
		SetKeyID(k.didKey).
		SetTag(httpsig.RegistrationTag)
	signer, err := httpsign.NewEd25519Signer(k.priv, cfg, httpsign.Headers(httpsig.RegistrationComponents...))
	if err != nil {
		return fmt.Errorf("building signer: %w", err)
	}
	sigInput, sig, err := httpsign.SignRequest(httpsig.SigLabel, *signer, req)
	if err != nil {
		return fmt.Errorf("signing v2 registration request: %w", err)
	}
	req.Header.Set("Signature-Input", sigInput)
	req.Header.Set("Signature", sig)
	return nil
}

// generateNonce returns a fresh base64url nonce with 128 bits of entropy.
func generateNonce() (string, error) {
	b := make([]byte, httpsig.MinNonceBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generating nonce: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// signOwnershipResponse writes an RFC 9421-signed 200 response proving this key
// controls origin (an RFC 6454 origin). The origin travels in the body, bound
// by a Content-Digest the signature covers, like the registration request.
// Freshness comes from the forge fetching it live over POST, so the response is
// not cacheable.
func (k SigningKey) signOwnershipResponse(w http.ResponseWriter, r *http.Request, origin string) error {
	body := []byte(origin)
	digestBody := io.NopCloser(bytes.NewReader(body))
	cd, err := httpsign.GenerateContentDigestHeader(&digestBody, []string{httpsign.DigestSha256})
	if err != nil {
		return fmt.Errorf("generating content-digest: %w", err)
	}

	cfg := httpsign.NewSignConfig().
		SignAlg(false).
		SignCreated(true).
		SetExpiresAfter(int64(httpsig.OwnershipProofLifetime / time.Second)).
		SetKeyID(k.didKey).
		SetTag(httpsig.OwnershipTag)
	signer, err := httpsign.NewEd25519Signer(k.priv, cfg, httpsign.Headers(httpsig.OwnershipComponents...))
	if err != nil {
		return err
	}

	// Build the response to sign, then copy the signed headers to the wire.
	resp := &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Request: r}
	resp.Header.Set("Content-Digest", cd)
	sigInput, sig, err := httpsign.SignResponse(httpsig.SigLabel, *signer, resp, r)
	if err != nil {
		return err
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Digest", cd)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Signature-Input", sigInput)
	w.Header().Set("Signature", sig)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
	return nil
}
