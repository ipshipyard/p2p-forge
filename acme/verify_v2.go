package acme

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/ipshipyard/p2p-forge/internal/httpsig"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/yaronf/httpsign"
)

// v2Verified is the authenticated result of a valid registration request.
type v2Verified struct {
	peerID peer.ID
	keyID  string // the did:key that signed
	nonce  string
}

// verifyV2Request checks the RFC 9421 signature (via yaronf/httpsign) against
// the fixed /v2 profile: the covered components, the RFC 9530 Content-Digest
// over body, the freshness window, the tag, and that @authority is the
// registration domain. Identity is taken from the signature's keyid, which
// carries the public key, so the body has nothing to spoof.
func verifyV2Request(r *http.Request, body []byte, domain string) (*v2Verified, error) {
	// Read the keyid before verification so we can resolve the key it names.
	details, err := httpsign.RequestDetails(httpsig.SigLabel, r)
	if err != nil {
		return nil, fmt.Errorf("parsing signature: %w", err)
	}
	if details.KeyID == nil {
		return nil, errors.New("signature is missing a keyid")
	}
	if details.Nonce == nil || len(*details.Nonce) < httpsig.MinNonceLen {
		return nil, errors.New("signature is missing a nonce")
	}
	regPub, err := httpsig.DecodeDIDKey(*details.KeyID)
	if err != nil {
		return nil, err
	}
	raw, err := regPub.Raw()
	if err != nil {
		return nil, fmt.Errorf("reading key: %w", err)
	}

	// The Content-Digest must match the body we actually read.
	digestBody := io.NopCloser(bytes.NewReader(body))
	if err := httpsign.ValidateContentDigestHeader(r.Header.Values("Content-Digest"), &digestBody, []string{httpsign.DigestSha256}); err != nil {
		return nil, fmt.Errorf("content-digest: %w", err)
	}

	// Verify the signature. The verifier requires every covered component, so a
	// caller cannot drop one; the tag and freshness window are enforced too.
	cfg := httpsign.NewVerifyConfig().
		SetVerifyCreated(true).
		SetNotNewerThan(httpsig.MaxForwardDrift).
		SetNotOlderThan(httpsig.MaxSignatureLifetime + httpsig.MaxClockSkew).
		SetRejectExpired(true).
		SetAllowedTags([]string{httpsig.RegistrationTag})
	verifier, err := httpsign.NewEd25519Verifier(ed25519.PublicKey(raw), cfg, httpsign.Headers(httpsig.RegistrationComponents...))
	if err != nil {
		return nil, fmt.Errorf("building verifier: %w", err)
	}
	if err := httpsign.VerifyRequest(httpsig.SigLabel, *verifier, r); err != nil {
		return nil, fmt.Errorf("signature verification failed: %w", err)
	}

	// @authority is covered by the signature; it must be our registration domain.
	if httpsig.CanonicalAuthority(r.Host) != httpsig.CanonicalAuthority(domain) {
		return nil, fmt.Errorf("unexpected authority %q", r.Host)
	}

	peerID, err := peer.IDFromPublicKey(regPub)
	if err != nil {
		return nil, fmt.Errorf("deriving peer ID: %w", err)
	}
	return &v2Verified{peerID: peerID, keyID: *details.KeyID, nonce: *details.Nonce}, nil
}
