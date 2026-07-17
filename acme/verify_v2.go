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

// errMalformed marks a request that does not conform to the /v2 signing
// profile (unparseable or missing signature material), as opposed to one that
// fails authentication. The handler maps it to 400 instead of 401.
var errMalformed = errors.New("malformed request")

// verifyV2Request checks the RFC 9421 signature (via yaronf/httpsign) against
// the fixed /v2 profile: the covered components, the RFC 9530 Content-Digest
// over body, the freshness window, the tag, and that @authority is the
// registration domain. Identity is taken from the signature's keyid, which
// carries the public key, so the body has nothing to spoof.
func verifyV2Request(r *http.Request, body []byte, domain string) (*v2Verified, error) {
	// Read the keyid before verification so we can resolve the key it names.
	details, err := httpsign.RequestDetails(httpsig.SigLabel, r)
	if err != nil {
		return nil, fmt.Errorf("%w: parsing signature: %w", errMalformed, err)
	}
	if details.KeyID == nil {
		return nil, fmt.Errorf("%w: signature is missing a keyid", errMalformed)
	}
	if details.Nonce == nil {
		return nil, fmt.Errorf("%w: signature is missing a nonce", errMalformed)
	}
	if len(*details.Nonce) < httpsig.MinNonceLen {
		return nil, fmt.Errorf("%w: nonce is shorter than %d base64url characters", errMalformed, httpsig.MinNonceLen)
	}
	// The library treats expires as optional and only bounds created, so the
	// profile's "expires present, expires-created <= MaxSignatureLifetime" is
	// enforced here. These are unauthenticated parses at this point, but they
	// are covered by the signature verified below, so a reject is safe and a
	// pass is re-checked by the verifier's own policy.
	if details.Created == nil {
		return nil, fmt.Errorf("%w: signature is missing a created parameter", errMalformed)
	}
	if details.Expires == nil {
		return nil, fmt.Errorf("%w: signature is missing an expires parameter", errMalformed)
	}
	if details.Expires.Sub(*details.Created) > httpsig.MaxSignatureLifetime {
		return nil, fmt.Errorf("%w: expires-created exceeds %s", errMalformed, httpsig.MaxSignatureLifetime)
	}
	regPub, err := httpsig.DecodeDIDKey(*details.KeyID)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errMalformed, err)
	}
	raw, err := regPub.Raw()
	if err != nil {
		return nil, fmt.Errorf("%w: reading key: %w", errMalformed, err)
	}

	// The Content-Digest must match the body we actually read. Both a
	// malformed header and a mismatch are the request contradicting itself,
	// knowable without any key material, so they class as malformed (400)
	// rather than as an authentication failure.
	digestBody := io.NopCloser(bytes.NewReader(body))
	if err := httpsign.ValidateContentDigestHeader(r.Header.Values("Content-Digest"), &digestBody, []string{httpsign.DigestSha256}); err != nil {
		return nil, fmt.Errorf("%w: content-digest: %w", errMalformed, err)
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
