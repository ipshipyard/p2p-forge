package acme

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/dunglas/httpsfv"
	"github.com/ipshipyard/p2p-forge/internal/httpsig"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/yaronf/httpsign"
)

// v2Verified is the authenticated result of a valid registration request.
type v2Verified struct {
	peerID peer.ID
	keyID  string            // the did:key that signed
	pub    ed25519.PublicKey // the key inside keyID, decoded once
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
	if err := enforceV2Envelope(r); err != nil {
		return nil, err
	}
	// Read the keyid before verification so we can resolve the key it names.
	details, err := httpsign.RequestDetails(httpsig.SigLabel, r)
	if err != nil {
		return nil, fmt.Errorf("%w: parsing signature: %w", errMalformed, err)
	}
	if details.KeyID == nil {
		return nil, fmt.Errorf("%w: signature is missing a keyid", errMalformed)
	}
	// The key in keyid decides the algorithm; a present alg must agree.
	if details.Alg != "" && details.Alg != "ed25519" {
		return nil, fmt.Errorf("%w: alg %q does not match the key type", errMalformed, details.Alg)
	}
	if details.CustomParams != nil {
		return nil, fmt.Errorf("%w: unknown signature parameters", errMalformed)
	}
	// The nonce is required so every signature is unique. The server does not
	// track nonces; replay is bounded by the expires window instead.
	if details.Nonce == nil {
		return nil, fmt.Errorf("%w: signature is missing a nonce", errMalformed)
	}
	nonceBytes, err := base64.RawURLEncoding.DecodeString(*details.Nonce)
	if err != nil {
		return nil, fmt.Errorf("%w: nonce is not unpadded base64url", errMalformed)
	}
	if len(nonceBytes) < httpsig.MinNonceBytes {
		return nil, fmt.Errorf("%w: nonce carries fewer than %d random bytes", errMalformed, httpsig.MinNonceBytes)
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
	// expires decides freshness: it must be present, at most created+300s
	// (both checked above), and not yet passed (SetRejectExpired). The
	// SetNotOlderThan bound never rejects anything on its own, because a
	// created that old always comes with an already-passed expires; it is set
	// only because the library needs a value when verifyCreated is on.
	cfg := httpsign.NewVerifyConfig().
		SetVerifyCreated(true).
		SetNotNewerThan(httpsig.MaxForwardDrift).
		SetNotOlderThan(httpsig.MaxSignatureLifetime + httpsig.MaxForwardDrift).
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
	return &v2Verified{peerID: peerID, keyID: *details.KeyID, pub: ed25519.PublicKey(raw)}, nil
}

// enforceV2Envelope checks the sig1 signature against the closed /v2 grammar
// before any cryptography runs: it must cover exactly the profile components in
// order, with no per-component parameters. A request MAY carry other signatures
// under different labels; the server verifies only sig1 and ignores the rest,
// so a generic RFC 9421 tool that adds its own signature still interoperates.
func enforceV2Envelope(r *http.Request) error {
	coverage, err := sig1Member(r, "Signature-Input")
	if err != nil {
		return err
	}
	if _, err := sig1Member(r, "Signature"); err != nil {
		return err
	}

	list, ok := coverage.(httpsfv.InnerList)
	if !ok {
		return fmt.Errorf("%w: Signature-Input %q is not a component list", errMalformed, httpsig.SigLabel)
	}
	if len(list.Items) != len(httpsig.RegistrationComponents) {
		return fmt.Errorf("%w: signature must cover exactly %v", errMalformed, httpsig.RegistrationComponents)
	}
	for i, item := range list.Items {
		name, ok := item.Value.(string)
		if !ok || name != httpsig.RegistrationComponents[i] {
			return fmt.Errorf("%w: signature must cover exactly %v, in this order", errMalformed, httpsig.RegistrationComponents)
		}
		if item.Params != nil && len(item.Params.Names()) > 0 {
			return fmt.Errorf("%w: covered component %q must not carry parameters", errMalformed, name)
		}
	}
	return nil
}

// sig1Member parses the named header as an RFC 8941 dictionary and returns its
// sig1 member. Other members are allowed and ignored.
func sig1Member(r *http.Request, header string) (httpsfv.Member, error) {
	values := r.Header.Values(header)
	if len(values) == 0 {
		return nil, fmt.Errorf("%w: missing %s header", errMalformed, header)
	}
	dict, err := httpsfv.UnmarshalDictionary(values)
	if err != nil {
		return nil, fmt.Errorf("%w: parsing %s: %w", errMalformed, header, err)
	}
	member, ok := dict.Get(httpsig.SigLabel)
	if !ok {
		return nil, fmt.Errorf("%w: %s has no %q signature", errMalformed, header, httpsig.SigLabel)
	}
	return member, nil
}
