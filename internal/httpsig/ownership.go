package httpsig

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/dunglas/httpsfv"
	"github.com/libp2p/go-libp2p/core/crypto"
)

// OwnershipOriginHeader carries the canonical origin (scheme://host[:port]) the
// proof is bound to. Binding the scheme means an http proof cannot satisfy an
// https address, and vice versa.
const OwnershipOriginHeader = "P2p-Forge-Origin"

// Ownership proof validity bounds. The signer picks a window up to
// MaxOwnershipWindow; the verifier enforces the cap. Freshness comes from the
// forge fetching the proof live, so the window only bounds how long a proof
// stays valid after the key holder loses control of the endpoint.
const (
	DefaultOwnershipWindow = 24 * time.Hour
	MaxOwnershipWindow     = 14 * 24 * time.Hour
	ownershipClockSkew     = 5 * time.Minute
)

// ownershipComponents is the fixed covered set for an ownership proof.
var ownershipComponents = []string{"p2p-forge-origin", "content-digest"}

// SignOwnership builds the headers a node serves at
// /.well-known/p2p-forge/<did:key> to prove its key controls origin. The proof
// is static (no per-request input), so it can be signed offline and cached: the
// identity key never has to touch the HTTP tier.
func SignOwnership(priv crypto.PrivKey, origin string, created, expires int64) (http.Header, error) {
	keyID, err := EncodeDIDKey(priv.GetPublic())
	if err != nil {
		return nil, err
	}
	cd, err := ContentDigest(nil) // empty body
	if err != nil {
		return nil, err
	}

	il := buildOwnershipInnerList(sigMeta{created: created, expires: expires, keyID: keyID, tag: OwnershipTag})
	sigParams, err := httpsfv.Marshal(il)
	if err != nil {
		return nil, fmt.Errorf("marshal ownership signature params: %w", err)
	}
	comps := []componentValue{
		{id: "p2p-forge-origin", value: origin},
		{id: "content-digest", value: cd},
	}
	sig, err := priv.Sign([]byte(signatureBase(comps, sigParams)))
	if err != nil {
		return nil, fmt.Errorf("signing ownership proof: %w", err)
	}

	h := http.Header{}
	h.Set(OwnershipOriginHeader, origin)
	h.Set(contentDigestHeader, cd)

	inputDict := httpsfv.NewDictionary()
	inputDict.Add(sigLabel, il)
	inputStr, err := httpsfv.Marshal(inputDict)
	if err != nil {
		return nil, fmt.Errorf("marshal ownership Signature-Input: %w", err)
	}
	h.Set("Signature-Input", inputStr)

	sigDict := httpsfv.NewDictionary()
	sigDict.Add(sigLabel, httpsfv.NewItem(sig))
	sigStr, err := httpsfv.Marshal(sigDict)
	if err != nil {
		return nil, fmt.Errorf("marshal ownership Signature: %w", err)
	}
	h.Set("Signature", sigStr)
	return h, nil
}

// OwnershipVerifyConfig carries the inputs for verifying a fetched proof.
type OwnershipVerifyConfig struct {
	// KeyID is the registration did:key. The proof MUST verify under this key
	// and name it, never a key the proof itself supplies.
	KeyID string
	// ExpectedOrigin is the canonical origin the forge connected to.
	ExpectedOrigin string
	Now            time.Time
}

// VerifyOwnership checks a fetched ownership proof: the Content-Digest matches
// the body, the covered set and tag are exact, the named key is the
// registration key, the origin matches what the forge connected to, the window
// is current and bounded, and the signature verifies under the registration key.
func VerifyOwnership(header http.Header, body []byte, cfg OwnershipVerifyConfig) error {
	if cfg.KeyID == "" || cfg.ExpectedOrigin == "" {
		return errors.New("ownership verify misconfigured: empty keyid or origin")
	}

	cds := header.Values(contentDigestHeader)
	if len(cds) != 1 {
		return fmt.Errorf("expected exactly one Content-Digest, got %d", len(cds))
	}
	if err := verifyContentDigest(cds[0], body); err != nil {
		return err
	}

	inputs := header.Values("Signature-Input")
	if len(inputs) != 1 {
		return fmt.Errorf("expected exactly one Signature-Input, got %d", len(inputs))
	}
	sigs := header.Values("Signature")
	if len(sigs) != 1 {
		return fmt.Errorf("expected exactly one Signature, got %d", len(sigs))
	}
	inputDict, err := httpsfv.UnmarshalDictionary([]string{inputs[0]})
	if err != nil {
		return fmt.Errorf("parse ownership Signature-Input: %w", err)
	}
	sigDict, err := httpsfv.UnmarshalDictionary([]string{sigs[0]})
	if err != nil {
		return fmt.Errorf("parse ownership Signature: %w", err)
	}

	label, il, err := selectByTag(inputDict, OwnershipTag)
	if err != nil {
		return err
	}
	if err := checkComponents(il, ownershipComponents); err != nil {
		return err
	}
	created, err := intParam(il.Params, "created")
	if err != nil {
		return err
	}
	expires, err := intParam(il.Params, "expires")
	if err != nil {
		return err
	}
	keyID, err := strParam(il.Params, "keyid")
	if err != nil {
		return err
	}
	if keyID != cfg.KeyID {
		return fmt.Errorf("ownership proof keyid does not match the registration key")
	}
	if err := checkOwnershipWindow(created, expires, cfg.Now); err != nil {
		return err
	}

	origin := header.Get(OwnershipOriginHeader)
	if origin != cfg.ExpectedOrigin {
		return fmt.Errorf("ownership proof origin %q does not match %q", origin, cfg.ExpectedOrigin)
	}

	pub, err := DecodeDIDKey(cfg.KeyID)
	if err != nil {
		return err
	}
	sig, err := signatureBytes(sigDict, label)
	if err != nil {
		return err
	}
	sigParams, err := httpsfv.Marshal(il)
	if err != nil {
		return fmt.Errorf("re-marshal ownership signature params: %w", err)
	}
	comps := []componentValue{
		{id: "p2p-forge-origin", value: origin},
		{id: "content-digest", value: cds[0]},
	}
	ok, err := pub.Verify([]byte(signatureBase(comps, sigParams)), sig)
	if err != nil {
		return fmt.Errorf("verifying ownership proof: %w", err)
	}
	if !ok {
		return errors.New("ownership proof signature verification failed")
	}
	return nil
}

// buildOwnershipInnerList builds the proof inner list: covered components plus
// created/expires/keyid/tag (no nonce, since the proof is static).
func buildOwnershipInnerList(m sigMeta) httpsfv.InnerList {
	items := make([]httpsfv.Item, len(ownershipComponents))
	for i, id := range ownershipComponents {
		items[i] = httpsfv.NewItem(id)
	}
	params := httpsfv.NewParams()
	params.Add("created", m.created)
	params.Add("expires", m.expires)
	params.Add("keyid", m.keyID)
	params.Add("tag", m.tag)
	return httpsfv.InnerList{Items: items, Params: params}
}

func checkOwnershipWindow(created, expires int64, now time.Time) error {
	if created == 0 || expires == 0 {
		return errors.New("ownership proof missing created/expires")
	}
	if expires <= created {
		return errors.New("ownership proof expires before created")
	}
	if expires-created > int64(MaxOwnershipWindow/time.Second) {
		return fmt.Errorf("ownership proof window exceeds %s", MaxOwnershipWindow)
	}
	ct, et := time.Unix(created, 0), time.Unix(expires, 0)
	if ct.After(now.Add(ownershipClockSkew)) {
		return errors.New("ownership proof not yet valid")
	}
	if et.Before(now.Add(-ownershipClockSkew)) {
		return errors.New("ownership proof has expired")
	}
	return nil
}
