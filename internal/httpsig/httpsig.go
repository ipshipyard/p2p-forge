package httpsig

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/dunglas/httpsfv"
	"github.com/libp2p/go-libp2p/core/crypto"
)

// Signature-Input / Signature tags identify which fixed profile a signature
// belongs to. The tag is covered by the signature, so it also domain-separates
// a registration signature from an ownership-proof signature and from any
// unrelated RFC 9421 service.
const (
	RegistrationTag = "p2p-forge-reg"
	OwnershipTag    = "p2p-forge-ownership"
)

// Freshness bounds for a registration signature. Exported so docs and callers
// reference the constant rather than a drifting literal.
const (
	// MaxSignatureLifetime bounds expires-created.
	MaxSignatureLifetime = 5 * time.Minute
	// MaxClockSkew is how far in the past `expires` may already be.
	MaxClockSkew = 2 * time.Minute
	// MaxForwardDrift is how far in the future `created` may be.
	MaxForwardDrift = 30 * time.Second
)

// sigLabel is the fixed Signature-Input / Signature dictionary label. The
// profile carries a single signature per request.
const sigLabel = "sig1"

// minNonceLen is the minimum accepted nonce length. Callers SHOULD use >=128
// bits of entropy; GenerateNonce produces 16 random bytes.
const minNonceLen = 16

// registrationComponents is the fixed, ordered set of covered components for a
// /v2 registration request. Verification rejects any request covering a
// different set.
var registrationComponents = []string{"@method", "@authority", "@path", "content-type", "content-digest"}

// SignParams are the per-request RFC 9421 signature parameters chosen by the
// signer. Created/Expires are unix seconds.
type SignParams struct {
	Created int64
	Expires int64
	Nonce   string
}

// NewSignParams builds SignParams valid for lifetime starting at now, with a
// fresh random nonce. lifetime is clamped to MaxSignatureLifetime.
func NewSignParams(now time.Time, lifetime time.Duration) (SignParams, error) {
	if lifetime <= 0 || lifetime > MaxSignatureLifetime {
		lifetime = MaxSignatureLifetime
	}
	nonce, err := GenerateNonce()
	if err != nil {
		return SignParams{}, err
	}
	return SignParams{
		Created: now.Unix(),
		Expires: now.Add(lifetime).Unix(),
		Nonce:   nonce,
	}, nil
}

// GenerateNonce returns a fresh base64url nonce with 128 bits of entropy.
func GenerateNonce() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generating nonce: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// SignRequest signs r in place for the registration profile: it sets
// Content-Type (if unset), Content-Digest, Signature-Input and Signature. body
// must be the exact bytes of the request body.
func SignRequest(r *http.Request, priv crypto.PrivKey, body []byte, p SignParams) error {
	keyID, err := EncodeDIDKey(priv.GetPublic())
	if err != nil {
		return err
	}
	if len(p.Nonce) < minNonceLen {
		return fmt.Errorf("nonce too short (%d < %d)", len(p.Nonce), minNonceLen)
	}

	cd, err := ContentDigest(body)
	if err != nil {
		return err
	}
	r.Header.Set(contentDigestHeader, cd)
	if r.Header.Get("Content-Type") == "" {
		r.Header.Set("Content-Type", "application/json")
	}

	il := buildInnerList(registrationComponents, sigMeta{
		created: p.Created,
		expires: p.Expires,
		nonce:   p.Nonce,
		keyID:   keyID,
		tag:     RegistrationTag,
	})
	sigParams, err := httpsfv.Marshal(il)
	if err != nil {
		return fmt.Errorf("marshal signature params: %w", err)
	}
	comps, err := deriveComponents(r, registrationComponents)
	if err != nil {
		return err
	}
	sig, err := priv.Sign([]byte(signatureBase(comps, sigParams)))
	if err != nil {
		return fmt.Errorf("signing: %w", err)
	}

	inputDict := httpsfv.NewDictionary()
	inputDict.Add(sigLabel, il)
	inputStr, err := httpsfv.Marshal(inputDict)
	if err != nil {
		return fmt.Errorf("marshal Signature-Input: %w", err)
	}
	r.Header.Set("Signature-Input", inputStr)

	sigDict := httpsfv.NewDictionary()
	sigDict.Add(sigLabel, httpsfv.NewItem(sig))
	sigStr, err := httpsfv.Marshal(sigDict)
	if err != nil {
		return fmt.Errorf("marshal Signature: %w", err)
	}
	r.Header.Set("Signature", sigStr)
	return nil
}

// VerifiedRequest is the authenticated result of a valid registration request.
type VerifiedRequest struct {
	PubKey  crypto.PubKey
	KeyID   string
	Nonce   string
	Created int64
	Expires int64
}

// VerifyConfig carries the server-side verification inputs.
type VerifyConfig struct {
	// Authority is the expected @authority (the registration domain), compared
	// after canonicalization.
	Authority string
	// Now is the reference time (injectable for tests).
	Now time.Time
}

// VerifyRequest verifies r against the fixed registration profile and returns
// the authenticated key. It checks Content-Digest against body, the covered
// component set, the freshness window, the authority, and the signature. The
// caller is responsible for nonce single-use (replay) and rate limiting.
func VerifyRequest(r *http.Request, body []byte, cfg VerifyConfig) (*VerifiedRequest, error) {
	wantAuthority := canonicalAuthority(cfg.Authority)
	if wantAuthority == "" {
		return nil, errors.New("verifier misconfigured: empty authority")
	}

	cds := r.Header.Values(contentDigestHeader)
	if len(cds) != 1 {
		return nil, fmt.Errorf("expected exactly one Content-Digest header, got %d", len(cds))
	}
	if err := verifyContentDigest(cds[0], body); err != nil {
		return nil, err
	}

	inputs := r.Header.Values("Signature-Input")
	if len(inputs) != 1 {
		return nil, fmt.Errorf("expected exactly one Signature-Input header, got %d", len(inputs))
	}
	sigs := r.Header.Values("Signature")
	if len(sigs) != 1 {
		return nil, fmt.Errorf("expected exactly one Signature header, got %d", len(sigs))
	}
	inputDict, err := httpsfv.UnmarshalDictionary([]string{inputs[0]})
	if err != nil {
		return nil, fmt.Errorf("parse Signature-Input: %w", err)
	}
	sigDict, err := httpsfv.UnmarshalDictionary([]string{sigs[0]})
	if err != nil {
		return nil, fmt.Errorf("parse Signature: %w", err)
	}

	label, il, err := selectByTag(inputDict, RegistrationTag)
	if err != nil {
		return nil, err
	}
	if err := checkComponents(il, registrationComponents); err != nil {
		return nil, err
	}
	meta, err := readMeta(il)
	if err != nil {
		return nil, err
	}
	if len(meta.nonce) < minNonceLen {
		return nil, fmt.Errorf("nonce too short")
	}
	if err := checkClock(meta.created, meta.expires, cfg.Now); err != nil {
		return nil, err
	}
	pub, err := DecodeDIDKey(meta.keyID)
	if err != nil {
		return nil, err
	}
	if got := canonicalAuthority(requestAuthority(r)); got != wantAuthority {
		return nil, fmt.Errorf("unexpected authority %q, want %q", got, wantAuthority)
	}

	sig, err := signatureBytes(sigDict, label)
	if err != nil {
		return nil, err
	}
	sigParams, err := httpsfv.Marshal(il)
	if err != nil {
		return nil, fmt.Errorf("re-marshal signature params: %w", err)
	}
	comps, err := deriveComponents(r, registrationComponents)
	if err != nil {
		return nil, err
	}
	ok, err := pub.Verify([]byte(signatureBase(comps, sigParams)), sig)
	if err != nil {
		return nil, fmt.Errorf("verifying signature: %w", err)
	}
	if !ok {
		return nil, errors.New("signature verification failed")
	}
	return &VerifiedRequest{
		PubKey:  pub,
		KeyID:   meta.keyID,
		Nonce:   meta.nonce,
		Created: meta.created,
		Expires: meta.expires,
	}, nil
}

// sigMeta holds the RFC 9421 signature parameters carried in the inner list.
type sigMeta struct {
	created int64
	expires int64
	nonce   string
	keyID   string
	tag     string
}

// componentValue is a covered component and its derived value.
type componentValue struct {
	id    string
	value string
}

// signatureBase builds the RFC 9421 signature base: one line per covered
// component, then the @signature-params line with no trailing newline.
func signatureBase(components []componentValue, sigParams string) string {
	var b strings.Builder
	for _, c := range components {
		b.WriteByte('"')
		b.WriteString(c.id)
		b.WriteString(`": `)
		b.WriteString(c.value)
		b.WriteByte('\n')
	}
	b.WriteString(`"@signature-params": `)
	b.WriteString(sigParams)
	return b.String()
}

// buildInnerList constructs the Signature-Input inner list (covered components
// plus parameters, in fixed order).
func buildInnerList(ids []string, m sigMeta) httpsfv.InnerList {
	items := make([]httpsfv.Item, len(ids))
	for i, id := range ids {
		items[i] = httpsfv.NewItem(id)
	}
	params := httpsfv.NewParams()
	params.Add("created", m.created)
	params.Add("expires", m.expires)
	params.Add("nonce", m.nonce)
	params.Add("keyid", m.keyID)
	params.Add("tag", m.tag)
	return httpsfv.InnerList{Items: items, Params: params}
}

// deriveComponents resolves each covered component id to its value from r.
func deriveComponents(r *http.Request, ids []string) ([]componentValue, error) {
	out := make([]componentValue, len(ids))
	for i, id := range ids {
		v, err := deriveComponent(r, id)
		if err != nil {
			return nil, err
		}
		out[i] = componentValue{id: id, value: v}
	}
	return out, nil
}

func deriveComponent(r *http.Request, id string) (string, error) {
	switch id {
	case "@method":
		return strings.ToUpper(r.Method), nil
	case "@authority":
		return canonicalAuthority(requestAuthority(r)), nil
	case "@path":
		p := r.URL.EscapedPath()
		if p == "" {
			p = "/"
		}
		return p, nil
	default:
		vals := r.Header.Values(id)
		if len(vals) == 0 {
			return "", fmt.Errorf("signature base: missing covered header %q", id)
		}
		return strings.TrimSpace(strings.Join(vals, ", ")), nil
	}
}

func requestAuthority(r *http.Request) string {
	if r.Host != "" {
		return r.Host
	}
	return r.URL.Host
}

// canonicalAuthority lowercases an authority and strips a default http/https
// port, matching how both signer and verifier must render @authority.
func canonicalAuthority(a string) string {
	a = strings.ToLower(strings.TrimSpace(a))
	if host, port, err := net.SplitHostPort(a); err == nil && (port == "80" || port == "443") {
		return host
	}
	return a
}

// selectByTag returns the single inner-list member whose tag parameter matches
// want. More than one match, or none, is an error.
func selectByTag(d *httpsfv.Dictionary, want string) (string, httpsfv.InnerList, error) {
	var (
		found bool
		label string
		il    httpsfv.InnerList
	)
	for _, name := range d.Names() {
		member, _ := d.Get(name)
		list, ok := member.(httpsfv.InnerList)
		if !ok {
			continue
		}
		tag, _ := list.Params.Get("tag")
		if ts, _ := tag.(string); ts == want {
			if found {
				return "", httpsfv.InnerList{}, fmt.Errorf("multiple signatures tagged %q", want)
			}
			found, label, il = true, name, list
		}
	}
	if !found {
		return "", httpsfv.InnerList{}, fmt.Errorf("no signature tagged %q", want)
	}
	return label, il, nil
}

// checkComponents verifies the inner list covers exactly want, in order, with
// no per-component parameters.
func checkComponents(il httpsfv.InnerList, want []string) error {
	if len(il.Items) != len(want) {
		return fmt.Errorf("covered components: got %d, want %d", len(il.Items), len(want))
	}
	for i, item := range il.Items {
		if len(item.Params.Names()) != 0 {
			return fmt.Errorf("covered component %q must not carry parameters", want[i])
		}
		got, ok := item.Value.(string)
		if !ok {
			return fmt.Errorf("covered component %d is not a string", i)
		}
		if got != want[i] {
			return fmt.Errorf("covered component %d: got %q, want %q", i, got, want[i])
		}
	}
	return nil
}

// readMeta extracts and type-checks the required signature parameters.
func readMeta(il httpsfv.InnerList) (sigMeta, error) {
	var m sigMeta
	var err error
	if m.created, err = intParam(il.Params, "created"); err != nil {
		return m, err
	}
	if m.expires, err = intParam(il.Params, "expires"); err != nil {
		return m, err
	}
	if m.nonce, err = strParam(il.Params, "nonce"); err != nil {
		return m, err
	}
	if m.keyID, err = strParam(il.Params, "keyid"); err != nil {
		return m, err
	}
	if m.tag, err = strParam(il.Params, "tag"); err != nil {
		return m, err
	}
	return m, nil
}

func intParam(p *httpsfv.Params, name string) (int64, error) {
	v, ok := p.Get(name)
	if !ok {
		return 0, fmt.Errorf("missing signature parameter %q", name)
	}
	i, ok := v.(int64)
	if !ok {
		return 0, fmt.Errorf("signature parameter %q is not an integer", name)
	}
	return i, nil
}

func strParam(p *httpsfv.Params, name string) (string, error) {
	v, ok := p.Get(name)
	if !ok {
		return "", fmt.Errorf("missing signature parameter %q", name)
	}
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("signature parameter %q is not a string", name)
	}
	return s, nil
}

func checkClock(created, expires int64, now time.Time) error {
	if created == 0 || expires == 0 {
		return errors.New("created and expires are required")
	}
	if expires <= created {
		return errors.New("expires must be after created")
	}
	if expires-created > int64(MaxSignatureLifetime/time.Second) {
		return fmt.Errorf("signature lifetime exceeds %s", MaxSignatureLifetime)
	}
	ct, et := time.Unix(created, 0), time.Unix(expires, 0)
	if ct.After(now.Add(MaxForwardDrift)) {
		return errors.New("created is too far in the future")
	}
	if et.Before(now.Add(-MaxClockSkew)) {
		return errors.New("signature has expired")
	}
	return nil
}

func signatureBytes(d *httpsfv.Dictionary, label string) ([]byte, error) {
	member, ok := d.Get(label)
	if !ok {
		return nil, fmt.Errorf("Signature missing label %q", label)
	}
	item, ok := member.(httpsfv.Item)
	if !ok {
		return nil, fmt.Errorf("Signature %q is not an item", label)
	}
	b, ok := item.Value.([]byte)
	if !ok {
		return nil, fmt.Errorf("Signature %q is not a byte sequence", label)
	}
	return b, nil
}
