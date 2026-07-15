package httpsig

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/dunglas/httpsfv"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/stretchr/testify/require"
)

const (
	testAuthority = "registration.libp2p.direct"
	testURL       = "https://registration.libp2p.direct/v2/_acme-challenge"
)

// fixedKey returns a deterministic Ed25519 key so signatures are reproducible.
func fixedKey(t *testing.T, seed byte) crypto.PrivKey {
	t.Helper()
	src := bytes.Repeat([]byte{seed}, 64)
	priv, _, err := crypto.GenerateEd25519Key(bytes.NewReader(src))
	require.NoError(t, err)
	return priv
}

func newRequest(t *testing.T, body []byte) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, testURL, bytes.NewReader(body))
	require.NoError(t, err)
	return req
}

func TestSignVerifyRoundTrip(t *testing.T) {
	priv := fixedKey(t, 0x01)
	body := []byte(`{"value":"3q2-7w","addresses":["/dns4/example.com/tcp/443/tls/http"]}`)
	req := newRequest(t, body)

	now := time.Unix(1_700_000_000, 0)
	p, err := NewSignParams(now, time.Minute)
	require.NoError(t, err)
	require.NoError(t, SignRequest(req, priv, body, p))

	got, err := VerifyRequest(req, body, VerifyConfig{Authority: testAuthority, Now: now})
	require.NoError(t, err)

	wantID, err := EncodeDIDKey(priv.GetPublic())
	require.NoError(t, err)
	require.Equal(t, wantID, got.KeyID)
	require.True(t, got.PubKey.Equals(priv.GetPublic()))
	require.Equal(t, p.Nonce, got.Nonce)
}

// TestSignatureBaseGolden pins the exact RFC 9421 signature base bytes so a
// canonicalization change cannot pass unnoticed and cross-language signers can
// reproduce it.
func TestSignatureBaseGolden(t *testing.T) {
	priv := fixedKey(t, 0x01)
	keyID, err := EncodeDIDKey(priv.GetPublic())
	require.NoError(t, err)

	body := []byte(`{"value":"abc"}`)
	req := newRequest(t, body)
	cd, err := ContentDigest(body)
	require.NoError(t, err)
	req.Header.Set(contentDigestHeader, cd)
	req.Header.Set("Content-Type", "application/json")

	il := buildInnerList(registrationComponents, sigMeta{
		created: 1_700_000_000,
		expires: 1_700_000_060,
		nonce:   "dGVzdG5vbmNlMTIzNA",
		keyID:   keyID,
		tag:     RegistrationTag,
	})
	sigParams, err := httpsfv.Marshal(il)
	require.NoError(t, err)
	comps, err := deriveComponents(req, registrationComponents)
	require.NoError(t, err)
	base := signatureBase(comps, sigParams)

	sum := sha256.Sum256(body)
	wantDigest := "sha-256=:" + base64.StdEncoding.EncodeToString(sum[:]) + ":"
	require.Equal(t, wantDigest, cd, "Content-Digest format")

	want := strings.Join([]string{
		`"@method": POST`,
		`"@authority": registration.libp2p.direct`,
		`"@path": /v2/_acme-challenge`,
		`"content-type": application/json`,
		`"content-digest": ` + wantDigest,
		`"@signature-params": ("@method" "@authority" "@path" "content-type" "content-digest");created=1700000000;expires=1700000060;nonce="dGVzdG5vbmNlMTIzNA";keyid="` + keyID + `";tag="p2p-forge-reg"`,
	}, "\n")
	require.Equal(t, want, base)
}

func TestVerifyRejectsTamper(t *testing.T) {
	priv := fixedKey(t, 0x02)
	body := []byte(`{"value":"xyz"}`)
	now := time.Unix(1_700_000_000, 0)

	sign := func() *http.Request {
		req := newRequest(t, body)
		p, err := NewSignParams(now, time.Minute)
		require.NoError(t, err)
		require.NoError(t, SignRequest(req, priv, body, p))
		return req
	}

	t.Run("body changed", func(t *testing.T) {
		req := sign()
		_, err := VerifyRequest(req, []byte(`{"value":"XYZ"}`), VerifyConfig{Authority: testAuthority, Now: now})
		require.ErrorContains(t, err, "content-digest")
	})

	t.Run("method changed", func(t *testing.T) {
		req := sign()
		req.Method = http.MethodPut
		_, err := VerifyRequest(req, body, VerifyConfig{Authority: testAuthority, Now: now})
		require.ErrorContains(t, err, "signature verification failed")
	})

	t.Run("covered header changed", func(t *testing.T) {
		req := sign()
		req.Header.Set("Content-Type", "text/plain")
		_, err := VerifyRequest(req, body, VerifyConfig{Authority: testAuthority, Now: now})
		require.ErrorContains(t, err, "signature verification failed")
	})

	t.Run("wrong authority", func(t *testing.T) {
		req := sign()
		_, err := VerifyRequest(req, body, VerifyConfig{Authority: "evil.example", Now: now})
		require.ErrorContains(t, err, "unexpected authority")
	})

	t.Run("signature bytes flipped", func(t *testing.T) {
		req := sign()
		sig := req.Header.Get("Signature")
		req.Header.Set("Signature", strings.Replace(sig, "sig1=:", "sig1=:AA", 1))
		_, err := VerifyRequest(req, body, VerifyConfig{Authority: testAuthority, Now: now})
		require.Error(t, err)
	})
}

func TestVerifyClockWindow(t *testing.T) {
	priv := fixedKey(t, 0x03)
	body := []byte(`{}`)
	signAt := time.Unix(1_700_000_000, 0)

	req := newRequest(t, body)
	p, err := NewSignParams(signAt, time.Minute)
	require.NoError(t, err)
	require.NoError(t, SignRequest(req, priv, body, p))

	t.Run("expired", func(t *testing.T) {
		_, err := VerifyRequest(req, body, VerifyConfig{Authority: testAuthority, Now: signAt.Add(MaxClockSkew + 2*time.Minute)})
		require.ErrorContains(t, err, "expired")
	})

	t.Run("created in future", func(t *testing.T) {
		_, err := VerifyRequest(req, body, VerifyConfig{Authority: testAuthority, Now: signAt.Add(-time.Hour)})
		require.ErrorContains(t, err, "future")
	})

	t.Run("within skew ok", func(t *testing.T) {
		_, err := VerifyRequest(req, body, VerifyConfig{Authority: testAuthority, Now: signAt.Add(30 * time.Second)})
		require.NoError(t, err)
	})
}

func TestVerifyRejectsWrongProfile(t *testing.T) {
	priv := fixedKey(t, 0x04)
	body := []byte(`{}`)
	now := time.Unix(1_700_000_000, 0)

	t.Run("wrong tag", func(t *testing.T) {
		req := newRequest(t, body)
		cd, err := ContentDigest(body)
		require.NoError(t, err)
		req.Header.Set(contentDigestHeader, cd)
		req.Header.Set("Content-Type", "application/json")
		il := buildInnerList(registrationComponents, sigMeta{
			created: now.Unix(), expires: now.Add(time.Minute).Unix(),
			nonce: "dGVzdG5vbmNlMTIzNA", keyID: mustDID(t, priv), tag: "some-other-service",
		})
		signInto(t, req, priv, il)
		_, err = VerifyRequest(req, body, VerifyConfig{Authority: testAuthority, Now: now})
		require.ErrorContains(t, err, "no signature tagged")
	})

	t.Run("missing covered component", func(t *testing.T) {
		req := newRequest(t, body)
		cd, err := ContentDigest(body)
		require.NoError(t, err)
		req.Header.Set(contentDigestHeader, cd)
		req.Header.Set("Content-Type", "application/json")
		shortSet := []string{"@method", "@authority", "@path", "content-digest"} // drops content-type
		il := buildInnerList(shortSet, sigMeta{
			created: now.Unix(), expires: now.Add(time.Minute).Unix(),
			nonce: "dGVzdG5vbmNlMTIzNA", keyID: mustDID(t, priv), tag: RegistrationTag,
		})
		signInto(t, req, priv, il)
		_, err = VerifyRequest(req, body, VerifyConfig{Authority: testAuthority, Now: now})
		require.ErrorContains(t, err, "covered components")
	})
}

func TestVerifyAuthority(t *testing.T) {
	priv := fixedKey(t, 0x05)
	body := []byte(`{}`)
	now := time.Unix(1_700_000_000, 0)
	req := newRequest(t, body)
	p, err := NewSignParams(now, time.Minute)
	require.NoError(t, err)
	require.NoError(t, SignRequest(req, priv, body, p))

	t.Run("empty configured authority is a misconfig", func(t *testing.T) {
		_, err := VerifyRequest(req, body, VerifyConfig{Authority: "", Now: now})
		require.ErrorContains(t, err, "empty authority")
	})

	t.Run("configured authority is canonicalized", func(t *testing.T) {
		// Uppercase + explicit default port must still match the request.
		_, err := VerifyRequest(req, body, VerifyConfig{Authority: strings.ToUpper(testAuthority) + ":443", Now: now})
		require.NoError(t, err)
	})
}

func TestContentDigestVerify(t *testing.T) {
	body := []byte("hello world")
	cd, err := ContentDigest(body)
	require.NoError(t, err)
	require.NoError(t, verifyContentDigest(cd, body))
	require.Error(t, verifyContentDigest(cd, []byte("hello world!")))
	require.ErrorContains(t, verifyContentDigest(`md5=:xxxx:`, body), "sha-256")
}

// mustDID and signInto are test helpers that build a signature from a
// caller-supplied inner list so tests can exercise malformed profiles.
func mustDID(t *testing.T, priv crypto.PrivKey) string {
	t.Helper()
	id, err := EncodeDIDKey(priv.GetPublic())
	require.NoError(t, err)
	return id
}

// signInto signs req with a caller-supplied inner list, so tests can craft
// malformed profiles (wrong tag, missing component) that SignRequest would not
// produce.
func signInto(t *testing.T, req *http.Request, priv crypto.PrivKey, il httpsfv.InnerList) {
	t.Helper()
	sigParams, err := httpsfv.Marshal(il)
	require.NoError(t, err)
	ids := make([]string, len(il.Items))
	for i, item := range il.Items {
		ids[i] = item.Value.(string)
	}
	comps, err := deriveComponents(req, ids)
	require.NoError(t, err)
	sig, err := priv.Sign([]byte(signatureBase(comps, sigParams)))
	require.NoError(t, err)

	inputDict := httpsfv.NewDictionary()
	inputDict.Add(sigLabel, il)
	inputStr, err := httpsfv.Marshal(inputDict)
	require.NoError(t, err)
	req.Header.Set("Signature-Input", inputStr)

	sigDict := httpsfv.NewDictionary()
	sigDict.Add(sigLabel, httpsfv.NewItem(sig))
	sigStr, err := httpsfv.Marshal(sigDict)
	require.NoError(t, err)
	req.Header.Set("Signature", sigStr)
}
