package httpsig

import (
	"bytes"
	"crypto/sha256"
	"fmt"

	"github.com/dunglas/httpsfv"
)

// contentDigestHeader is the RFC 9530 header carrying the body hash.
const contentDigestHeader = "Content-Digest"

// ContentDigest returns the RFC 9530 Content-Digest field value for a body,
// using SHA-256, e.g. `sha-256=:Mv9b...=:`.
func ContentDigest(body []byte) (string, error) {
	sum := sha256.Sum256(body)
	d := httpsfv.NewDictionary()
	d.Add("sha-256", httpsfv.NewItem(sum[:]))
	s, err := httpsfv.Marshal(d)
	if err != nil {
		return "", fmt.Errorf("content-digest: marshal: %w", err)
	}
	return s, nil
}

// verifyContentDigest checks that the received Content-Digest field value
// carries a sha-256 digest matching body. Additional algorithms are ignored
// per RFC 9530; sha-256 must be present and correct.
func verifyContentDigest(fieldValue string, body []byte) error {
	dict, err := httpsfv.UnmarshalDictionary([]string{fieldValue})
	if err != nil {
		return fmt.Errorf("content-digest: parse: %w", err)
	}
	member, ok := dict.Get("sha-256")
	if !ok {
		return fmt.Errorf("content-digest: missing sha-256")
	}
	item, ok := member.(httpsfv.Item)
	if !ok {
		return fmt.Errorf("content-digest: sha-256 is not an item")
	}
	got, ok := item.Value.([]byte)
	if !ok {
		return fmt.Errorf("content-digest: sha-256 is not a byte sequence")
	}
	want := sha256.Sum256(body)
	if !bytes.Equal(got, want[:]) {
		return fmt.Errorf("content-digest: sha-256 does not match body")
	}
	return nil
}
