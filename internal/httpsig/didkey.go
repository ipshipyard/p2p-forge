// Package httpsig implements the fixed-profile HTTP Message Signatures
// (RFC 9421) and Digest Fields (RFC 9530) used by the p2p-forge /v2
// registration API. It is shared by the client (signer) and the acme server
// (verifier) so both sides build the same signature base by construction.
//
// The profile is deliberately closed: Ed25519 keys only, a fixed set of
// covered components, and did:key key identifiers. This keeps the protocol
// surface libp2p-agnostic (a did:key is a generic W3C identifier) and lets a
// non-Go client sign a request with any RFC 9421 tooling.
package httpsig

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/multiformats/go-multibase"
	"github.com/multiformats/go-multicodec"
)

// didKeyPrefix is the fixed scheme+method prefix of a did:key identifier.
const didKeyPrefix = "did:key:"

// ed25519PubMulticodec is the ed25519-pub multicodec (0xed) as an unsigned
// varint, the byte prefix a did:key places before the raw public key.
var ed25519PubMulticodec = binary.AppendUvarint(nil, uint64(multicodec.Ed25519Pub))

// EncodeDIDKeyEd25519 returns the did:key form of an Ed25519 public key, e.g.
// "did:key:z6Mk...". It takes a stdlib key so the v2 client stays libp2p-free.
func EncodeDIDKeyEd25519(pub ed25519.PublicKey) (string, error) {
	if len(pub) != ed25519.PublicKeySize {
		return "", fmt.Errorf("did:key: invalid Ed25519 public key length %d", len(pub))
	}
	prefixed := append(append([]byte{}, ed25519PubMulticodec...), pub...)
	mb, err := multibase.Encode(multibase.Base58BTC, prefixed)
	if err != nil {
		return "", fmt.Errorf("did:key: multibase encode: %w", err)
	}
	return didKeyPrefix + mb, nil
}

// EncodeDIDKey is the libp2p wrapper of EncodeDIDKeyEd25519, used server-side
// where keys arrive as libp2p crypto.PubKey. Only Ed25519 is supported; other
// libp2p key types continue to use /v1.
func EncodeDIDKey(pub crypto.PubKey) (string, error) {
	if _, ok := pub.(*crypto.Ed25519PublicKey); !ok {
		return "", fmt.Errorf("did:key: only Ed25519 keys are supported, got %s", pub.Type())
	}
	raw, err := pub.Raw()
	if err != nil {
		return "", fmt.Errorf("did:key: reading raw public key: %w", err)
	}
	return EncodeDIDKeyEd25519(ed25519.PublicKey(raw))
}

// DecodeDIDKey parses a did:key into an Ed25519 public key. It rejects any
// other multibase or multicodec so there is exactly one accepted encoding.
func DecodeDIDKey(did string) (crypto.PubKey, error) {
	suffix, ok := strings.CutPrefix(did, didKeyPrefix)
	if !ok {
		return nil, fmt.Errorf("did:key: missing %q prefix", didKeyPrefix)
	}
	enc, data, err := multibase.Decode(suffix)
	if err != nil {
		return nil, fmt.Errorf("did:key: multibase decode: %w", err)
	}
	if enc != multibase.Base58BTC {
		return nil, fmt.Errorf("did:key: expected base58btc (z...), got multibase %q", enc)
	}
	raw, ok := bytes.CutPrefix(data, ed25519PubMulticodec)
	if !ok {
		return nil, fmt.Errorf("did:key: not an Ed25519 key (unexpected multicodec prefix)")
	}
	pub, err := crypto.UnmarshalEd25519PublicKey(raw)
	if err != nil {
		return nil, fmt.Errorf("did:key: invalid Ed25519 public key: %w", err)
	}
	return pub, nil
}
