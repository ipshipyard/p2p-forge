# p2p-forge `/v2`: adding a key type

`/v2` is Ed25519-only today (2026-Q3), but its request profile is built for crypto-agility
so it can adopt new key types without a breaking change. The near-term driver is
post-quantum signatures. This document explains how a new key type fits and
tracks the standards each one depends on. It builds on the
[`/v2` API reference](registration-v2.md) and uses the same requirements
language (MUST, SHOULD, MAY).

Three things make a key type work, and each SHOULD be pinned to an existing
registry rather than invented here:

1. **Identifier.** `keyid` is a `did:key`
   ([W3C did:key spec](https://w3c-ccg.github.io/did-key-spec/)), which is
   self-describing: the key's type is a
   [multicodec](https://github.com/multiformats/multicodec) prefix on the raw
   public key. The exact Ed25519 encoding (`0xed01` prefix, base58btc, `z`
   header) is pinned by
   [W3C Controlled Identifiers 1.0](https://www.w3.org/TR/cid-1.0/), a
   Recommendation. Adding a type means accepting its multicodec when decoding
   the `did:key`. Old clients are unaffected. A request with a key type the
   server does not accept fails with a `malformed-signature` error.
2. **Algorithm.** The forge MUST derive the signature algorithm from the key's
   multicodec, never from a client-supplied value. RFC 9421 allows an explicit
   `alg` parameter but treats the key material as authoritative; this profile
   follows that, so a present `alg` MUST match the codec-derived algorithm or the
   server MUST reject the request. Prefer an algorithm already in the IANA
   [HTTP Message Signature Algorithms registry](https://www.iana.org/assignments/http-message-signature/http-message-signature.xhtml)
   established by RFC 9421.
3. **Signature encoding.** The bytes in the `Signature` header MUST match what a
   generic RFC 9421 verifier expects for that algorithm. This is the subtle part
   (see below).

## Identifiers: on the wire versus in DNS

Two identifiers derive from the same key, with very different size budgets:

- The **`did:key`** in the request carries the full public key. It is bounded
  only by HTTP header and JSON limits, so a multi-kilobyte post-quantum key is
  fine here.
- The **Peer ID** is the DNS and cert identifier: a base36 CID over the key,
  used as a single label in `_acme-challenge.<peer-id>.<forge>` and in the
  wildcard cert `*.<peer-id>.<forge>`. A DNS label is capped at 63 octets
  ([RFC 1035 section 2.3.4](https://www.rfc-editor.org/rfc/rfc1035#section-2.3.4)),
  and today's Ed25519 label is already about 62 characters, right at that limit.

The Peer ID is defined by the recipe below, with no dependency on the libp2p
stack. The recipe is deliberately the same one
[libp2p](https://github.com/libp2p/specs/blob/master/peer-ids/peer-ids.md) uses
for a peer ID, so the Peer ID is byte-identical to the libp2p peer ID of the
same key and a node keeps one name across `/v1`, `/v2`, and the libp2p
ecosystem.

So the full public key cannot sit in the DNS label once a key is larger than
Ed25519's. The recipe handles this the way libp2p does: for a key above the
inline threshold (42 bytes), the Peer ID uses a SHA-256 multihash of the key
instead of inlining it, so the base36 label stays a fixed ~57 characters
whatever the key size. This is how an RSA Peer ID looks today and how an ML-DSA
one will look: the CID commits to the key, and the full key is recovered from
the `did:key` in the request, not from the DNS name.

A new key type MUST use this hash-based form unless its public key is as small
as Ed25519's. Before enabling a type, an implementation MUST confirm the base36
Peer ID is at most 63 octets.

### Deriving the Ed25519 Peer ID

The Peer ID is a CID over the multihash of the key's protobuf-wrapped public
key. A pure-HTTP client needs no libp2p library to compute it for Ed25519: the
protobuf prefix is constant. From the 32 raw public-key bytes:

1. Prefix them with `0x08 0x01 0x12 0x20` to get the 36-byte protobuf
   `PublicKey{Type: Ed25519, Data: <key>}`.
2. Wrap that in an identity multihash: prefix `0x00 0x24` (code 0, length 36).
3. Wrap that in a CIDv1 with the `libp2p-key` codec: prefix `0x01 0x72`.
4. Encode with multibase base36 (a leading `k`).

Test vector, the `did:key` used throughout this spec:

```
did:key  did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK
peer-id  k51qzi5uqu5dhc96r58jy0jkdk95s0ea50e1ci53otca8mxenz19bxhj4tebxi
```

### Label encoding for new key types

Ed25519 keeps the libp2p peer ID encoding above (protobuf wrapper,
`libp2p-key` codec) on purpose, for backward compatibility. The label
equals the existing libp2p peer ID, so a node's cert matches the
`<peer-id>.libp2p.direct` name that libp2p tooling and browsers already
derive from its key, and one key carries one name across `/v1`, `/v2`, and
libp2p. Dropping the wrapper would shorten the label (57 characters versus
62 for the vector above) but break that correspondence, so it is not worth
it for a key type already deployed in libp2p.

A new key type has no such legacy. It SHOULD drop the libp2p protobuf
wrapper and identify the key by its own multicodec, the way `did:key`
does: a base36 encoding of the key's multicodec (for example a PQ
`ml-dsa-*` code) over the key, not the generic `libp2p-key` codec over a
protobuf. That is shorter and carries no libp2p-specific framing. Pin the
exact encoding when the type is enabled, hashing the key as above to keep
the base36 label within the 63-octet DNS limit.

## Classical key types

Ed25519 is the only supported type. The rest are unsupported on `/v2` and stay
on `/v1`; the notes say what each would need before it could be enabled, and
none should be enabled until a spec pins that piece and ships a test vector.

The multicodec registry marks all of these code points `draft` (it reserves
`permanent` for a small core set), so the values below can still change.

| Key | Status | Multicodec | RFC 9421 algorithm | Notes |
| --- | --- | --- | --- | --- |
| Ed25519 | Supported | `0xed` | `ed25519` | libp2p signs raw 64-byte Ed25519, exactly what RFC 9421 `ed25519` expects, so it interoperates with off-the-shelf tooling. This is why it is the primary. |
| ECDSA P-256 | Unsupported | `0x1200` | `ecdsa-p256-sha256` | libp2p signs ASN.1 DER, while RFC 9421 (section 3.3) mandates the fixed-width `r \|\| s` form (as in JWS), and the multicodec is a compressed point, so both the key bytes and the signature bytes need conversion. |
| ECDSA P-384 | Unsupported | `0x1201` | `ecdsa-p384-sha384` | Same encoding gaps as P-256. |
| RSA (PKCS#1 v1.5, SHA-256) | Unsupported | `0x1205` | `rsa-v1_5-sha256` | Encoding-compatible, but not enabled. Signatures and keys are large, so mind the request size limits. |
| secp256k1 | Unsupported | `0xe7` | none | No IANA-registered RFC 9421 algorithm exists. Enabling it needs a profile-defined algorithm identifier and a decision on encoding (libp2p uses ASN.1 DER). |

## Post-quantum signatures

Post-quantum is why crypto-agility matters now. The near-term risk is "harvest
now, decrypt later," and a swarm needs years of lead time before it can rely on a
new key type, so opt-in support has to exist well before any forced migration.
This is tracked for the wider IPFS and libp2p stack in
[ipfs/kubo#11281](https://github.com/ipfs/kubo/issues/11281), which counts
HTTP-signature (RFC 9421) identities like this one among the pieces that need a
post-quantum path. The goal is opt-in PQ, not changing the Ed25519 default.

The identifier and algorithm layers are already landing:

- NIST finalized [ML-DSA (FIPS 204)](https://csrc.nist.gov/pubs/fips/204/final)
  and [SLH-DSA (FIPS 205)](https://csrc.nist.gov/pubs/fips/205/final).
- [Multicodec](https://github.com/multiformats/multicodec) code points for the
  public keys are registered (draft): `mldsa-{44,65,87}-pub` (`0x1210`-`0x1212`)
  and `slhdsa-*-pub` (`0x1220`+).
- The `ml-dsa-44`, `ml-dsa-65`, and `ml-dsa-87` algorithm identifiers are
  defined by the C2SP [`httpsig-pq`](https://c2sp.org/httpsig-pq)
  specification. They are not yet in the IANA HTTP Message Signature
  Algorithms registry, which currently holds only the six RFC 9421
  algorithms; httpsig-pq requests their registration.

ML-DSA fits this profile more cleanly than ECDSA does: its signatures are raw,
fixed-size byte strings, like Ed25519, so they carry in the `Signature` header
with no DER-to-`r || s` reconciliation. Once the pieces below are in place,
enabling ML-DSA is the same three-step change as any other key type.

| Key | Status | Multicodec | RFC 9421 algorithm | Notes |
| --- | --- | --- | --- | --- |
| ML-DSA-44 / 65 / 87 | Unsupported | `0x1210` / `0x1211` / `0x1212` (draft) | `ml-dsa-44` / `ml-dsa-65` / `ml-dsa-87` (C2SP, IANA registration pending) | Identifiers exist on both layers; blocked on libp2p key support. |
| SLH-DSA (all parameter sets) | Unsupported | `0x1220`+ (draft) | none | No RFC 9421 algorithm yet, and signatures are large (see below). |

What is still pending, and where:

- **libp2p key support is the gating dependency.** `keyid` is a `did:key` over the
  libp2p public key, so p2p-forge can accept an ML-DSA key only once go-libp2p
  produces and verifies one (or the identity layer is decoupled from the
  `libp2p-key` wrapper). This is tracked in
  [ipfs/kubo#11281](https://github.com/ipfs/kubo/issues/11281) and
  [libp2p/specs#710](https://github.com/libp2p/specs/pull/710); p2p-forge will
  follow whatever go-libp2p adopts.
- **did:key** needs its binding for these multicodecs to settle so the identifier
  is unambiguous across implementations.
- **SLH-DSA** has a multicodec but no RFC 9421 algorithm, so it cannot be used on
  the signature path yet.

PQ keys and signatures are large. ML-DSA public keys run 1.3 to 2.6 KB and its
signatures 2.4 to 4.6 KB; SLH-DSA signatures reach 8 to 50 KB; Ed25519 is 32 and
64 bytes. Large public keys never enter the DNS label, because the Peer ID
hashes them the same way it hashes an RSA key (see Identifiers above), but they do
travel in the `did:key`, and the `Signature` header grows with the signature.
Check the header-size limits of any fronting proxy or CDN, and the proof-fetch
header cap on the `HTTP-BROKERED-DNS-01` path. ML-DSA is workable; SLH-DSA is likely
too large to carry in a header for now.

## Guidance

- Prefer a key type that has both a `did:key` multicodec and an IANA-registered
  RFC 9421 algorithm whose signature encoding matches what libp2p produces.
  Ed25519 is the only one that clears all three bars unchanged.
- For ECDSA, specify both conversions before enabling the type, the
  compressed-point public key and the DER-to-`r \|\| s` signature, and add a
  test vector, so non-Go and non-libp2p signers can interoperate.
- Do not invent an `alg` identifier when a published one fits. Adopt the
  registered multicodec and the RFC 9421 algorithm identifier from IANA, or
  from a public spec pending IANA registration (for example the C2SP
  `ml-dsa-*` names above), rather than a local name.
- Migration is additive: a new type is opt-in, the `did:key` self-describes it,
  and Ed25519 stays the default while existing clients keep working through a
  dual-stack transition.
- The ownership proof needs no per-type work: it reuses the same key and
  the same signature machinery, so any key type accepted for requests works for
  the proof automatically.
