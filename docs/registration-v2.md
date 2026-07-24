# p2p-forge `/v2` registration API

The `/v2` API lets a node claim `*.<peerid>.libp2p.direct` and get a TLS cert
without running a libp2p client for the registration itself. Requests are signed
with [HTTP Message Signatures (RFC 9421)](https://www.rfc-editor.org/rfc/rfc9421)
and [Digest Fields (RFC 9530)](https://www.rfc-editor.org/rfc/rfc9530), so any
HTTP client that can produce an Ed25519 signature can register.

`/v1` (the libp2p PeerID-auth handshake) still works and is unchanged. It is
documented in the libp2p [AutoTLS client spec](https://github.com/libp2p/specs/blob/master/tls/autotls-client.md).

This document is the reference for `/v2`. It is enough to implement a client in
any language.

## Requirements language

The key words MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY in this document are to
be interpreted as described in BCP 14
([RFC 2119](https://www.rfc-editor.org/rfc/rfc2119),
[RFC 8174](https://www.rfc-editor.org/rfc/rfc8174)) when, and only when, they
appear in all capitals.

In this document the client is the registrant and the server is the forge.

## What the forge guarantees

Two independent checks gate a registration:

1. **Key ownership.** The request signature proves the caller holds the private
   key for `<peerid>`. Only that key holder can set the DNS-01 record for its
   own `*.<peerid>.libp2p.direct` name. This is the security-critical property,
   and the server MUST verify the signature before it acts on the request.
2. **A real, reachable endpoint.** The caller MUST prove control of a public
   endpoint, either by serving a signed proof over HTTP (below) or by answering
   a libp2p dial. This is anti-abuse: it keeps the forge from minting certs for
   keys that run nothing. It does not scope the cert.

The `<peerid>` never travels on the wire in `/v2`; requests and the success
response carry a `did:key` instead. The base36 peerid appears only in the DNS
name and the cert name, which `/v2` shares with `/v1`.

## Endpoints

| Method | Path | Purpose |
| --- | --- | --- |
| `POST` | `/v2/_acme-challenge` | Set the DNS-01 TXT value for the peer derived from the signing key. |
| `GET` | `/v2/health` | Liveness. Always `204`. |

## Request signing

### Key identifier

`keyid` MUST be a `did:key` for an Ed25519 key, for example
`did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK`. The server MUST derive
identity with `peer.IDFromPublicKey` over the key in `keyid` and MUST NOT trust
any peer field in the body. Non-Ed25519 keys are not accepted on `/v2`; those
peers use `/v1`.

### Content-Digest (RFC 9530)

Every request MUST carry a `Content-Digest` over the exact body bytes, using
`sha-256`. The forge MUST check the digest before it parses the body, and the
signature MUST cover the digest, so signing the request signs the body too.

```
Content-Digest: sha-256=:<base64 of the SHA-256 of the body>:
```

### Signature (RFC 9421)

The signature MUST cover exactly this set of components, in this order, with no
per-component parameters:

```
("@method" "@authority" "@path" "content-type" "content-digest")
```

with these signature parameters:

| Parameter | Meaning |
| --- | --- |
| `created` | Unix seconds when signed. |
| `expires` | Unix seconds when the signature stops being valid. `expires - created` MUST be `<= 300`. |
| `nonce` | At least 128 random bits, unpadded base64url, fresh for every signature. |
| `keyid` | The `did:key` above. |
| `tag` | `p2p-forge-reg`. |

The server enforces this grammar as written: it compares the covered-components
list against the exact serialization above (same set, same order, no
per-component parameters) and rejects anything else as `malformed-signature`.
An `alg` parameter is OPTIONAL, because the key in `keyid` decides the
algorithm; a present `alg` MUST be `ed25519`. Any signature parameter other
than the table above and `alg` MUST be rejected.

`@authority` MUST equal the registration domain (for example
`registration.libp2p.direct`). `@target-uri` and `@scheme` are deliberately not
covered, because a TLS-terminating load balancer rewrites the scheme the backend
sees. A request MUST NOT carry a query string, and the server MUST reject one, so
`@query` is not covered either.

The server MUST reject a `created` more than 30 seconds in the future and an
`expires` that has already passed. With the 300-second cap on
`expires - created`, this is the whole freshness policy. There is no extra
grace for client clock skew: a skewed clock shifts `created` and `expires` by
the same amount, so the `expires` check covers it. A client with a fast clock
SHOULD NOT sign `created` far ahead of real time.

### Signature base

The signature base is built per RFC 9421 section 2.5: one line per covered
component as `"<id>": <value>`, then a final `"@signature-params"` line with no
trailing newline. For a POST to `registration.libp2p.direct` it looks like:

```
"@method": POST
"@authority": registration.libp2p.direct
"@path": /v2/_acme-challenge
"content-type": application/json
"content-digest": sha-256=:<base64>:
"@signature-params": ("@method" "@authority" "@path" "content-type" "content-digest");created=1700000000;expires=1700000060;nonce="dGVzdG5vbmNlMTIzNDU2Nw";keyid="did:key:z6Mk...";tag="p2p-forge-reg"
```

The `Signature-Input` and `Signature` headers MUST each appear exactly once and
carry exactly one signature, labeled `sig1`; the server rejects any other label
and any additional signature:

```
Signature-Input: sig1=("@method" "@authority" "@path" "content-type" "content-digest");created=1700000000;expires=1700000060;nonce="dGVzdG5vbmNlMTIzNDU2Nw";keyid="did:key:z6Mk...";tag="p2p-forge-reg"
Signature: sig1=:<base64 of the Ed25519 signature over the base>:
```

`Signature-Input` MUST be in RFC 8941 canonical form: the server rebuilds the
signature base from the canonical serialization of what it received, so a
non-canonical form verifies only if the signature was made over the canonical
form. The signature is a raw Ed25519 signature over the UTF-8 bytes of the
base.

### Body

```json
{
  "value": "<base64url of a 32-byte SHA-256 digest, RFC 8555 section 8.4>",
  "addresses": ["<multiaddr or http(s) URL>", "..."]
}
```

The request MUST carry `Content-Type: application/json` (media-type parameters
such as `charset` are ignored). The body MUST be at most 8 KiB. The server MUST
reject unknown JSON fields and trailing data. `addresses` tells the forge where
to prove reachability (below).

### Success

`200` with:

```json
{
  "did": "did:key:z6Mk...",
  "name": "*.<peerid-b36>.libp2p.direct",
  "verification": {"mode": "http-ownership"},
  "ttl": 3600
}
```

## Proving reachability

A registration MUST prove control of at least one address in the body. Two
verification modes exist. A server MUST support at least one; it SHOULD support
http-ownership, the libp2p-free path, and it MAY support libp2p-dialback. An
implementation MAY omit the dialback entirely to avoid a dependency on the libp2p
stack.

A client that wants to stay off libp2p SHOULD provide at least one `http(s)`
address and serve the ownership proof. A client MAY provide libp2p multiaddrs,
but MUST NOT assume that a given server supports the dialback.

The forge tries the addresses in the body. It verifies an `http://` or
`https://` address with the ownership proof, and treats anything else as a
libp2p multiaddr to dial (where the dialback is supported). It tries the
ownership proof first, and falls back to the dialback if that is absent or
fails.

The forge bounds the work per registration: it considers at most the first 8
`http(s)` addresses and at most the first 32 multiaddrs (relay addresses are
skipped without counting), and ignores the rest. Clients SHOULD lead with the
addresses most likely to verify.

### http-ownership (no libp2p)

The node MUST serve, at the key-scoped path below, a compact EdDSA JWT
([RFC 7519](https://www.rfc-editor.org/rfc/rfc7519)) proving its key controls the
origin:

```
GET http(s)://<host>[:<port>]/.well-known/p2p-forge/<did:key>
```

The `p2p-forge` well-known path suffix may be registered in the IANA registry
([RFC 8615](https://www.rfc-editor.org/rfc/rfc8615)) in the future, if this
API sees enough adoption.

The response body is the JWT (`Content-Type: application/jwt`), signed with the
node's Ed25519 key. The node signs it once and reuses it until close to expiry,
so it is cacheable and can be signed offline. The JWT header MUST carry
`alg: EdDSA` and `typ: p2p-forge-ownership+jwt` (explicit typing per
[RFC 8725](https://www.rfc-editor.org/rfc/rfc8725), so no other JWT signed by
the same key can pass as an ownership proof). The payload carries these claims:

| Claim | Meaning |
| --- | --- |
| `origin` | The canonical `scheme://host:port` the key controls (below). |
| `iat` | Issued-at, unix seconds. |
| `exp` | Expiry, unix seconds. `exp - iat` MUST NOT exceed 14 days, with no extra allowance. |

The `origin` string is `scheme://host:port` built as follows:

1. `scheme` is lowercase, `http` or `https` only.
2. There is no userinfo, path, query, or fragment; a lone trailing `/` in the
   source URL is dropped.
3. `host` is lowercase. An IP-literal host is in its canonical textual form
   ([RFC 5952](https://www.rfc-editor.org/rfc/rfc5952) for IPv6), an
   IPv4-mapped IPv6 literal collapses to its IPv4 form, an IPv6 literal stays
   bracketed, and a zoned IPv6 literal (`fe80::1%eth0`) is rejected.
4. `port` is always explicit: `443` fills in for `https` and `80` for `http`
   when the URL has none.

For example `https://GW.Example` becomes `https://gw.example:443`, and
`http://[::ffff:1.2.3.4]` becomes `http://1.2.3.4:80`. This differs from the
serialization browsers use for the `Origin` header
([RFC 6454](https://www.rfc-editor.org/rfc/rfc6454) section 6.2), which omits
a default port; the always-explicit port keeps the comparison a single string
equality with no per-scheme table.

The forge MUST verify the JWT under the registration `keyid`, and MUST NOT trust
the key or `kid` the token itself carries. It MUST check that the `origin` claim
equals, as an exact string, the origin it connected to (scheme, host, and port
are all bound, so an `http` proof cannot satisfy an `https` address), and MUST
reject an expired token. The verifier allows 5 minutes of clock skew on `iat`
and `exp`, and a signer MAY backdate `iat` to tolerate a slow verifier clock;
the 14-day cap on `exp - iat` still applies as written. Freshness comes from
the forge fetching the proof live, so a stale proof at a dead node does not
verify.

What this proves: the key holder controls what is served at that origin right
now. It does not prove the node is dialable over libp2p (a CDN can serve the
static file while the node is down). For proven dialability, use a libp2p
address.

Notes for operators of the endpoint:

- The proof is offline-signable. The identity key does not have to be online in
  the HTTP tier. A static file server or a CDN can serve the token.
- The endpoint may answer on any port, so a node behind NAT can serve the
  proof on a port forwarded via UPnP or router config. The public IP is what
  is being proven and denylisted; the port does not matter, and the
  libp2p-dialback mode accepts arbitrary ports too.
- The forge MUST pin each connection to a vetted resolved public IP of the
  endpoint (it MAY try one address per family when the host resolves to both),
  MUST refuse a non-public target, and MUST NOT follow redirects. It does not
  require a CA-verified TLS certificate on this fetch: a node registers
  precisely because it has no publicly trusted cert yet, and the proof's
  authenticity comes from its signature plus the pinned IP, not from the
  transport.

### libp2p-dialback

Support for this mode is OPTIONAL. It exists so nodes that already speak libp2p
can register with no HTTP endpoint to serve, but a forge MAY implement only
http-ownership and skip the libp2p stack entirely.

For a libp2p multiaddr, the forge opens a libp2p connection to the peer and the
transport handshake authenticates the `<peerid>`. This works for QUIC-v1; TCP or
WS or WSS with Yamux and TLS or Noise; and WebTransport, plus the
[Identify protocol](https://github.com/libp2p/specs/tree/master/identify). A
forge that supports this mode MUST resolve and pin the address IPs, MUST refuse
non-public targets, and MUST bound the dial with a timeout.

## Errors

The server SHOULD return [problem+json (RFC 9457)](https://www.rfc-editor.org/rfc/rfc9457)
and MUST use a status consistent with the table below. Each error class carries
a stable fragment at the end of its `type` URI; a client that needs to tell
classes apart SHOULD match on that fragment.

| Status | `type` fragment | When |
| --- | --- | --- |
| `400` | `unexpected-query` | The request carries a query string. |
| `400` | `malformed-body` | The `Content-Type` is not `application/json`, the body is not the JSON object above, has unknown fields, or has trailing data. |
| `400` | `malformed-value` | `value` is not unpadded base64url of a 32-byte SHA-256 digest. |
| `400` | `malformed-signature` | The request does not conform to this profile: unparseable signature headers, a label other than `sig1`, covered components other than the exact list above, an unknown signature parameter, an `alg` other than `ed25519`, a bad `did:key`, a `nonce` that is not unpadded base64url of at least 128 bits, a missing `created` or `expires`, `expires - created` over 300 seconds, or a `Content-Digest` that is malformed or does not match the body. |
| `401` | `signature-invalid` | Signature verification failed, a required component is not covered, the clock window is violated, or `@authority` is not the registration domain. |
| `403` | `denylisted` | The client IP or a submitted address is denylisted. |
| `413` | `body-too-large` | The body exceeds 8 KiB. |
| `422` | `verification-failed` | No submitted address could be verified. |
| `500` | `misconfigured`, `storage-error` | Server-side failure; safe to retry later. |

A fronting proxy or implementation-specific access control may add statuses
outside this table, such as `429` when rate limited or `403` when access is
denied.

## Anti-abuse

- **Rate limiting** is the operator's responsibility on the fronting reverse
  proxy, CDN, or load balancer. The forge does not rate-limit requests itself.
- **Replay.** The server does not track nonces, so a captured request can be
  resubmitted until its `expires` passes. This is accepted: the signature
  binds the whole request, so a replay can only repeat it, re-verifying the
  same addresses and re-writing the same TXT value. The `nonce` keeps every
  signature unique, and a server MAY additionally reject reused nonces.
- **Denylist** applies to the client IP and to every resolved endpoint IP. The
  forge MUST NOT trust a leftmost `X-Forwarded-For` for the client IP, which any
  client can forge; it trusts only the direct connection address plus, when the
  operator configures one, a proxy header (see `client-ip-header`).

## Operator configuration

Two settings in the `acme` Corefile block affect `/v2` (see the README for the
full syntax):

- `allow-private-addresses=true` (an argument on the `registration-domain`
  line) turns off every reachability safeguard: destination-IP vetting, the
  address caps, the dialback IP pinning, and the verification timeouts. Off by
  default. Use it only for local testing or a private deployment that trusts
  the submitted addresses. Never enable it on a public instance.
- `client-ip-header <name>` names the header the fronting proxy sets with the
  real client IP (for example `CF-Connecting-IP` behind Cloudflare), used for
  the denylist. Without it, only the direct connection address is trusted.

## Adding a key type

`/v2` is Ed25519-only today (2026-Q3). The request profile is built to add key types
without a breaking change; the near-term driver is post-quantum signatures. See
[Adding a key type](key-types.md) for how a new type fits, the DNS-label size
limit, and the standards each candidate depends on.
