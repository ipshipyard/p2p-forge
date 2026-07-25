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
   HTTP origin by serving a signed proof the forge fetches (below). This is
   anti-abuse: it keeps the forge from minting certs for keys that run nothing.
   It does not scope the cert.

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
| `tag` | `autotls-reg`. |

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
"@signature-params": ("@method" "@authority" "@path" "content-type" "content-digest");created=1700000000;expires=1700000060;nonce="dGVzdG5vbmNlMTIzNDU2Nw";keyid="did:key:z6Mk...";tag="autotls-reg"
```

The `Signature-Input` and `Signature` headers MUST each appear exactly once and
carry exactly one signature, labeled `sig1`; the server rejects any other label
and any additional signature:

```
Signature-Input: sig1=("@method" "@authority" "@path" "content-type" "content-digest");created=1700000000;expires=1700000060;nonce="dGVzdG5vbmNlMTIzNDU2Nw";keyid="did:key:z6Mk...";tag="autotls-reg"
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
  "origins": ["<http(s) origin>", "..."]
}
```

The request MUST carry `Content-Type: application/json` (media-type parameters
such as `charset` are ignored). The body MUST be at most 8 KiB. The server MUST
reject unknown JSON fields and trailing data. `origins` lists the public
`http(s)` origins where the node serves its ownership proof (below).

### Success

`200` with a body that is informational: a client needs none of it to proceed.

```json
{
  "did": "did:key:z6Mk...",
  "name": "*.<peerid-b36>.libp2p.direct",
  "challenge": "HTTP-BROKERED-DNS-01",
  "expiresIn": 3600
}
```

| Field | Meaning |
| --- | --- |
| `did` | The `did:key` that registered, echoed back. |
| `name` | The wildcard cert name the peer can now get. |
| `challenge` | The challenge that passed. Always `HTTP-BROKERED-DNS-01` today. |
| `expiresIn` | Seconds from now until the forge expires the stored challenge value. This is not the DNS TTL of the TXT record. This is how long we serve the value. |

## Proving reachability

A registration MUST prove control of at least one `origin` in the body. `/v2` is
pure HTTP: the forge proves it by fetching a signed proof over HTTP, with no
libp2p. A node that speaks only libp2p uses `/v1` instead, whose dialback
authenticates the peer over a libp2p connection.

The forge tries the submitted origins in order and stops at the first that
proves ownership. It considers at most the first 4 and ignores the rest, so
clients SHOULD lead with the origin most likely to verify. One origin is
typical; a node may list more, for example a separate IPv4 and IPv6 hostname.

### HTTP-BROKERED-DNS-01

This challenge is analogous to ACME's
[`HTTP-01`](https://letsencrypt.org/docs/challenge-types/#http-01-challenge):
the verifier fetches a key-bound artifact from a well-known HTTP path. It is
"brokered" because the forge, not the CA, performs it, then translates a
successful check into the `DNS-01` record it publishes for the node. That
indirection is the point: a NATed libp2p node cannot run `HTTP-01` or `DNS-01`
for a `libp2p.direct` name itself.

The node serves an ownership proof at the key-scoped path below. The forge
fetches it with a `POST` and the node answers with an RFC 9421-signed response,
reusing the same signature scheme as the registration request. `POST` (not
`GET`) keeps the response uncacheable, so every check gets a fresh signature.

```
POST http(s)://<host>[:<port>]/.well-known/autotls/<did:key>
```

The `autotls` well-known path suffix may be registered in the IANA registry
([RFC 8615](https://www.rfc-editor.org/rfc/rfc8615)) in the future, if this
API sees enough adoption.

The node MUST answer `200`, with the origin it controls as the response body,
and sign the response with its Ed25519 key. The signature MUST cover exactly:

```
("@status" "content-digest")
```

with signature parameters `created`, `expires` (`expires - created` bounds the
proof lifetime), `keyid` (the node's `did:key`), and `tag` set to
`autotls-ownership`. As on the request, `Content-Digest` (RFC 9530) over the
body is covered by the signature, so signing the response signs the origin too.

The body is the origin
([RFC 6454](https://www.rfc-editor.org/rfc/rfc6454) section 6.2): a
`scheme://host` string (`http` or `https`, lowercase host), with the port only
when it is not the scheme default (`443` for `https`, `80` for `http`), and no
userinfo, path, query, or fragment. For example `https://GW.Example` is
`https://gw.example`, `https://gw.example:8443` keeps its port, and an IPv6
literal is bracketed (`https://[2001:db8::1]`).

The forge MUST verify the response signature under the registration `keyid`,
and MUST NOT trust the `keyid` the proof itself carries. It MUST confirm the
`Content-Digest` matches the body, check that the body equals, as an exact
string, the origin of the server it connected to (scheme, host, and port are
all bound, so an `http` proof cannot satisfy an `https` server), and reject a
proof whose `expires` has passed. Freshness comes from the forge fetching the
proof live over `POST`, so a stale proof at a dead node does not verify.

What this proves: the key holder controls what is served at that server right
now. It does not prove the node is dialable over libp2p. For proven
dialability, use `/v1`.

Notes for operators of the endpoint:

- The proof is signed live per request, so the identity key is used in the HTTP
  tier. This library ships a ready handler (see the client docs) that produces
  the signed response.
- The endpoint may answer on any port, so a node behind NAT can serve the
  proof on a port forwarded via UPnP or router config. The public IP is what
  is being proven and denylisted; the port does not matter.
- The forge MUST pin each connection to a vetted resolved public IP of the
  endpoint (it MAY try one address per family when the host resolves to both),
  MUST refuse a non-public target, and MUST NOT follow redirects. It does not
  require a CA-verified TLS certificate on this fetch: a node registers
  precisely because it has no publicly trusted cert yet, and the proof's
  authenticity comes from its signature plus the pinned IP, not from the
  transport.

## Errors

The server SHOULD return [problem+json (RFC 9457)](https://www.rfc-editor.org/rfc/rfc9457)
and MUST use a status consistent with the table below. Each error class has a
stable `type` URI ending in the fragment shown, which anchors to that row. A
client that needs to tell classes apart SHOULD match on the whole `type` URI
(the fragment alone is enough in practice).

| Status | `type` fragment | When |
| --- | --- | --- |
| `400` | `unexpected-query`<a id="unexpected-query"></a> | The request carries a query string. |
| `400` | `malformed-body`<a id="malformed-body"></a> | The `Content-Type` is not `application/json`, the body is not the JSON object above, has unknown fields, or has trailing data. |
| `400` | `malformed-value`<a id="malformed-value"></a> | `value` is not unpadded base64url of a 32-byte SHA-256 digest. |
| `400` | `malformed-signature`<a id="malformed-signature"></a> | The request does not conform to this profile: unparseable signature headers, a label other than `sig1`, covered components other than the exact list above, an unknown signature parameter, an `alg` other than `ed25519`, a bad `did:key`, a `nonce` that is not unpadded base64url of at least 128 bits, a missing `created` or `expires`, `expires - created` over 300 seconds, or a `Content-Digest` that is malformed or does not match the body. |
| `401` | `signature-invalid`<a id="signature-invalid"></a> | Signature verification failed, a required component is not covered, the clock window is violated, or `@authority` is not the registration domain. |
| `403` | `denylisted`<a id="denylisted"></a> | The client IP or a submitted origin's IP is denylisted. |
| `413` | `body-too-large`<a id="body-too-large"></a> | The body exceeds 8 KiB. |
| `422` | `verification-failed`<a id="verification-failed"></a> | No submitted origin could be verified. |
| `500` | `misconfigured`<a id="misconfigured"></a>, `storage-error`<a id="storage-error"></a> | Server-side failure; safe to retry later. |

A fronting proxy or implementation-specific access control may add statuses
outside this table, such as `429` when rate limited or `403` when access is
denied.

## Anti-abuse

- **Rate limiting** is the operator's responsibility on the fronting reverse
  proxy, CDN, or load balancer. The forge does not rate-limit requests itself.
- **Replay.** The server does not track nonces, so a captured request can be
  resubmitted until its `expires` passes. This is accepted: the signature
  binds the whole request, so a replay can only repeat it, re-verifying the
  same origins and re-writing the same TXT value. The `nonce` keeps every
  signature unique, and a server MAY additionally reject reused nonces.
- **Denylist** applies to the client IP and to every resolved origin IP. The
  forge MUST NOT trust a leftmost `X-Forwarded-For` for the client IP, which any
  client can forge; it trusts only the direct connection address plus, when the
  operator configures one, a proxy header (see `client-ip-header`).

## Operator configuration

Two settings in the `acme` Corefile block affect `/v2` (see the README for the
full syntax):

- `allow-private-addresses=true` (an argument on the `registration-domain`
  line) turns off every reachability safeguard: destination-IP vetting, the
  origin cap, and the fetch timeouts. Off by default. Use it only for local
  testing or a private deployment that trusts the submitted origins. Never
  enable it on a public instance.
- `client-ip-header <name>` names the header the fronting proxy sets with the
  real client IP (for example `CF-Connecting-IP` behind Cloudflare), used for
  the denylist. The value may be a bare IP or `ip:port`. It MUST be a
  single-value header the proxy controls; `X-Forwarded-For` is refused at
  startup, because a client can prepend to it and dodge the denylist. Without
  this option, only the direct connection address is trusted.

## Adding a key type

`/v2` is Ed25519-only today (2026-Q3). The request profile is built to add key types
without a breaking change; the near-term driver is post-quantum signatures. See
[Adding a key type](key-types.md) for how a new type fits, the DNS-label size
limit, and the standards each candidate depends on.
