# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Legend

- 🛠 - BREAKING CHANGE
- ✨ - Noteworthy change

## [Unreleased]

### Added
- ✨ New `/v2` registration API that authenticates with [HTTP Message Signatures (RFC 9421)](https://www.rfc-editor.org/rfc/rfc9421) plus [Digest Fields (RFC 9530)](https://www.rfc-editor.org/rfc/rfc9530) over an Ed25519 `did:key`, so a client can register without a libp2p HTTP stack. A node proves it controls a real endpoint by serving a signed proof at `/.well-known/autotls/<did:key>`, no libp2p needed. The `/v1` PeerID-auth API is unchanged and runs alongside it. See [docs/registration-v2.md](docs/registration-v2.md).
- New `acme` config: `allow-private-addresses=true` (an argument on the `registration-domain` line that turns off every reachability safeguard for local testing or trusted private deployments, default false) and the `client-ip-header` directive (names the trusted proxy header for the real client IP, e.g. `CF-Connecting-IP`; `X-Forwarded-For` is refused).

### Changed
- The reachability dialback now refuses to dial non-public destinations (loopback, RFC1918, CGNAT, link-local, cloud-metadata, and IPv4-embedding IPv6 ranges), pins resolved IPs against DNS rebinding, caps the address count, and bounds the dial with a timeout. Set `allow-private-addresses true` to restore the previous behavior for local testing.

### Fixed
- `X-Forwarded-For` is no longer trusted for the client IP used by the denylist. Only the direct connection address, plus a header named via `client-ip-header`, is trusted, so a client can no longer forge its way around an IP denylist entry.

## [v0.10.1] - 2026-07-29

### Fixed
- ✨ A node that comes back online after its certificate expired now gets a fresh certificate instead of staying stuck without one. Renewing an expired certificate cannot succeed: the renewal order references it through the ACME ARI `replaces` field, and the CA rejects orders that reference a certificate it no longer considers current (Let's Encrypt returns HTTP 404 `urn:ietf:params:acme:error:malformed`), which certmagic retried forever. On startup the client now discards an expired certificate found in local storage and requests a new one from scratch, without the `replaces` field.[^ari-replaces]

[^ari-replaces]: [RFC 9773, section 5](https://www.rfc-editor.org/rfc/rfc9773.html#section-5): servers SHOULD validate the certificate referenced by `replaces` and SHOULD reject the newOrder request when those checks fail.

## [v0.10.0] - 2026-07-17

### Added
- ✨ First-time certificate setup now confirms the registration broker is healthy (HTTP 204 from `/v1/health`) before starting ACME issuance. While the broker keeps failing the check, the client logs a single ERROR and re-checks hourly instead of running doomed ACME flows that certmagic would retry with backoff for weeks; issuance starts automatically once the broker recovers. Nodes with a certificate already in storage are unaffected. The re-check interval respects a `Retry-After` header sent by the broker when it is longer than the hourly default, capped at 24h. The probe is exposed as `client.CheckBrokerHealth` together with the `client.HealthCheckPath` constant; see [ipfs/kubo#11397](https://github.com/ipfs/kubo/pull/11397) for an example of wiring this in a downstream node. ([#91](https://github.com/ipshipyard/p2p-forge/pull/91))

## [v0.9.1] - 2026-06-22

### Fixed
- ✨ Fixed AutoTLS registration failing with a `401` when the forge endpoint is load-balanced (such as `registration.libp2p.direct`). The DNS-01 PeerID-auth handshake makes two requests, and without a session-affinity cookie the second can reach a different backend than the first, which never issued the challenge and rejects the request with an additional `401`. `client.SendChallenge` now adds a cookie jar when the supplied `*http.Client` lacks one, so the affinity cookie pins both requests to the same backend. A jar you set via `WithHTTPClient` or `WithChallengeHTTPClient` stays in place. ([#90](https://github.com/ipshipyard/p2p-forge/pull/90))

## [v0.9.0] - 2026-05-27

### Changed
- Bumped direct dependencies. `certmagic` v0.21.6 → v0.25.3 hardens OCSP delegated-responder validation, and `coredns` v1.14.2 → v1.14.3 builds against Go 1.26.2 to sweep in stdlib CVE fixes. `fsnotify` v1.9.0 → v1.10.1 fixes the inotify sibling-path watch removal that affected the `denylist` plugin. Also bumped `acmez/v3` v3.0.0 → v3.1.6, `pebble/v2` v2.7.0 → v2.10.1, `bart` v0.26.0 → v0.28.0, `go-datastore` v0.8.2 → v0.9.1, `go-multiaddr` v0.16.0 → v0.16.1, `go-multiaddr-dns` v0.4.1 → v0.5.0, `go-multibase` v0.2.0 → v0.3.0, and `slok/go-http-metrics` v0.12.0 → v0.13.0, plus patch bumps for `go-log/v2`, `prometheus/client_golang`, and `zap`. The pebble bump required passing `keyAlg="rsa"` to `pebbleCA.New`, `caaIdentities=nil` to `pebbleWFE.New`, and pointing pebble VA's DNS queries at CoreDNS's TCP listener, since pebble v2.10 forces TCP for ACME DNS lookups.
- 🛠 Bumped the optional DynamoDB datastore (`database-type dynamo`) to `go-ds-dynamodb` v0.3.0. The release switches to the current AWS SDK for Go and fixes several crashes and deadlocks. Operators should confirm their AWS credentials still work; `AWS_REGION`, `AWS_ACCESS_KEY_ID`, and `AWS_SECRET_ACCESS_KEY` still apply. See the [go-ds-dynamodb v0.3.0 release notes](https://github.com/ipfs/go-ds-dynamodb/releases/tag/v0.3.0) for details.

### Fixed
- `denylist` plugin leaked the previous instance's feed tickers and fsnotify watcher on every Caddy reload. Cleanup now runs on `OnShutdown` instead of `OnFinalShutdown`, so reloads release these resources.

## [v0.8.1] - 2026-05-16

### Added
- ✨ `client.WithHTTPClient(*http.Client)` option on `P2PForgeCertMgr` and a matching `client.WithChallengeHTTPClient(*http.Client)` option for `client.SendChallenge`. Lets callers supply a custom `*http.Client` (with a custom `Transport`, resolver, or root CAs) for the DNS-01 challenge POST to the forge registration endpoint. Useful for test harnesses that run an in-process forge on a loopback address while the PeerID-auth signature must stay scoped to the production registration hostname. `client.SendChallenge` gains a trailing variadic `opts ...SendChallengeOption` parameter; existing positional-only callers compile unchanged. ([#87](https://github.com/ipshipyard/p2p-forge/pull/87))

## [v0.8.0] - 2026-04-14

### Changed
- Bumped `google.golang.org/grpc` to v1.79.3, clearing CVE-2026-33186 from SBOM scanners (not exploitable in p2p-forge at runtime; no gRPC listener is exposed)
- Bumped `go-libp2p` to v0.48.0 and `coredns` to v1.14.2 to match the new `quic-go` v0.59.0 that ships with go-libp2p
- Bumped `go-ds-dynamodb` to v0.2.2 and `go-log` to v2.9.1
- Pinned `coredns/caddy` to the tagged v1.1.4 release in place of the pre-release master snapshot inherited from coredns
- Wired the go-log slog bridge in `main.go`, required by go-log v2.9 and go-libp2p v0.45+, so libp2p subsystem logs flow through go-log and respond to `golog.SetLogLevel`

## [v0.7.0] - 2025-12-04

### Added
- 🛠 IP denylist plugin (`denylist`) supporting local files with fsnotify auto-reload and HTTP feeds (e.g. Spamhaus DROP, URLhaus) with periodic refresh. Integrates with the `ipparser` (DNS) and `acme` (HTTP) plugins: denied IPs get NODATA on DNS and HTTP 403 on ACME requests. Allowlists are checked first and bypass denylists. Prometheus metrics expose blocked request counts, list sizes, and refresh status.

### Changed
- 🛠 Bumped go.mod to Go 1.24
- Hardened `ipparser`: extracted IP parsing into `parseIPFromPrefix()` with query-type validation, removed dead `ANY` query handling (now returned as HINFO via the `any` plugin per RFC 8482), and isolated tests to stop flakiness

### Fixed
- Metrics registry race conditions
- Datastore not closed on shutdown, leaking file handles on Windows

## [v0.6.1] - 2025-07-30

### Fixed
- Fixed addrs factory skipping logic in client/acme.go
- Added test coverage for addr skipping in client/acme_test.go

## [v0.6.0] - 2024-XX-XX

### Changed
- Updated go-libp2p to v0.42

### Fixed
- Use autonatv2 event to begin cert management

## [v0.5.1] - 2024-XX-XX

### Fixed
- Filter out public /p2p-circuit addrs in client

## [v0.5.0] - 2024-XX-XX

### Changed
- Updated go-libp2p to v0.41.1