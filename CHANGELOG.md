# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Legend

- 🛠 - BREAKING CHANGE
- ✨ - Noteworthy change

## [Unreleased]

### Added

### Changed
- Bumped direct dependencies: `certmagic` v0.21.6 → v0.25.3 (OCSP delegated-responder validation hardening), `coredns` v1.14.2 → v1.14.3 (built against Go 1.26.2, sweeping in stdlib CVE fixes), `acmez/v3` v3.0.0 → v3.1.6, `pebble/v2` v2.7.0 → v2.10.1, `fsnotify` v1.9.0 → v1.10.1 (fixes inotify sibling-path watch removal that affected the `denylist` plugin), `bart` v0.26.0 → v0.27.1, `go-datastore` v0.8.2 → v0.9.1, `go-multiaddr` v0.16.0 → v0.16.1, `go-multiaddr-dns` v0.4.1 → v0.5.0, `go-multibase` v0.2.0 → v0.3.0, `slok/go-http-metrics` v0.12.0 → v0.13.0, plus patch bumps for `go-log/v2`, `prometheus/client_golang`, and `zap`. The pebble update required passing `keyAlg="rsa"` to `pebbleCA.New`, `caaIdentities=nil` to `pebbleWFE.New`, and routing pebble VA's DNS queries to CoreDNS's TCP listener (pebble v2.10 forces TCP for ACME DNS lookups).
- 🛠 Migrated the `acme` plugin's optional DynamoDB datastore from `aws-sdk-go` (v1, end-of-support as of v1.55.8) to `aws-sdk-go-v2`. The client is now built with `dynamodb.NewFromConfig(config.LoadDefaultConfig(...))` instead of the v1 session API. Operators configuring `database-type dynamo` should make sure their AWS credentials chain still resolves under v2 (env vars, shared config, IAM role, etc.; the same `AWS_REGION` / `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` env vars are still honored). Depends on [ipfs/go-ds-dynamodb#22](https://github.com/ipfs/go-ds-dynamodb/pull/22); pinned to that PR's head pending the v0.3.0 release.

### Fixed

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