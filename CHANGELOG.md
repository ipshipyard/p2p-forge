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

### Fixed

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