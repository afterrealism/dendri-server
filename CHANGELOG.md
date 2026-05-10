# Changelog — Dendri Server

All notable changes to the Dendri signaling server. This project adheres to [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
- `--key-file` flag (`DENDRI_KEY_FILE` env) for reading shared secret from file
- `--discovery-token` flag (`DENDRI_DISCOVERY_TOKEN` env) for `/peers` endpoint auth
- `--jwt-secret` flag (`DENDRI_JWT_SECRET` env) for HS256 JWT authentication
- JWT-based room access control via `rooms` claim
- `pii::redact_room()` — room name redaction by default (`DENDRI_LOG_PII=true` to disable)
- Prometheus `/metrics` endpoint with `dendri_connections_total` and `dendri_messages_total` counters
- HSTS header (`Strict-Transport-Security`) when TLS is enabled
- SIGHUP TLS certificate reload (zero-downtime rotation via `RustlsConfig::reload_from_pem_file`)
- ROOM-JOIN-DENIED message type with `reason` field (`auth_denied`, `room_full`)
- REPLAY-INCOMPLETE message type for buffer gap detection
- Webhook retry with exponential backoff (1s, 5s, 25s, max 3 attempts)
- Structured panic handler emitting tracing on background task panics
- Graceful WebSocket drain on shutdown (CLOSE 4001, 30s timeout)
- `max_room_size` config (0 = unlimited)

### Changed
- CORS default: deny all (was permissive). Requires explicit `--cors` for cross-origin.
- Rate limiter backed by `governor` crate (GCRA algorithm) instead of hand-rolled token bucket
- `serialize_relay` replaced with `serde_json::to_string` (removed `itoa` dependency)
- TURN credentials include peer ID in username for per-client tracking
- `ROOM-JOIN-DENIED` replaces generic ERROR for auth and capacity denials
- `REPLAY-INCOMPLETE` replaces ERROR/REPLAY_GAP for buffer gap messages
- Dockerfile: 3-stage `cargo-chef` build, non-root user (UID 1001), pinned base images

### Fixed
- DashMap lock held across async in `sync_redis` — keys collected before iteration
- SSRF webhook protection: added IPv6 private ranges + full RFC 1918 block
- Identical branches collapsed in `handle_transmission`
- Dead `or_else(|| None)` removed from `ws.rs`

### Security
- SPDX license headers (AGPL-3.0-only) on all source files
- AGPL §13 compliance: `GET /` returns license + source URL
- THREAT_MODEL.md added (STRIDE per attack surface)

## [0.1.0] — Initial Release
- Axum/Tokio signaling server with Redis-backed shared state
- WebSocket, HTTP/SSE, and long-poll transport support
- Message relay with replay buffer for reconnection
- JWT authentication support
- Webhook event delivery (peer connected/disconnected, rate limited)
- Per-client rate limiting
- TURN credential issuance
