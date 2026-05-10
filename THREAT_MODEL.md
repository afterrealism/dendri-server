# THREAT_MODEL.md — Dendri Signaling Server

STRIDE per attack surface. Last reviewed: 2026-05-08.

## 1. WebSocket (`GET /{base}/dendri`)

| Threat | Severity | Mitigation |
|--------|----------|------------|
| Spoofing (peer identity) | High | `src` field overwritten server-side; JWT validation with HS256 when `jwt_secret` configured; constant-time key comparison via `subtle` |
| Tampering (message payload) | Medium | Rate limiter prevents flooding; message size cap (`max_message_size`); `is_valid_identifier` rejects malformed IDs |
| Repudiation | Low | All actions logged via `tracing`; webhook events for connect/disconnect/rate-limit |
| Information Disclosure | Medium | Room names redacted via `pii::redact_room()` unless `DENDRI_LOG_PII=true`; `strip_ice_candidates` hides client IPs |
| Denial of Service | High | Per-client rate limiting (signaling/data); `concurrent_limit` cap; bounded `replay_buffer`; bounded `webhook_queue` |
| Elevation of Privilege | High | JWT claims gating on room join (`rooms` claim); `discovery_token` for peer list; `key` + `key_file` auth |

## 2. HTTP REST APIs (`GET /:key/{id,peers,turn-credentials}`, `GET/POST /http/{sse,send,poll}`)

| Threat | Severity | Mitigation |
|--------|----------|------------|
| Spoofing | High | `DENDRI_KEY` authentication; token validation on reconnection; TURN credentials require key |
| Tampering | Medium | Input validation via `is_valid_identifier`; JSON parsing failure returns 400 |
| Information Disclosure | Medium | `--allow_discovery` default-off; `discovery_token` required when enabled; CORS default-deny |
| Denial of Service | High | Rate limiting applied to HTTP send handler; connection slot reservation prevents TOCTOU |
| Elevation of Privilege | Medium | SSE/polling clients use same auth as WebSocket; ID-taken check prevents hijack |

## 3. Webhooks (outbound POST)

| Threat | Severity | Mitigation |
|--------|----------|------------|
| SSRF | High | `is_safe_webhook_url` blocks loopback, link-local, RFC 1918, ULA, and metadata IPs |
| Tampering (in transit) | Medium | HMAC-SHA256 signing via `X-Dendri-Signature` header when `webhook_secret` configured |
| Information Disclosure | Medium | Payload contains only event type, peer IDs, room names — no message contents |
| Denial of Service | Low | Bounded queue (1024); 5s HTTP timeout; fire-and-forget with retry (1s/5s/25s backoff) |

## 4. TLS

| Threat | Severity | Mitigation |
|--------|----------|------------|
| Downgrade attack | Medium | HSTS header (`max-age=31536000; includeSubDomains`) when TLS enabled |
| Certificate expiry | Medium | SIGHUP reload via `RustlsConfig::reload_from_pem_file()` (zero-downtime rotation) |
| Weak ciphers | Low | rustls defaults (modern, safe ciphersuites); no legacy cipher config exposed |

## 5. Redis

| Threat | Severity | Mitigation |
|--------|----------|------------|
| Unauthorized access | High | Redis URL passed via env/CLI only; operator responsible for network ACL/firewall |
| Data loss | Medium | In-memory `DashMap` as hot-path cache; Redis as persistence layer; `sync_redis` background sync |
| Injection | Low | Redis commands use typed API (no string concatenation); peer IDs validated before storage |

## 6. TURN

| Threat | Severity | Mitigation |
|--------|----------|------------|
| Credential theft | Medium | Short-lived HMAC credentials (timestamp-based expiry); `turn_secret` never exposed in logs |
| Relay abuse | Low | TURN server configured separately (coturn); Dendri only issues credentials |

## 7. Supply Chain

| Threat | Severity | Mitigation |
|--------|----------|------------|
| Vulnerable dependency | Medium | `cargo audit` in CI; `cargo deny` for license compliance |
| Malicious dependency | Low | `Cargo.lock` committed; pinned base images in Dockerfile |
