# Dendri Signaling Server

[![License: AGPL-3.0](https://img.shields.io/badge/license-AGPL--3.0--only-blue.svg)](LICENSE)

Rust (Axum/Tokio) signaling server for WebRTC peer-to-peer collaboration with **4-tier connectivity fallback**: direct P2P → STUN → TURN → TLS relay through the signaling server itself.

Part of the [Dendri](https://dendri.dev) ecosystem. Client SDK: [`@afterrealism/dendri-client`](https://github.com/afterrealism/dendri-client).

## Quick Start

```bash
# Build
cargo build --release

# Run (local development)
cargo run -- --host 127.0.0.1 --port 9876 --enable_relay --allow_discovery

# Run with TLS
cargo run -- --host 0.0.0.0 --port 443 \
  --sslkey /path/to/key.pem --sslcert /path/to/cert.pem \
  --enable_relay --allow_discovery
```

The server requires **Redis** running at `redis://127.0.0.1:6379` by default. Override with `--redis-url`.

## Docker / Podman

```bash
# Using the Quadlet stack from dendri-infrastructure
# See: https://github.com/afterrealism/dendri-infrastructure

# Or run directly:
podman run -d --name dendri \
  -p 9876:9876 \
  -e REDIS_URL=redis://redis:6379 \
  ghcr.io/afterrealism/dendri-server:latest \
  --host 0.0.0.0 --port 9876 --enable_relay
```

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Liveness probe |
| `GET` | `/metrics` | Prometheus metrics |
| `GET` | `/{base}/` | Server info |
| `GET` | `/{base}/:key/id` | Generate a peer ID for the given room key |
| `GET` | `/{base}/:key/peers` | List peers in a room (requires `--allow_discovery`) |
| `GET` | `/{base}/:key/turn-credentials` | Ephemeral TURN credentials (requires `--turn-secret`) |
| `GET` | `/{base}/dendri` | WebSocket upgrade — primary signaling transport |
| `GET` | `/{base}/http/sse` | Server-Sent Events fallback transport |
| `POST` | `/{base}/http/send` | HTTP send fallback transport |
| `GET` | `/{base}/http/poll` | HTTP long-poll fallback transport |

`{base}` defaults to `/` and is configurable with `--path`.

## Configuration

All flags can also be set via environment variables (shown in parentheses below).

| Flag | Env | Default | Description |
|------|-----|---------|-------------|
| `--port` | `PORT` | `9000` | Listen port |
| `--host` | — | `::` | Bind address |
| `--key` | `DENDRI_KEY` | `dendri` | Connection key |
| `--key-file` | `DENDRI_KEY_FILE` | — | Path to file containing the connection key |
| `--path` | `PEERSERVER_PATH` | `/` | URL path prefix |
| `--concurrent-limit` | — | `10000` | Max simultaneous clients |
| `--alive-timeout` | — | `60000` | Heartbeat timeout (ms) |
| `--idle-timeout` | — | `900000` | Idle eviction timeout (ms, 0 = disabled) |
| `--expire-timeout` | — | `5000` | Message queue expiration (ms) |
| `--allow-discovery` | `DENDRI_ALLOW_DISCOVERY` | `false` | Enable `GET /:key/peers` |
| `--discovery-token` | `DENDRI_DISCOVERY_TOKEN` | — | Token required for peer discovery |
| `--enable-relay` | `DENDRI_ENABLE_RELAY` | `false` | Enable WebSocket relay (tier 4) |
| `--sslkey` | — | — | Path to TLS private key |
| `--sslcert` | — | — | Path to TLS certificate |
| `--cors` | — | — | CORS origins (repeat for multiple) |
| `--turn-secret` | `TURN_SECRET` | — | HMAC secret for TURN credentials |
| `--turn-servers` | — | — | TURN server URLs |
| `--jwt-secret` | `DENDRI_JWT_SECRET` | — | JWT validation secret |
| `--webhook-url` | `DENDRI_WEBHOOK_URL` | — | Webhook notification URL |
| `--webhook-secret` | `DENDRI_WEBHOOK_SECRET` | — | Webhook HMAC-SHA256 secret |
| `--redis-url` | `REDIS_URL` | `redis://127.0.0.1:6379` | Redis connection URL |
| `--max-room-size` | — | `50` | Max clients per room (0 = unlimited) |
| `--max-message-size` | — | `65536` | Max payload size (bytes) |
| `--session-ttl` | `DENDRI_SESSION_TTL` | `30000` | Grace period before removing disconnected clients (ms) |
| `--telemetry-enabled` | `DENDRI_TELEMETRY` | `false` | Opt-in anonymised telemetry |

## Architecture

```
Browser A ──WebSocket──┐
                       ├──► Dendri Server ──► Redis (shared state)
Browser B ──HTTP/SSE───┘         │
                                 ├── Tier 1-3: ICE candidate brokering
                                 └── Tier 4:   TLS relay (ciphertext only)
```

The 4-tier fallback model:

1. **P2P** — direct connection (same LAN / public IP)
2. **STUN** — server-reflexive candidates through NAT
3. **TURN** — UDP/TCP relay via coturn
4. **TLS relay** — through the signaling server itself (when all else fails)

Tier 4 reuses the already-reachable TLS connection. DTLS end-to-end confidentiality is preserved — the relay sees only ciphertext.

## Development

```bash
cargo build
cargo test
cargo clippy -- -D warnings
cargo fmt
DENDRI_DEBUG=1 cargo run -- --help
```

## License

AGPL-3.0-only. See [LICENSE](LICENSE).

The client SDK (`@afterrealism/dendri-client`) is Apache-2.0 licensed separately.
