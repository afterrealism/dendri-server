# dendri-server — Agent Guide

## What This Is

Rust Axum/Tokio **WebRTC signaling relay** — brokers SDP/ICE between peers, relays messages when P2P fails, handles room lifecycle, presence, RPC + ACK delivery, JWT auth, rate limiting, webhook callbacks. AGPL-3.0-only (see root AGENTS.md > Licensing Boundaries).

## Entry Point & Routing

**`src/main.rs`** wires Axum routes under a configurable `--base` path:

- `GET /health` — liveness probe
- `GET /{base}/` — server info
- `GET /{base}/:key/{id,peers,turn-credentials}` — realm-scoped HTTP helpers
- `GET /{base}/dendri` — WebSocket upgrade → `handlers::ws::ws_upgrade`
- `GET /{base}/http/{sse,poll}`, `POST /{base}/http/send` — HTTP transport fallbacks

**Background tasks** (tokio::spawn):
- `services::check_broken` — detect stale peers, clean rooms
- `services::messages_expire` — bounded replay buffer eviction
- `services::replay_evict` — GC old replayed messages
- `services::sync_redis` — multi-instance state sync (if Redis is configured)

## Module Map

```
src/
├── config              # clap CLI config, env vars
├── enums               # MessageType (serde hyphenated wire form: "peer-list", "host-changed")
├── handlers/
│   ├── http.rs (420)   # SSE + long-poll + send; watchdog cleanup at L117-140; polling Arc<Mutex> at L254-279
│   ├── message.rs (534)# frame dispatch core
│   └── ws.rs (555)     # WebSocket upgrade + per-connection loop
├── models              # wire types (Envelope, SDP, ICE, RPC, etc.)
├── rate_limiter        # per-key rate limiting (token bucket or similar)
├── redis_realm         # Redis-backed shared state (replicas, messages, rooms)
├── replay_buffer       # bounded in-process message replay store; MAX_BATCH=500
├── services/           # check_broken, messages_expire, replay_evict, sync_redis
├── state               # AppState + DI; atomic SeqCst slot reservation for peer IDs
├── validation          # input validation (sanitize room keys, peer IDs, etc.)
├── webhook             # outbound webhook POST; constant-time secret cmp via `subtle`
└── main.rs             # Axum + wiring
```

**Hotspots** to know before editing: `handlers/ws.rs` (555 LOC) is the per-connection state machine; `handlers/message.rs` (534) is the frame router both transports share; `handlers/http.rs` (420) hosts the fallback SSE/poll/send trio.

## Adding a New Handler

1. **Create handler function** in `handlers/` (HTTP or WS dispatch)
2. **Register route** in `main.rs` under the appropriate transport (WebSocket vs HTTP)
3. **Share state** through `state::AppState` (liveness, rooms, peers, Redis connection)
4. **Validate input** in `validation::*` before processing
5. **Return wire model** (from `models/`) or error

**Key constraint:** Handler must not hold AppState lock across async boundaries. Clone what you need, drop the lock.

## State Management

- **In-process state:** DashMap for per-instance state (active rooms, peer connections)
- **Cross-instance state:** `redis_realm` for replicas (ensure multi-instance deploys see consistent data)
- **Don't mix:** In-process DashMap is fast but single-replica only. Use Redis for multi-instance.

## Testing & QA

Cargo commands listed in root `AGENTS.md > Commands by Directory > dendri-server/`. Local-only flags worth knowing: `cargo test -- --nocapture` shows println/tracing; `cargo audit` is the CVE gate before release.

## Config

- **CLI flags:** `--help` lists all options (base path, TLS, Redis, debug logging)
- **Debug mode:** `DENDRI_DEBUG=1 cargo run` → sets `RUST_LOG=dendri=debug,tower_http=debug`
- **TLS:** Pass `--sslkey` + `--sslcert` together to enable rustls; otherwise plain Axum
- **Redis:** Optional; if present, syncs state across replicas

## Red Flags

1. **Holding AppState lock in async functions** — clone, drop, await
2. **Mixing in-process DashMap with multi-instance deploy** — use Redis
3. **Non-deterministic message ordering** — use sequence numbers or timestamps
4. **Webhook delivery without timeout/retry** — implement exponential backoff + deadletter
5. **Unvalidated user input in logs or errors** — sanitize PII before emitting
