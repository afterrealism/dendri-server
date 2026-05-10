# Third-Party Licenses — Dendri Server

Key production dependencies and their licenses (generated 2026-05-08).

| Crate | License | Notes |
|-------|---------|-------|
| axum | MIT | HTTP framework |
| axum-server | MIT | TLS support (rustls) |
| tokio | MIT | Async runtime |
| serde / serde_json | MIT / Apache-2.0 | Serialization |
| dashmap | MIT | Concurrent hash map |
| redis | BSD-3-Clause | Redis client |
| reqwest | MIT / Apache-2.0 | HTTP client (webhooks) |
| clap | MIT / Apache-2.0 | CLI parser |
| tracing | MIT | Structured logging |
| mimalloc | MIT | Allocator |
| governor | MIT | Rate limiting |
| jsonwebtoken | MIT | JWT validation |
| metrics / metrics-exporter-prometheus | MIT | Observability |
| hmac / sha2 / sha1 | MIT / Apache-2.0 | HMAC for TURN/webhook |
| subtle | BSD-3-Clause | Constant-time comparison |
| uuid | MIT / Apache-2.0 | Peer ID generation |
| futures | MIT / Apache-2.0 | Async utilities |

For the complete dependency tree with transitive licenses, run:
```bash
cargo install cargo-license
cargo license --direct-deps-only
```
