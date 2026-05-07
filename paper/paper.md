---
title: 'Dendri: A 4-tier WebRTC Connectivity-Fallback Architecture for Self-Hosted Collaborative Research on Restricted Networks'
tags:
  - rust
  - typescript
  - webrtc
  - ice
  - nat-traversal
  - tls-relay
  - real-time-collaboration
  - crdt
  - signaling
  - self-hosted
authors:
  - name: Sheece Gardezi
    orcid: 0009-0000-6983-444X
    affiliation: 1
affiliations:
  - name: Afterrealism Pty Ltd, Canberra, Australia
    index: 1
date: 15 June 2026
bibliography: paper.bib
---

# Summary

Dendri is a self-hosted WebRTC signaling stack that introduces a novel
4-tier connectivity fallback (P2P → STUN → TURN → TLS relay through
the signaling server itself). Standard Web Real-Time Communication
(WebRTC) relies on the Interactive Connectivity Establishment (ICE)
framework [@rfc8445], which assumes either UDP egress or a reachable
TURN server [@rfc8656]. On many enterprise, government, and
defence-adjacent research networks, neither condition holds: outbound
UDP is filtered, public TURN endpoints are blocked, and TURN
credentials cannot be provisioned per-session.

Dendri's tier 4 reuses the signaling server — already reachable over
TLS, since WebRTC negotiation requires it — as an encrypted last-resort
relay. DTLS end-to-end confidentiality is preserved across the relay:
the server sees only ciphertext. Tier transitions are graceful, with
application-layer session state (presence, host migration, RPC
acknowledgements) surviving the renegotiation. The server is written
in Rust (Axum/Tokio, mimalloc), supports Redis-backed shared state
for multi-instance deployments, and ships with a framework-neutral
TypeScript client SDK and a Yjs CRDT bridge [@nicolaescu2015yjs].

# Statement of Need

Connectivity is the hardest unsolved problem for real-time
collaboration on restricted research networks. The Interactive
Connectivity Establishment framework [@rfc8445] defines a three-tier
model (direct P2P → STUN-assisted → TURN relay), but this model
breaks in environments common to Australian government, CSIRO, and
defence-adjacent research:

1. **Outbound UDP is often blocked entirely.** Many enterprise
   firewalls filter all UDP traffic as a security baseline, and
   carrier-grade NAT in mobile and remote settings adds further
   obstruction [@reddy2015webrtc-udp].

2. **TURN servers are themselves blocked.** Coturn and other open
   TURN instances are categorically filtered by the same egress
   policies that block UDP. Per-session TURN credential provisioning
   is operationally infeasible in locked-down environments
   [@ietf-webrtc-firewall].

3. **Existing solutions fall short.** Hosted realtime backends
   (Liveblocks, PartyKit, Pusher, Ably, Supabase Realtime) require
   data to traverse vendor-controlled infrastructure — incompatible
   with sovereignty and jurisdiction constraints. Self-hosted
   alternatives are fragmented: Matrix is message-oriented and heavy;
   Jitsi targets media only; y-webrtc [@nicolaescu2015yjs] lacks a
   hardened server with authentication, host migration, and webhook
   support; PeerJS and simple-peer ship hosted signaling defaults and
   provide no relay fallback.

Dendri is the first open-source stack to integrate all four
connectivity tiers with a production-grade signaling server in a
self-host-first deployment model. The closest prior academic work is
a WebRTC gateway tunneling system for restricted hospital networks
[@arowolo2013tunneling], which uses a separate gateway service (not
the signaling server itself) and does not preserve end-to-end DTLS
confidentiality across the relay. Snowflake [@bocovich2024snowflake]
demonstrates WebRTC-based connectivity at global scale through
censored networks, but is purpose-built for circumvention, not
general-purpose collaboration.

The research applicability is direct: collaborative geospatial
labeling, CRDT-backed annotation across air-gapped sites, and
multi-institution data collection on networks where hosted SaaS is
impermissible. Dendri enables these workflows with no external
infrastructure dependency beyond a TLS-reachable server.

# Implementation

Dendri is implemented as two complementary components:

**Signaling server** — Rust (Axum/Tokio, mimalloc allocator), licensed
under AGPL-3.0-only. Transport-agnostic message routing via a unified
`WsSender` channel shared by WebSocket, SSE, and long-polling clients
[@rfc8835]. ICE candidate brokering, per-realm STUN configuration,
ephemeral TURN credential issuance via `/turn-credentials`, JWT
authentication, webhook delivery, host migration with deterministic
election, and a bounded replay buffer for reconnection state
reconciliation. Redis-backed shared state enables multi-instance
deployments. Tier 4 is handled by the `handlers/ws.rs` and
`handlers/http.rs` modules; application payloads remain
DTLS-encrypted throughout — the relay sees only ciphertext.

**Client SDK** — Framework-neutral TypeScript
(`@afterrealism/dendri-client`), licensed under Apache-2.0.
`createDendriStore()` exposes a reactive store compatible with React,
Vue, Svelte, and vanilla JS. A 7-state connection state machine
manages tier transitions. The `HybridConnection` class wraps WebRTC
and WebSocket transports with E2E encryption (ECDH P-256 +
AES-256-GCM) auto-negotiated on relay fallback. The Yjs CRDT bridge
(`@afterrealism/dendri-y`) is published as a separate package.

Both components are self-host-first: the SDK receives its server URL
from configuration and fails with a clear error if none is provided.
No hardcoded default connects to any hosted instance.

# Acknowledgements

We acknowledge the Yjs and YATA authors [@nicolaescu2016yata] for
the CRDT framework that dendri-y extends, the coturn and Snowflake
teams for advancing WebRTC on restricted networks, and the
Hocuspocus authors for establishing the collaborative-editing server
category.

# References
