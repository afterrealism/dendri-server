// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2025-2026 Dendri contributors

use std::time::Duration;

use tokio::sync::watch;

use crate::handlers::message::cleanup_expired_sessions;
use crate::redis_realm;
use crate::state::AppState;

const CHECK_INTERVAL_MS: u64 = 300;
/// Reconciliation runs every 60 ticks (18 s) and forces the atomic counter
/// to match the actual client-count, fixing any drift from edge-case races.
const RECONCILE_TICKS: u64 = 60;

/// Background task that evicts clients whose last heartbeat exceeds alive_timeout,
/// or whose last non-heartbeat message exceeds idle_timeout. Also periodically
/// reconciles the atomic connection counter against the real client count.
pub async fn run(state: AppState, mut shutdown: watch::Receiver<bool>) {
    let interval = Duration::from_millis(CHECK_INTERVAL_MS);
    let alive_timeout_ms = state.config.alive_timeout as i64;
    let idle_timeout_ms = state.config.idle_timeout as i64;
    let mut tick: u64 = 0;

    loop {
        tokio::select! {
            _ = tokio::time::sleep(interval) => {}
            _ = shutdown.changed() => {
                tracing::info!("check_broken_connections shutting down");
                return;
            }
        }

        tick = tick.wrapping_add(1);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;

        // Collect IDs to evict (can't mutate DashMap while iterating).
        let to_evict: Vec<String> = state
            .clients
            .iter()
            .filter(|entry| {
                let meta = entry.value();
                // Alive check — no heartbeat within alive_timeout.
                if now - meta.last_ping_ms() >= alive_timeout_ms {
                    return true;
                }
                // Idle check — no data messages within idle_timeout.
                if idle_timeout_ms > 0 && now - meta.last_message_ms() >= idle_timeout_ms {
                    return true;
                }
                false
            })
            .map(|entry| entry.key().clone())
            .collect();

        for client_id in to_evict {
            let reason = {
                let meta = state.clients.get(&client_id);
                match meta {
                    Some(ref m) if now - m.last_ping_ms() >= alive_timeout_ms => "heartbeat",
                    _ => "idle",
                }
            };
            tracing::info!("Evicting {reason} client: {client_id}");

            state.ws_senders.remove(&client_id);
            if state.clients.remove(&client_id).is_some() {
                state.release_connection_slot();
            }

            let _ = redis_realm::clear_message_queue(&state.redis, &client_id).await;
            let _ = redis_realm::remove_client(&state.redis, &client_id).await;
        }

        // Periodic reconciliation: reset the atomic counter to the actual
        // client count in case the counter has drifted due to edge cases.
        if tick % RECONCILE_TICKS == 0 {
            let actual = state.clients.len();
            let counter = state.active_connections.load(std::sync::atomic::Ordering::SeqCst);
            if actual != counter {
                tracing::warn!(
                    actual,
                    counter,
                    drift = (counter as isize) - (actual as isize),
                    "Connection counter drift detected — reconciling"
                );
                state
                    .active_connections
                    .store(actual, std::sync::atomic::Ordering::SeqCst);
            }
        }

        // Clean up expired pending room removals (session TTL).
        cleanup_expired_sessions(&state);
    }
}
