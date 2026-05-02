use std::time::Duration;

use tokio::sync::watch;

use crate::handlers::message::cleanup_expired_sessions;
use crate::redis_realm;
use crate::state::AppState;

const CHECK_INTERVAL_MS: u64 = 300;

/// Background task that evicts clients whose last heartbeat exceeds alive_timeout.
/// Reads last_ping from the in-memory cache (no Redis round-trip on the hot path).
pub async fn run(state: AppState, mut shutdown: watch::Receiver<bool>) {
    let interval = Duration::from_millis(CHECK_INTERVAL_MS);
    let alive_timeout_ms = state.config.alive_timeout as i64;

    loop {
        tokio::select! {
            _ = tokio::time::sleep(interval) => {}
            _ = shutdown.changed() => {
                tracing::info!("check_broken_connections shutting down");
                return;
            }
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;

        // Collect IDs to evict (can't mutate DashMap while iterating).
        let to_evict: Vec<String> = state
            .clients
            .iter()
            .filter(|entry| now - entry.value().last_ping_ms() >= alive_timeout_ms)
            .map(|entry| entry.key().clone())
            .collect();

        for client_id in to_evict {
            tracing::info!("Evicting timed-out client: {client_id}");

            // Close the WebSocket sender channel (which closes the socket).
            state.ws_senders.remove(&client_id);
            if state.clients.remove(&client_id).is_some() {
                state.release_connection_slot();
            }

            // Clear their message queue and remove from Redis.
            let _ = redis_realm::clear_message_queue(&state.redis, &client_id).await;
            let _ = redis_realm::remove_client(&state.redis, &client_id).await;
        }

        // Clean up expired pending room removals (session TTL).
        cleanup_expired_sessions(&state);
    }
}
