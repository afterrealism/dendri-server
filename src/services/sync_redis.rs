use std::time::Duration;

use tokio::sync::watch;

use crate::redis_realm;
use crate::state::AppState;

/// Sync interval: flush in-memory last_ping values to Redis every 10 seconds.
/// This keeps Redis eventually consistent for multi-instance scenarios and
/// persistence across restarts, without adding latency to the hot path.
const SYNC_INTERVAL_SECS: u64 = 10;

/// Background task that periodically syncs in-memory client last_ping values to Redis.
pub async fn run(state: AppState, mut shutdown: watch::Receiver<bool>) {
    let interval = Duration::from_secs(SYNC_INTERVAL_SECS);

    loop {
        tokio::select! {
            _ = tokio::time::sleep(interval) => {}
            _ = shutdown.changed() => {
                tracing::info!("sync_redis shutting down");
                return;
            }
        }

        let alive_timeout = state.config.alive_timeout;

        for entry in state.clients.iter() {
            let id = entry.key();
            if let Err(e) = redis_realm::set_last_ping(&state.redis, id, alive_timeout).await {
                tracing::warn!("sync_redis: failed to update last_ping for {id}: {e}");
            }
        }
    }
}
