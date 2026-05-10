// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2025-2026 Dendri contributors

use std::time::Duration;

use tokio::sync::watch;

use crate::state::AppState;

const EVICT_INTERVAL_SECS: u64 = 10;

/// Background task that evicts expired entries from the replay buffer every 10 seconds.
pub async fn run(state: AppState, mut shutdown: watch::Receiver<bool>) {
    let interval = Duration::from_secs(EVICT_INTERVAL_SECS);

    loop {
        tokio::select! {
            _ = tokio::time::sleep(interval) => {}
            _ = shutdown.changed() => {
                tracing::info!("replay_evict shutting down");
                return;
            }
        }

        state.replay_buffer.evict_expired();
    }
}
