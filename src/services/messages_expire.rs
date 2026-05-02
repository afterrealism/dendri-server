use std::collections::HashSet;
use std::time::Duration;

use tokio::sync::watch;

use crate::models::message::Message;
use crate::redis_realm;
use crate::state::AppState;

/// Background task that expires queued messages after expire_timeout.
/// Sends deduplicated EXPIRE messages back to the original senders.
pub async fn run(state: AppState, mut shutdown: watch::Receiver<bool>) {
    let interval = Duration::from_millis(state.config.cleanup_out_msgs);
    let expire_timeout_ms = state.config.expire_timeout as i64;

    loop {
        tokio::select! {
            _ = tokio::time::sleep(interval) => {}
            _ = shutdown.changed() => {
                tracing::info!("messages_expire shutting down");
                return;
            }
        }

        let queue_ids = match redis_realm::get_client_ids_with_queue(&state.redis).await {
            Ok(ids) => ids,
            Err(e) => {
                tracing::error!("Redis error in messages_expire: {e}");
                continue;
            }
        };

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;

        for dst_id in queue_ids {
            let last_read_at = redis_realm::get_queue_last_read_at(&state.redis, &dst_id)
                .await
                .unwrap_or(None)
                .unwrap_or(0);

            if now - last_read_at < expire_timeout_ms {
                continue;
            }

            let messages = redis_realm::read_all_messages(&state.redis, &dst_id)
                .await
                .unwrap_or_default();

            let mut seen = HashSet::new();

            for msg_json in &messages {
                let Ok(msg) = serde_json::from_str::<Message>(msg_json) else {
                    continue;
                };

                let src = msg.src.as_deref().unwrap_or("");
                let dst = msg.dst.as_deref().unwrap_or("");
                let seen_key = format!("{src}_{dst}");

                if seen.contains(&seen_key) {
                    continue;
                }
                seen.insert(seen_key);

                let data = format!(r#"{{"type":"EXPIRE","src":"{}","dst":"{}"}}"#, dst, src);

                if let Some(sender) = state.ws_senders.get(src) {
                    let _ = sender.send(data);
                }
            }

            let _ = redis_realm::clear_message_queue(&state.redis, &dst_id).await;
        }
    }
}
