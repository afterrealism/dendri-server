use std::collections::HashSet;
use std::sync::atomic::{AtomicI64, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;

use dashmap::DashMap;
use redis::aio::ConnectionManager;
use tokio::sync::mpsc;

use crate::config::Config;
use crate::rate_limiter::RateLimiter;
use crate::replay_buffer::ReplayBuffer;
use crate::webhook::WebhookSender;

/// Tracks a client that disconnected but hasn't been removed from rooms yet.
/// Holds the rooms they were in and the disconnect timestamp.
pub struct PendingRemoval {
    pub rooms: Vec<String>,
    pub disconnected_at: Instant,
}

/// A sender handle for pushing text frames into a client's writer task.
pub type WsSender = mpsc::UnboundedSender<String>;

/// Receiver handle for polling clients. Wrapped in Arc<Mutex> so it can
/// survive across the many sequential HTTP poll requests a single polling
/// client makes — replacing it on every poll would drop messages that
/// arrived between polls.
pub type PollingReceiver = Arc<tokio::sync::Mutex<mpsc::UnboundedReceiver<String>>>;

/// Transport type used by a connected client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportKind {
    WebSocket,
    SSE,
    Polling,
}

/// In-memory client metadata, avoids Redis round-trips on the hot path.
pub struct ClientMeta {
    pub token: String,
    pub last_ping: AtomicI64,
    pub transport: TransportKind,
}

impl ClientMeta {
    pub fn new(token: String) -> Self {
        Self {
            token,
            last_ping: AtomicI64::new(now_ms()),
            transport: TransportKind::WebSocket,
        }
    }

    pub fn with_transport(token: String, transport: TransportKind) -> Self {
        Self {
            token,
            last_ping: AtomicI64::new(now_ms()),
            transport,
        }
    }

    pub fn touch(&self) {
        self.last_ping.store(now_ms(), Ordering::Relaxed);
    }

    pub fn last_ping_ms(&self) -> i64 {
        self.last_ping.load(Ordering::Relaxed)
    }
}

/// Shared application state, cheaply cloneable via Arc internals.
#[derive(Clone)]
pub struct AppState {
    pub ws_senders: Arc<DashMap<String, WsSender>>,
    pub clients: Arc<DashMap<String, ClientMeta>>,
    pub redis: ConnectionManager,
    pub config: Arc<Config>,
    /// Room name -> set of client IDs in that room.
    pub rooms: Arc<DashMap<String, HashSet<String>>>,
    /// Client ID -> set of room names (reverse index for fast cleanup).
    pub client_rooms: Arc<DashMap<String, HashSet<String>>>,
    /// Global monotonic counter for message sequencing.
    pub seq_counter: Arc<AtomicU64>,
    /// Server start time for uptime tracking.
    pub start_time: Instant,
    /// Per-client token bucket rate limiter.
    pub rate_limiter: Arc<RateLimiter>,
    /// Per-client ring buffer for message replay on reconnection.
    pub replay_buffer: Arc<ReplayBuffer>,
    /// Tracks clients that disconnected but haven't been removed from rooms yet.
    /// Maps client_id -> PendingRemoval (rooms + disconnect timestamp).
    pub pending_removals: Arc<DashMap<String, PendingRemoval>>,
    /// Room name -> (peer_id -> JSON presence data).
    pub presence: Arc<DashMap<String, DashMap<String, String>>>,
    /// Per-client JWT claims (stored after successful JWT validation).
    pub client_claims: Arc<DashMap<String, serde_json::Value>>,
    /// Optional webhook sender for server event notifications.
    pub webhook: Option<Arc<WebhookSender>>,
    /// Atomic count of live connections. Used to enforce `concurrent_limit`
    /// without the TOCTOU race inherent in `clients.len()` + `clients.insert()`.
    pub active_connections: Arc<AtomicUsize>,
    /// Persistent receivers for HTTP long-polling clients. One entry per
    /// client; reused across poll requests so messages delivered between
    /// polls aren't dropped when the poll handler returns.
    pub polling_receivers: Arc<DashMap<String, PollingReceiver>>,
}

impl AppState {
    /// Atomically reserve a connection slot. Returns `true` on success
    /// (caller must later call [`release_connection_slot`] when the client
    /// is removed). Returns `false` if the limit has been reached; no
    /// counter change is persisted in that case.
    pub fn try_reserve_connection_slot(&self, limit: usize) -> bool {
        let prev = self.active_connections.fetch_add(1, Ordering::SeqCst);
        if prev >= limit {
            self.active_connections.fetch_sub(1, Ordering::SeqCst);
            return false;
        }
        true
    }

    /// Release a previously reserved connection slot. Must be called
    /// exactly once per successful [`try_reserve_connection_slot`].
    pub fn release_connection_slot(&self) {
        // saturating_sub via compare_exchange loop would be paranoid; a
        // bare fetch_sub is fine because reserve/release are paired.
        self.active_connections.fetch_sub(1, Ordering::SeqCst);
    }
}

impl AppState {
    pub async fn new(config: Config) -> Result<Self, redis::RedisError> {
        let client = redis::Client::open(config.redis_url.as_str())?;
        let redis = ConnectionManager::new(client).await?;
        let replay_buffer = Arc::new(ReplayBuffer::new(
            config.replay_buffer_size,
            config.replay_buffer_ttl,
        ));
        let webhook = config.webhook_url.as_ref().and_then(|url| {
            if !crate::webhook::is_safe_webhook_url(url) {
                tracing::error!(
                    url = %url,
                    "Refusing to initialise webhook: URL points at loopback / link-local / metadata host"
                );
                return None;
            }
            Some(Arc::new(WebhookSender::new(
                url.clone(),
                config.webhook_secret.clone(),
            )))
        });
        Ok(Self {
            ws_senders: Arc::new(DashMap::new()),
            clients: Arc::new(DashMap::new()),
            redis,
            config: Arc::new(config),
            rooms: Arc::new(DashMap::new()),
            client_rooms: Arc::new(DashMap::new()),
            seq_counter: Arc::new(AtomicU64::new(0)),
            start_time: Instant::now(),
            rate_limiter: Arc::new(RateLimiter::new()),
            replay_buffer,
            pending_removals: Arc::new(DashMap::new()),
            presence: Arc::new(DashMap::new()),
            client_claims: Arc::new(DashMap::new()),
            webhook,
            active_connections: Arc::new(AtomicUsize::new(0)),
            polling_receivers: Arc::new(DashMap::new()),
        })
    }
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_meta_new_sets_token_and_current_time() {
        let before = now_ms();
        let meta = ClientMeta::new("my_token".to_string());
        let after = now_ms();

        assert_eq!(meta.token, "my_token");
        assert!(meta.last_ping_ms() >= before);
        assert!(meta.last_ping_ms() <= after);
    }

    #[test]
    fn client_meta_touch_updates_last_ping() {
        let meta = ClientMeta::new("tok".to_string());
        let initial = meta.last_ping_ms();

        // Sleep briefly to ensure different timestamp.
        std::thread::sleep(std::time::Duration::from_millis(5));
        meta.touch();

        assert!(meta.last_ping_ms() > initial);
    }

    #[test]
    fn client_meta_last_ping_ms_reads_value() {
        let meta = ClientMeta::new("tok".to_string());
        let ping = meta.last_ping_ms();
        assert!(ping > 0);
    }
}
