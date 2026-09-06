use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{
        sse::{Event, KeepAlive, Sse},
        IntoResponse,
    },
    Json,
};
use serde::Deserialize;
use std::convert::Infallible;
use std::sync::Arc;
use tokio::sync::mpsc;

use crate::enums::MessageType;
use crate::handlers::message::handle_message;
use crate::models::message::Message;
use crate::redis_realm;
use crate::state::{AppState, ClientMeta, TransportKind, WsSender};
use crate::validation::constant_time_str_eq;
use crate::webhook::WebhookEvent;

#[derive(Debug, Deserialize)]
pub struct HttpQuery {
    pub id: String,
    pub token: String,
    pub key: Option<String>,
    pub last_seq: Option<u64>,
    /// Tenant API key (hosted/multi-tenant deployments).
    pub api_key: Option<String>,
    /// Per-connection JWT (HS256), enforced when an effective secret is set.
    pub jwt: Option<String>,
}

/// GET /http/sse -- Server-Sent Events stream for receiving messages.
///
/// Creates an SSE connection, registers the client in the same `ws_senders`
/// DashMap used by WebSocket clients, so all message routing works unchanged.
pub async fn sse_handler(
    Query(params): Query<HttpQuery>,
    State(state): State<AppState>,
) -> Result<
    Sse<impl futures::stream::Stream<Item = Result<Event, Infallible>>>,
    (StatusCode, &'static str),
> {
    let id = params.id;
    let token = params.token;

    // Validate key (constant-time to avoid timing oracles). The key is
    // required — treating it as optional made the shared key advisory for
    // SSE clients while WS clients were forced to present it.
    match params.key {
        Some(ref key) if constant_time_str_eq(key, &state.config.key) => {}
        _ => return Err((StatusCode::UNAUTHORIZED, "Invalid key")),
    }

    // Tenant resolution (hosted mode) — same contract as the WS handler.
    let resolved_tenant = match params.api_key.as_deref() {
        Some(api_key) => {
            match crate::tenant::resolve_api_key(&state.redis, &state.tenant_cache, api_key).await {
                Some(tenant) => Some(tenant),
                None => return Err((StatusCode::UNAUTHORIZED, "Invalid api_key")),
            }
        }
        None => {
            if state.config.require_api_key {
                return Err((StatusCode::UNAUTHORIZED, "api_key required"));
            }
            None
        }
    };
    let tenant_id = resolved_tenant.as_ref().map(|t| t.id.clone());

    // Same JWT rule as the WS transport — the HTTP fallback must not be a
    // back door around the room ACL.
    if super::enforce_jwt(&state, resolved_tenant.as_ref(), params.jwt.as_deref(), &id)
        .await
        .is_err()
    {
        return Err((StatusCode::FORBIDDEN, "Invalid token"));
    }

    // Handle reconnection: validate token if client already exists.
    let is_new_client = !state.clients.contains_key(&id);
    if let Some(existing) = state.clients.get(&id) {
        if existing.token != token {
            return Err((StatusCode::CONFLICT, "ID is taken"));
        }
    }

    // For new clients, atomically reserve a connection slot. Doing this
    // with a plain `clients.len()` check races with other concurrent
    // connects at high connection rates.
    if is_new_client && !state.try_reserve_connection_slot(state.config.concurrent_limit) {
        return Err((StatusCode::SERVICE_UNAVAILABLE, "Connection limit reached"));
    }

    // Register client in backend.
    register_client_backend(&state, &id, &token).await;

    // Create channel for this client.
    let (tx, mut rx) = mpsc::unbounded_channel::<String>();

    // Register in the same DashMaps used by WebSocket clients.
    let meta = ClientMeta::with_transport(token, TransportKind::Sse);
    state.clients.insert(id.clone(), meta);
    state.ws_senders.insert(id.clone(), tx.clone());
    if let Some(tenant_id) = tenant_id {
        state.client_tenants.insert(id.clone(), tenant_id);
    }

    // Send OPEN message.
    let _ = tx.send(r#"{"type":"OPEN"}"#.to_string());

    // Deliver queued messages.
    deliver_queued_messages(&state, &id, &tx).await;

    // Handle replay gap detection.
    if let Some(requested_seq) = params.last_seq {
        if let Some(oldest) = state.replay_buffer.oldest_seq(&id) {
            if requested_seq < oldest {
                let gap_msg = format!(
                    r#"{{"type":"ERROR","payload":{{"msg":"REPLAY_GAP","oldest_seq":{},"requested_seq":{}}}}}"#,
                    oldest, requested_seq
                );
                let _ = tx.send(gap_msg);
            }
        }
        for msg in state.replay_buffer.replay_since(&id, requested_seq) {
            let _ = tx.send(msg);
        }
    }

    tracing::info!("SSE client connected: {id}");

    if let Some(ref webhook) = state.webhook {
        webhook.emit(WebhookEvent::peer_connected(&id));
    }

    // Build SSE stream from the receiver.
    let client_id = id.clone();
    let state_cleanup = state.clone();
    let stream = async_stream::stream! {
        while let Some(msg) = rx.recv().await {
            yield Ok::<_, Infallible>(Event::default().data(msg));
        }
        // Channel closed -- clean up.
        cleanup_client(&state_cleanup, &client_id).await;
    };

    // Watchdog: when the client disconnects mid-stream, axum drops the
    // stream future, which drops `rx`. The original `tx` stays alive in
    // `ws_senders`, so `rx.recv().await` never returns None in the stream
    // block above — meaning the inline cleanup never runs. Detect the
    // dropped receiver via `tx.is_closed()` on a poll loop and trigger
    // cleanup ourselves. Without this, disconnected SSE clients leak
    // until the heartbeat timeout (default 60 s) evicts them.
    let watchdog_tx = tx.clone();
    let watchdog_state = state.clone();
    let watchdog_id = id.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
            if watchdog_tx.is_closed() {
                cleanup_client(&watchdog_state, &watchdog_id).await;
                break;
            }
            // Also bail out if the client was evicted via a different path
            // (e.g. check_broken); no reason to keep polling.
            if !watchdog_state.clients.contains_key(&watchdog_id) {
                break;
            }
        }
    });

    Ok(Sse::new(stream).keep_alive(KeepAlive::default()))
}

/// POST /http/send -- Client sends a message to the server (used by SSE and polling clients).
pub async fn send_handler(
    Query(params): Query<HttpQuery>,
    State(state): State<AppState>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let id = params.id;

    // Verify client exists AND the caller holds its session token. Without
    // the token comparison, anyone who learns a peer ID (e.g. from a room
    // peer list) could POST signaling or DATA as that peer.
    match state.clients.get(&id) {
        Some(client) if client.token == params.token => client.touch(),
        _ => return (StatusCode::UNAUTHORIZED, "Client not registered").into_response(),
    }

    // Parse and handle message.
    match serde_json::from_value::<Message>(body) {
        Ok(msg) => {
            // Apply the same rate limits WebSocket clients get. Without this
            // an SSE/polling client could flood DATA at unlimited rate while
            // WS peers are throttled.
            if !apply_rate_limit(&state, &id, &msg) {
                return (
                    StatusCode::TOO_MANY_REQUESTS,
                    Json(serde_json::json!({"error": "Rate limit exceeded"})),
                )
                    .into_response();
            }
            handle_message(&state, &id, msg).await;
            (StatusCode::OK, "ok").into_response()
        }
        Err(e) => {
            tracing::warn!("Invalid message from HTTP client {id}: {e}");
            (StatusCode::BAD_REQUEST, "Invalid message").into_response()
        }
    }
}

/// Apply the per-client token-bucket rate limit that also gates WebSocket
/// messages. Returns `true` when the message is allowed, `false` when the
/// bucket is exhausted (caller should surface an error to the client).
fn apply_rate_limit(state: &AppState, client_id: &str, msg: &Message) -> bool {
    let (bucket, limit) = match msg.type_ {
        MessageType::OFFER | MessageType::ANSWER | MessageType::CANDIDATE => {
            ("signaling", state.config.rate_limit_signaling)
        }
        MessageType::DATA => ("data", state.config.rate_limit_data),
        _ => return true, // HEARTBEAT, LEAVE, room ops — unmetered.
    };
    let allowed = state
        .rate_limiter
        .check_and_consume(client_id, bucket, limit);
    if !allowed {
        tracing::warn!(
            client_id = %client_id,
            bucket = %bucket,
            limit = limit,
            msg_type = ?msg.type_,
            "HTTP rate limit exceeded"
        );
        if let Some(ref webhook) = state.webhook {
            webhook.emit(WebhookEvent::rate_limited(client_id, bucket));
        }
    }
    allowed
}

/// GET /http/poll -- Long polling endpoint for receiving messages.
///
/// On first call (client not registered), registers the client and creates a
/// persistent `(tx, rx)` pair for this client's lifetime. On subsequent
/// calls, reuses the same receiver so messages delivered between polls are
/// not dropped.
pub async fn poll_handler(
    Query(params): Query<HttpQuery>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    let id = params.id;
    let token = params.token;

    // Validate key (constant-time). Required — same reasoning as sse_handler.
    match params.key {
        Some(ref key) if constant_time_str_eq(key, &state.config.key) => {}
        _ => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({"error": "Invalid key"})),
            )
                .into_response();
        }
    }

    // Tenant resolution (hosted mode) — same contract as the WS handler.
    let resolved_tenant = match params.api_key.as_deref() {
        Some(api_key) => {
            match crate::tenant::resolve_api_key(&state.redis, &state.tenant_cache, api_key).await {
                Some(tenant) => Some(tenant),
                None => {
                    return (
                        StatusCode::UNAUTHORIZED,
                        Json(serde_json::json!({"error": "Invalid api_key"})),
                    )
                        .into_response();
                }
            }
        }
        None => {
            if state.config.require_api_key {
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(serde_json::json!({"error": "api_key required"})),
                )
                    .into_response();
            }
            None
        }
    };
    let tenant_id = resolved_tenant.as_ref().map(|t| t.id.clone());

    // Same JWT rule as the WS transport — the HTTP fallback must not be a
    // back door around the room ACL.
    if super::enforce_jwt(&state, resolved_tenant.as_ref(), params.jwt.as_deref(), &id)
        .await
        .is_err()
    {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "Invalid token"})),
        )
            .into_response();
    }

    let is_new_client = !state.clients.contains_key(&id);

    if !is_new_client {
        // Validate token for existing client.
        if let Some(existing) = state.clients.get(&id) {
            if existing.token != token {
                return (
                    StatusCode::CONFLICT,
                    Json(serde_json::json!({"error": "ID is taken"})),
                )
                    .into_response();
            }
        }
    } else if !state.try_reserve_connection_slot(state.config.concurrent_limit) {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"error": "Connection limit reached"})),
        )
            .into_response();
    }

    // Reuse the persistent receiver for this client if it exists; otherwise
    // create a fresh (tx, rx) pair. The receiver is wrapped in an Arc<Mutex>
    // so only one poll at a time can drain it even if a client misbehaves
    // and pipelines polls.
    //
    // Clone the Arc values out of DashMap refs eagerly, then drop the refs
    // before awaiting — holding DashMap refs across .await risks deadlock
    // with shard locks.
    let existing_rx: Option<crate::state::PollingReceiver> =
        state.polling_receivers.get(&id).map(|r| r.value().clone());
    let existing_tx: Option<WsSender> = state.ws_senders.get(&id).map(|r| r.value().clone());

    let (tx, receiver): (WsSender, crate::state::PollingReceiver) = match (existing_rx, existing_tx)
    {
        (Some(rx), Some(tx)) => (tx, rx),
        _ => {
            // Either this is a new client, or we lost one half of the
            // pair (e.g. check_broken evicted tx). Rebuild both ends
            // consistently.
            let (tx, rx) = mpsc::unbounded_channel::<String>();
            let rx_arc: crate::state::PollingReceiver = Arc::new(tokio::sync::Mutex::new(rx));
            state.ws_senders.insert(id.clone(), tx.clone());
            state.polling_receivers.insert(id.clone(), rx_arc.clone());
            (tx, rx_arc)
        }
    };

    if is_new_client {
        // Register in backend.
        register_client_backend(&state, &id, &token).await;

        let meta = ClientMeta::with_transport(token, TransportKind::Polling);
        state.clients.insert(id.clone(), meta);
        if let Some(tenant_id) = tenant_id {
            state.client_tenants.insert(id.clone(), tenant_id);
        }

        // Send OPEN message.
        let _ = tx.send(r#"{"type":"OPEN"}"#.to_string());

        // Deliver queued messages.
        deliver_queued_messages(&state, &id, &tx).await;

        tracing::info!("Polling client connected: {id}");

        if let Some(ref webhook) = state.webhook {
            webhook.emit(WebhookEvent::peer_connected(&id));
        }
    } else {
        // Touch heartbeat.
        if let Some(client) = state.clients.get(&id) {
            client.touch();
        }
    }

    // Handle replay gap detection.
    if let Some(requested_seq) = params.last_seq {
        if let Some(oldest) = state.replay_buffer.oldest_seq(&id) {
            if requested_seq < oldest {
                let gap_msg = format!(
                    r#"{{"type":"ERROR","payload":{{"msg":"REPLAY_GAP","oldest_seq":{},"requested_seq":{}}}}}"#,
                    oldest, requested_seq
                );
                let _ = tx.send(gap_msg);
            }
        }
        for msg in state.replay_buffer.replay_since(&id, requested_seq) {
            let _ = tx.send(msg);
        }
    }

    // Drain whatever is pending, waiting up to 25s for the first message.
    let messages = collect_poll_messages_shared(receiver).await;

    Json(messages).into_response()
}

/// Drain the persistent polling receiver shared across poll requests.
/// Waits up to 25 seconds for the first message then drains anything else
/// that is immediately ready. Cap the batch to a reasonable upper bound so
/// one laggy poll can't return megabytes.
async fn collect_poll_messages_shared(
    receiver: Arc<tokio::sync::Mutex<mpsc::UnboundedReceiver<String>>>,
) -> Vec<String> {
    const MAX_BATCH: usize = 500;
    let mut messages = Vec::new();
    let timeout = tokio::time::Duration::from_secs(25);
    let mut guard = receiver.lock().await;

    if let Ok(Some(msg)) = tokio::time::timeout(timeout, guard.recv()).await {
        messages.push(msg);
        while messages.len() < MAX_BATCH {
            match guard.try_recv() {
                Ok(msg) => messages.push(msg),
                Err(_) => break,
            }
        }
    }

    messages
}

/// Register a client in Redis.
async fn register_client_backend(state: &AppState, id: &str, token: &str) {
    let _ = redis_realm::register_client(&state.redis, id, token, state.config.alive_timeout).await;
}

/// Deliver queued messages from the backend to a newly connected client.
async fn deliver_queued_messages(state: &AppState, id: &str, tx: &WsSender) {
    let messages = redis_realm::read_all_messages(&state.redis, id)
        .await
        .unwrap_or_default();

    if messages.is_empty() {
        return;
    }

    for msg_json in &messages {
        if let Ok(msg) = serde_json::from_str::<Message>(msg_json) {
            let data = serde_json::to_string(&msg).unwrap_or_default();
            if tx.send(data).is_err() {
                break;
            }
        }
    }

    let _ = redis_realm::clear_message_queue(&state.redis, id).await;
}

/// Clean up a disconnected SSE or polling client.
async fn cleanup_client(state: &AppState, client_id: &str) {
    state.ws_senders.remove(client_id);
    state.polling_receivers.remove(client_id);
    if state.clients.remove(client_id).is_some() {
        state.release_connection_slot();
    }
    state.client_claims.remove(client_id);
    state.client_tenants.remove(client_id);
    state.rate_limiter.remove_client(client_id);
    super::message::remove_client_from_all_rooms(state, client_id);

    let _ = redis_realm::remove_client(&state.redis, client_id).await;

    tracing::info!("SSE client disconnected: {client_id}");

    if let Some(ref webhook) = state.webhook {
        webhook.emit(WebhookEvent::peer_disconnected(client_id));
    }
}
