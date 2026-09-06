use std::sync::Arc;

use axum::extract::ws::{Message as WsMessage, WebSocket};
use axum::extract::{Query, State, WebSocketUpgrade};
use axum::response::Response;
use futures::stream::StreamExt;
use serde::Deserialize;
use serde_json::value::RawValue;
use tokio::sync::mpsc;

use crate::enums::{MessageType, PeerError};
use crate::handlers::message::{handle_message, make_error_json};
use crate::models::message::Message;
use crate::redis_realm;
use crate::state::{AppState, ClientMeta};
use crate::validation::{constant_time_str_eq, is_valid_identifier};
use crate::webhook::WebhookEvent;

#[derive(Debug, Deserialize)]
pub struct WsQuery {
    pub id: Option<String>,
    pub token: Option<String>,
    pub key: Option<String>,
    /// Last received sequence number for replay gap detection on reconnect.
    pub last_seq: Option<u64>,
    /// Optional JWT for authenticated connections.
    pub jwt: Option<String>,
    /// Tenant API key (hosted/multi-tenant deployments).
    pub api_key: Option<String>,
}

/// WebSocket upgrade handler.
pub async fn ws_upgrade(
    ws: WebSocketUpgrade,
    Query(params): Query<WsQuery>,
    State(state): State<AppState>,
) -> Response {
    ws.on_upgrade(move |socket| handle_socket(socket, params, state))
}

async fn handle_socket(socket: WebSocket, params: WsQuery, state: AppState) {
    let (id, token, key, last_seq) = match (params.id, params.token, params.key) {
        (Some(id), Some(token), Some(key)) => (id, token, key, params.last_seq),
        _ => {
            send_error_and_close(socket, &PeerError::InvalidWsParameters).await;
            return;
        }
    };

    // Reject malformed identifiers before they touch storage or serializers.
    // Peer IDs and tokens are interpolated into hand-built JSON elsewhere, so
    // the character-class restriction here is load-bearing for safety.
    if !is_valid_identifier(&id) || !is_valid_identifier(&token) {
        send_error_and_close(socket, &PeerError::InvalidWsParameters).await;
        return;
    }

    // Constant-time compare the shared key so an attacker can't probe it
    // byte-by-byte via timing differences.
    if !constant_time_str_eq(&key, &state.config.key) {
        send_error_and_close(socket, &PeerError::InvalidKey).await;
        return;
    }

    // Tenant resolution (hosted mode): an api_key must resolve to an active
    // tenant; a missing api_key is allowed only in self-host mode.
    let resolved_tenant = match params.api_key.as_deref() {
        Some(api_key) => {
            match crate::tenant::resolve_api_key(&state.redis, &state.tenant_cache, api_key).await {
                Some(tenant) => Some(tenant),
                None => {
                    send_error_and_close(socket, &PeerError::InvalidKey).await;
                    return;
                }
            }
        }
        None => {
            if state.config.require_api_key {
                send_error_and_close(socket, &PeerError::InvalidKey).await;
                return;
            }
            None
        }
    };
    let tenant_id = resolved_tenant.as_ref().map(|t| t.id.clone());

    // Optional JWT validation — enforced when the effective secret (per-tenant
    // first, then global) is configured for this connection.
    let effective_secret = crate::jwt::effective_jwt_secret(
        resolved_tenant
            .as_ref()
            .and_then(|t| t.jwt_secret.as_deref()),
        state.config.jwt_secret.as_deref(),
    );
    if let Some(secret) = effective_secret {
        let jwt_token = params.jwt.as_deref().unwrap_or("");
        match crate::jwt::validate_jwt(secret, jwt_token) {
            Ok(claims) => {
                if let Some(ref t) = resolved_tenant {
                    if !crate::jwt::tid_matches(&claims, &t.id) {
                        tracing::warn!(client = %id, tenant = %t.id, "JWT tid mismatch");
                        send_error_and_close(socket, &PeerError::InvalidToken).await;
                        return;
                    }
                }
                tracing::debug!(client = %id, claims = ?claims, "JWT validated");
                state.client_claims.insert(id.clone(), claims);
            }
            Err(e) => {
                tracing::warn!(client = %id, error = %e, "JWT validation failed");
                send_error_and_close(socket, &PeerError::InvalidToken).await;
                return;
            }
        }
    }

    // Check if client already exists (reconnection scenario).
    // Try in-memory cache first, fall back to Redis.
    let existing_token = state.clients.get(&id).map(|meta| meta.token.clone());

    // If not in memory, check Redis (may exist from a previous process).
    let existing_token = match existing_token {
        Some(t) => Some(t),
        None => redis_realm::get_client_token(&state.redis, &id)
            .await
            .unwrap_or(None),
    };

    if let Some(stored_token) = existing_token {
        if token != stored_token {
            // ID is taken with a different token.
            let id_taken = serde_json::to_string(&Message {
                type_: MessageType::IdTaken,
                src: None,
                dst: None,
                payload: Some(
                    RawValue::from_string(r#"{"msg":"ID is taken"}"#.to_string()).unwrap(),
                ),
                seq: None,
                room: None,
                timestamp: None,
                topic_class: None,
            })
            .unwrap_or_default();

            let (mut sink, _) = socket.split();
            let _ = futures::SinkExt::send(&mut sink, WsMessage::Text(id_taken)).await;
            let _ = futures::SinkExt::close(&mut sink).await;
            return;
        }

        // Valid reconnection — update in-memory cache and Redis.
        state.clients.insert(id.clone(), ClientMeta::new(token));
        if let Some(ref tenant_id) = tenant_id {
            state.client_tenants.insert(id.clone(), tenant_id.clone());
        }

        // Cancel any pending room removal — client reconnected within session TTL.
        let mut restored_rooms: Vec<String> = Vec::new();
        if let Some((_, pending)) = state.pending_removals.remove(&id) {
            let rooms_count = pending.rooms.len();
            for room in &pending.rooms {
                state
                    .rooms
                    .entry(room.clone())
                    .or_default()
                    .insert(id.clone());
            }
            restored_rooms = pending.rooms.clone();
            state
                .client_rooms
                .insert(id.clone(), pending.rooms.into_iter().collect());
            tracing::info!(client = %id, rooms_restored = rooms_count, "Session restored from pending removal");
        }

        let _ = redis_realm::set_last_ping(&state.redis, &id, state.config.alive_timeout).await;
        run_client(socket, &state, &id, last_seq, restored_rooms).await;
    } else {
        // New client — atomically reserve a connection slot to avoid the
        // TOCTOU race where two concurrent connects both pass the limit
        // check and then both insert.
        if !state.try_reserve_connection_slot(state.config.concurrent_limit) {
            send_error_and_close(socket, &PeerError::ConnectionLimitExceed).await;
            return;
        }

        // From here on, any early return must release the slot.
        if let Err(e) =
            redis_realm::register_client(&state.redis, &id, &token, state.config.alive_timeout)
                .await
        {
            tracing::error!("Redis error registering client {id}: {e}");
            state.release_connection_slot();
            send_error_and_close(socket, &PeerError::InvalidWsParameters).await;
            return;
        }

        // Insert into in-memory cache.
        state.clients.insert(id.clone(), ClientMeta::new(token));
        if let Some(ref tenant_id) = tenant_id {
            state.client_tenants.insert(id.clone(), tenant_id.clone());
        }

        run_client(socket, &state, &id, last_seq, Vec::new()).await;
    }
}

/// Main client lifecycle: split socket, register sender, deliver queued messages, read loop.
///
/// `restored_rooms` is non-empty only on reconnection — for each room listed,
/// the server immediately sends the reconnecting client a ROOM-PEERS update
/// so it can resync membership without waiting for the 30 s client heartbeat.
async fn run_client(
    socket: WebSocket,
    state: &AppState,
    id: &str,
    last_seq: Option<u64>,
    restored_rooms: Vec<String>,
) {
    let (sink, mut stream) = socket.split();

    // Create mpsc channel for the writer task.
    let (tx, mut rx) = mpsc::unbounded_channel::<String>();

    // Store sender in DashMap.
    state.ws_senders.insert(id.to_string(), tx.clone());

    // Spawn writer task: receives strings from the channel and sends them to the WebSocket sink.
    let writer = tokio::spawn(async move {
        use futures::SinkExt;
        let mut sink = sink;
        while let Some(msg) = rx.recv().await {
            if sink.send(WsMessage::Text(msg)).await.is_err() {
                break;
            }
        }
        let _ = sink.close().await;
    });

    // Send OPEN message.
    let open_msg = serde_json::to_string(&Message {
        type_: MessageType::OPEN,
        src: None,
        dst: None,
        payload: None,
        seq: None,
        room: None,
        timestamp: None,
        topic_class: None,
    })
    .unwrap_or_default();
    let _ = tx.send(open_msg);

    // Check for replay gap: if the client requests a sequence older than what
    // we have buffered, notify them so they can do a full state sync.
    if let Some(requested_seq) = last_seq {
        if let Some(oldest) = state.replay_buffer.oldest_seq(id) {
            if requested_seq < oldest {
                let gap_msg = format!(
                    r#"{{"type":"ERROR","payload":{{"msg":"REPLAY_GAP","oldest_seq":{},"requested_seq":{}}}}}"#,
                    oldest, requested_seq
                );
                let _ = tx.send(gap_msg);
            }
        }
    }

    // Deliver queued messages.
    deliver_queued_messages(state, id, &tx).await;

    // For reconnections that restored room memberships, push a fresh
    // ROOM-PEERS for each restored room so the client knows its current
    // membership before the next heartbeat tick.
    for stored_key in &restored_rooms {
        if let Some(members) = state.rooms.get(stored_key) {
            let member_list: Vec<String> = members.iter().cloned().collect();
            let peers_json =
                serde_json::to_string(&member_list).unwrap_or_else(|_| "[]".to_string());
            // restored_rooms holds stored (tenant-namespaced) keys; echo the
            // stripped display name to the client.
            let msg = format!(
                r#"{{"type":"ROOM-PEERS","room":"{}","payload":{}}}"#,
                super::message::room_display(stored_key),
                peers_json
            );
            let _ = tx.send(msg);
        }
    }

    tracing::info!("Client connected: {id}");

    if let Some(ref webhook) = state.webhook {
        webhook.emit(WebhookEvent::peer_connected(id));
    }

    // Read loop: process incoming messages from the client.
    let client_id = id.to_string();
    let state_clone = state.clone();
    let max_msg_size = state.config.max_message_size;
    let rate_limit_signaling = state.config.rate_limit_signaling;
    let rate_limit_data = state.config.rate_limit_data;
    let rate_limiter = Arc::clone(&state.rate_limiter);
    while let Some(result) = stream.next().await {
        match result {
            Ok(WsMessage::Text(text)) => {
                // Reject oversized messages without disconnecting.
                if text.len() > max_msg_size {
                    tracing::warn!(
                        "Oversized message from {client_id}: {} bytes (max {max_msg_size})",
                        text.len()
                    );
                    let error_payload = format!(
                        r#"{{"type":"ERROR","payload":{{"msg":"Message exceeds maximum size of {max_msg_size} bytes"}}}}"#,
                    );
                    let _ = tx.send(error_payload);
                    continue;
                }

                match serde_json::from_str::<Message>(&text) {
                    Ok(msg) => {
                        // Rate limit: signaling messages vs data messages.
                        let allowed = match msg.type_ {
                            MessageType::OFFER | MessageType::ANSWER | MessageType::CANDIDATE => {
                                rate_limiter.check_and_consume(
                                    &client_id,
                                    "signaling",
                                    rate_limit_signaling,
                                )
                            }
                            MessageType::DATA => {
                                rate_limiter.check_and_consume(&client_id, "data", rate_limit_data)
                            }
                            _ => true, // HEARTBEAT, LEAVE, etc. are not rate-limited.
                        };

                        if !allowed {
                            let bucket = match msg.type_ {
                                MessageType::DATA => "data",
                                _ => "signaling",
                            };
                            let limit = if bucket == "data" {
                                rate_limit_data
                            } else {
                                rate_limit_signaling
                            };
                            tracing::warn!(
                                client_id = %client_id,
                                bucket = %bucket,
                                limit = limit,
                                msg_type = ?msg.type_,
                                "Rate limit exceeded"
                            );
                            if let Some(ref webhook) = state_clone.webhook {
                                webhook.emit(WebhookEvent::rate_limited(&client_id, bucket));
                            }
                            let error_payload =
                                r#"{"type":"ERROR","payload":{"msg":"Rate limit exceeded"}}"#
                                    .to_string();
                            let _ = tx.send(error_payload);
                            continue;
                        }

                        handle_message(&state_clone, &client_id, msg).await;
                    }
                    Err(e) => {
                        tracing::warn!("Invalid message from {client_id}: {e}");
                    }
                }
            }
            Ok(WsMessage::Close(_)) => break,
            Err(e) => {
                tracing::warn!("WebSocket error for {client_id}: {e}");
                break;
            }
            _ => {} // Ping/Pong/Binary — ignore
        }
    }

    // Socket closed. Only clean up if we're still the current sender for this ID.
    // This prevents a stale socket close from removing a valid reconnection.
    let should_remove = state_clone
        .ws_senders
        .get(&client_id)
        .map(|s| s.same_channel(&tx))
        .unwrap_or(false);

    if should_remove {
        state_clone.ws_senders.remove(&client_id);
        if state_clone.clients.remove(&client_id).is_some() {
            state_clone.release_connection_slot();
        }
        state_clone.client_claims.remove(&client_id);
        state_clone.client_tenants.remove(&client_id);
        state_clone.rate_limiter.remove_client(&client_id);
        super::message::remove_client_from_all_rooms(&state_clone, &client_id);
        let _ = redis_realm::remove_client(&state_clone.redis, &client_id).await;
        tracing::info!("Client disconnected: {client_id}");

        if let Some(ref webhook) = state_clone.webhook {
            webhook.emit(WebhookEvent::peer_disconnected(&client_id));
        }
    }

    // Abort the writer task.
    writer.abort();
}

/// Deliver queued messages from Redis to a newly connected/reconnected client.
async fn deliver_queued_messages(state: &AppState, id: &str, tx: &mpsc::UnboundedSender<String>) {
    let messages = redis_realm::read_all_messages(&state.redis, id)
        .await
        .unwrap_or_default();

    if messages.is_empty() {
        return;
    }

    for msg_json in &messages {
        // Re-route each message through the transmission handler so it goes
        // through the same path as a live message (handles failures correctly).
        if let Ok(msg) = serde_json::from_str::<Message>(msg_json) {
            let data = serde_json::to_string(&msg).unwrap_or_default();
            if tx.send(data).is_err() {
                break;
            }
        }
    }

    let _ = redis_realm::clear_message_queue(&state.redis, id).await;
}

/// Send an error message and close the socket (pre-split).
async fn send_error_and_close(socket: WebSocket, error: &PeerError) {
    let (mut sink, _) = socket.split();
    let error_json = make_error_json(error);
    let _ = futures::SinkExt::send(&mut sink, WsMessage::Text(error_json)).await;
    let _ = futures::SinkExt::close(&mut sink).await;
}
