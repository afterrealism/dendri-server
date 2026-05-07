use std::sync::atomic::Ordering;
use std::time::Instant;

use crate::enums::{MessageType, PeerError};
use crate::models::message::Message;
use crate::redis_realm;
use crate::state::{AppState, PendingRemoval};
use crate::validation::is_valid_identifier;
use crate::webhook::WebhookEvent;

/// Handle an incoming message from a client.
/// Dispatches to heartbeat, transmission, relay, or room operations based on message type.
pub async fn handle_message(state: &AppState, client_id: &str, mut msg: Message) {
    // Overwrite src to prevent spoofing.
    msg.src = Some(client_id.to_string());

    match msg.type_ {
        MessageType::HEARTBEAT => handle_heartbeat(state, client_id).await,
        MessageType::OFFER
        | MessageType::ANSWER
        | MessageType::CANDIDATE
        | MessageType::ACK
        | MessageType::LEAVE
        | MessageType::EXPIRE => handle_transmission(state, client_id, msg).await,
        MessageType::DATA => handle_data(state, client_id, msg).await,
        MessageType::RoomJoin => handle_room_join(state, client_id, msg).await,
        MessageType::RoomLeave => handle_room_leave(state, client_id, msg).await,
        MessageType::PresenceUpdate => handle_presence_update(state, client_id, msg).await,
        _ => {
            tracing::warn!("Unhandled message type from {client_id}: {:?}", msg.type_);
        }
    }
}

/// Heartbeat: update last_ping in the in-memory cache (no Redis round-trip).
/// A background task periodically syncs these values to Redis.
async fn handle_heartbeat(state: &AppState, client_id: &str) {
    if let Some(meta) = state.clients.get(client_id) {
        meta.touch();
    }
}

/// Manually serialize a relay message to JSON, avoiding serde overhead.
/// Peer IDs are alphanumeric tokens (safe ASCII), so no JSON escaping needed.
/// The payload is already valid JSON from RawValue.
fn serialize_relay(msg: &Message) -> String {
    let type_str = msg.type_.as_str();
    let src = msg.src.as_deref().unwrap_or("");
    let dst = msg.dst.as_deref().unwrap_or("");

    // Estimate capacity: {"type":"TYPE","src":"...","dst":"...","payload":...,"seq":N,"room":"...","timestamp":N}
    let payload_len = msg.payload.as_ref().map_or(0, |p| p.get().len());
    let room_len = msg.room.as_ref().map_or(0, |r| r.len());
    let capacity = 80 + type_str.len() + src.len() + dst.len() + payload_len + room_len;

    let mut out = String::with_capacity(capacity);
    out.push_str(r#"{"type":""#);
    out.push_str(type_str);
    out.push('"');

    if !src.is_empty() {
        out.push_str(r#","src":""#);
        out.push_str(src);
        out.push('"');
    }

    if !dst.is_empty() {
        out.push_str(r#","dst":""#);
        out.push_str(dst);
        out.push('"');
    }

    if let Some(ref payload) = msg.payload {
        out.push_str(r#","payload":"#);
        out.push_str(payload.get());
    }

    if let Some(seq) = msg.seq {
        out.push_str(r#","seq":"#);
        // itoa-style manual number formatting for hot path
        let mut buf = itoa::Buffer::new();
        out.push_str(buf.format(seq));
    }

    if let Some(ref room) = msg.room {
        out.push_str(r#","room":""#);
        out.push_str(room);
        out.push('"');
    }

    if let Some(ts) = msg.timestamp {
        out.push_str(r#","timestamp":"#);
        let mut buf = itoa::Buffer::new();
        out.push_str(buf.format(ts));
    }

    out.push('}');
    out
}

/// Transmission: route messages between peers.
/// If destination is online, forward directly. If offline, queue (except LEAVE/EXPIRE).
/// LEAVE with empty dst removes the source client.
async fn handle_transmission(state: &AppState, _client_id: &str, msg: Message) {
    let src_id = msg.src.as_deref().unwrap_or("");
    let dst_id = msg.dst.as_deref().unwrap_or("");
    let msg_type = msg.type_;

    if !dst_id.is_empty() {
        // Serialize before acquiring any lock.
        let data = serialize_relay(&msg);

        // Try to send to destination directly via in-memory sender.
        if let Some(sender) = state.ws_senders.get(dst_id) {
            if sender.send(data).is_err() {
                // Sender channel closed — peer's writer task is dead.
                let dst_owned = dst_id.to_string();
                drop(sender);
                state.ws_senders.remove(&dst_owned);
                if state.clients.remove(&dst_owned).is_some() {
                    state.release_connection_slot();
                }
                let _ = redis_realm::remove_client(&state.redis, dst_id).await;

                // Send LEAVE back to source (not recursive — direct send).
                send_leave_to_source(state, dst_id, src_id).await;
            }
        } else {
            // Destination not online in this instance.
            // Check in-memory cache first (no Redis round-trip).
            let exists = state.clients.contains_key(dst_id);

            if exists {
                // Client registered but not on this instance — queue the message.
                if !matches!(msg_type, MessageType::LEAVE | MessageType::EXPIRE) {
                    queue_message_raw(state, dst_id, &data).await;
                }
            } else {
                // Destination truly offline — queue important messages.
                if !matches!(msg_type, MessageType::LEAVE | MessageType::EXPIRE) {
                    queue_message_raw(state, dst_id, &data).await;
                }
            }
        }
    } else if msg_type == MessageType::LEAVE {
        // LEAVE with empty dst: remove the source client.
        let src_owned = src_id.to_string();
        state.ws_senders.remove(&src_owned);
        if state.clients.remove(&src_owned).is_some() {
            state.release_connection_slot();
        }
        let _ = redis_realm::remove_client(&state.redis, src_id).await;
    }
}

/// Send a LEAVE message from `from_id` to `to_id` to notify the source
/// that the destination is gone. Uses a direct channel send (no recursion).
async fn send_leave_to_source(state: &AppState, from_id: &str, to_id: &str) {
    let leave_msg = Message {
        type_: MessageType::LEAVE,
        src: Some(from_id.to_string()),
        dst: Some(to_id.to_string()),
        payload: None,
        seq: None,
        room: None,
        topic_class: None,
        timestamp: None,
    };
    let data = serialize_relay(&leave_msg);

    if let Some(sender) = state.ws_senders.get(to_id) {
        let _ = sender.send(data);
    }
}

/// Queue a pre-serialized message in Redis for later delivery.
async fn queue_message_raw(state: &AppState, dst_id: &str, json_str: &str) {
    if let Err(e) = redis_realm::add_message_to_queue(&state.redis, dst_id, json_str).await {
        tracing::error!("Redis error queuing message for {dst_id}: {e}");
    }
}

/// Handle a DATA message: relay to destination peer or fan-out to a room.
/// Only works when `enable_relay` is true.
async fn handle_data(state: &AppState, client_id: &str, mut msg: Message) {
    if !state.config.enable_relay {
        if let Some(sender) = state.ws_senders.get(client_id) {
            let _ = sender.send(
                r#"{"type":"ERROR","payload":{"msg":"Relay not enabled on this server"}}"#
                    .to_string(),
            );
        }
        return;
    }

    // Room name is interpolated into the relayed frame; reject malformed
    // rooms rather than letting them reach the hand-built serializer.
    if let Some(ref room_name) = msg.room {
        if !is_valid_identifier(room_name) {
            return;
        }
    }
    if let Some(ref dst) = msg.dst {
        if !is_valid_identifier(dst) {
            return;
        }
    }

    // Assign server-side sequence number and timestamp.
    let seq = state.seq_counter.fetch_add(1, Ordering::Relaxed) + 1;
    msg.seq = Some(seq);
    msg.timestamp = Some(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64,
    );

    tracing::debug!(src = %client_id, dst = ?msg.dst, room = ?msg.room, seq = ?msg.seq, "DATA relay");

    let data = serialize_relay(&msg);

    if let Some(ref room_name) = msg.room {
        // Room fan-out: send to all members except sender.
        if let Some(members) = state.rooms.get(room_name) {
            for member_id in members.iter() {
                if member_id.as_str() != client_id {
                    if let Some(sender) = state.ws_senders.get(member_id.as_str()) {
                        let _ = sender.send(data.clone());
                    }
                }
            }
        }
        // H6: Ephemeral messages skip replay buffer (cursor/typing)
        if msg.topic_class.as_deref() != Some("ephemeral") {
            state.replay_buffer.push(room_name, seq, data);
        }
    } else if let Some(ref dst_id) = msg.dst {
        // Point-to-point relay.
        if let Some(sender) = state.ws_senders.get(dst_id.as_str()) {
            let _ = sender.send(data.clone());
        }
        if msg.topic_class.as_deref() != Some("ephemeral") {
            state.replay_buffer.push(dst_id, seq, data);
        }
    }
}

/// Handle ROOM_JOIN: add client to room, send ROOM_PEERS response.
async fn handle_room_join(state: &AppState, client_id: &str, msg: Message) {
    let room_name = match msg.room {
        Some(ref name) => name.clone(),
        None => return,
    };

    // Room names are interpolated into hand-built JSON (ROOM-PEERS,
    // PRESENCE-UPDATE, DATA fan-out). Reject anything that could break
    // the JSON framing before it reaches the serializer.
    if !is_valid_identifier(&room_name) {
        if let Some(sender) = state.ws_senders.get(client_id) {
            let _ = sender
                .send(r#"{"type":"ERROR","payload":{"msg":"Invalid room name"}}"#.to_string());
        }
        return;
    }

    // Check room access control (if JWT claims exist for this client).
    if let Some(claims) = state.client_claims.get(client_id) {
        if let Some(allowed_rooms) = claims.get("rooms") {
            if let Some(rooms_array) = allowed_rooms.as_array() {
                let room_allowed = rooms_array.iter().any(|r| r.as_str() == Some(&room_name));
                if !room_allowed {
                    let error =
                        r#"{"type":"ERROR","payload":{"msg":"Not authorized to join this room"}}"#;
                    if let Some(sender) = state.ws_senders.get(client_id) {
                        let _ = sender.send(error.to_string());
                    }
                    return;
                }
            }
        }
        // If no "rooms" claim, all rooms are allowed (backward compat).
    }
    // If no claims at all (no JWT), all rooms are allowed (backward compat).

    // Enforce max_room_size (0 means unlimited).
    let max_size = state.config.max_room_size;
    if max_size > 0 {
        if let Some(members) = state.rooms.get(&room_name) {
            if members.len() >= max_size {
                let error = r#"{"type":"ERROR","payload":{"msg":"Room is full"}}"#;
                if let Some(sender) = state.ws_senders.get(client_id) {
                    let _ = sender.send(error.to_string());
                }
                return;
            }
        }
    }

    // Add client to room.
    state
        .rooms
        .entry(room_name.clone())
        .or_default()
        .insert(client_id.to_string());

    // Update reverse index.
    state
        .client_rooms
        .entry(client_id.to_string())
        .or_default()
        .insert(room_name.clone());

    // Build member list.
    let members: Vec<String> = state
        .rooms
        .get(&room_name)
        .map(|m| m.iter().cloned().collect())
        .unwrap_or_default();

    // Send ROOM_PEERS to the joining client.
    let peers_json = serde_json::to_string(&members).unwrap_or_else(|_| "[]".to_string());
    let response = format!(
        r#"{{"type":"ROOM-PEERS","room":"{}","payload":{}}}"#,
        room_name, peers_json
    );
    if let Some(sender) = state.ws_senders.get(client_id) {
        let _ = sender.send(response);
    }

    // Send existing presence data to the new joiner.
    if let Some(room_presence) = state.presence.get(&room_name) {
        for entry in room_presence.iter() {
            let presence_msg = format!(
                r#"{{"type":"PRESENCE-UPDATE","src":"{}","room":"{}","payload":{}}}"#,
                entry.key(),
                room_name,
                entry.value()
            );
            if let Some(sender) = state.ws_senders.get(client_id) {
                let _ = sender.send(presence_msg);
            }
        }
    }

    tracing::info!(
        "Client {client_id} joined room {room_name} ({} members)",
        members.len()
    );

    if let Some(ref webhook) = state.webhook {
        webhook.emit(WebhookEvent::room_joined(client_id, &room_name));
    }
}

/// Handle PRESENCE_UPDATE: store presence data and fan-out to all room members.
async fn handle_presence_update(state: &AppState, client_id: &str, msg: Message) {
    let room_name = match msg.room {
        Some(ref name) => name.clone(),
        None => return,
    };

    if !is_valid_identifier(&room_name) {
        return;
    }

    tracing::debug!(src = %client_id, room = %room_name, "Presence update");

    // Store presence data.
    if let Some(ref payload) = msg.payload {
        state
            .presence
            .entry(room_name.clone())
            .or_default()
            .insert(client_id.to_string(), payload.get().to_string());
    }

    // Fan-out to all room members (except sender).
    let data = serialize_relay(&msg);
    if let Some(members) = state.rooms.get(&room_name) {
        for member_id in members.iter() {
            if member_id.as_str() != client_id {
                if let Some(sender) = state.ws_senders.get(member_id.as_str()) {
                    let _ = sender.send(data.clone());
                }
            }
        }
    }
}

/// Handle ROOM_LEAVE: remove client from room, notify remaining members.
async fn handle_room_leave(state: &AppState, client_id: &str, msg: Message) {
    let room_name = match msg.room {
        Some(ref name) => name.clone(),
        None => return,
    };

    // Defensive: reject malformed names so we never emit them in ROOM-PEERS.
    if !is_valid_identifier(&room_name) {
        return;
    }

    remove_client_from_room(state, client_id, &room_name);
    tracing::info!("Client {client_id} left room {room_name}");

    if let Some(ref webhook) = state.webhook {
        webhook.emit(WebhookEvent::room_left(client_id, &room_name));
    }
}

/// Remove a client from a specific room and notify remaining members.
/// Deletes the room if it becomes empty.
pub fn remove_client_from_room(state: &AppState, client_id: &str, room_name: &str) {
    // Remove from room member set.
    let room_empty = {
        if let Some(mut members) = state.rooms.get_mut(room_name) {
            members.remove(client_id);
            members.is_empty()
        } else {
            return;
        }
    };

    // Clean up presence data for this client.
    if let Some(room_presence) = state.presence.get(room_name) {
        room_presence.remove(client_id);
    }

    if room_empty {
        state.rooms.remove(room_name);
        // Clean up the presence map for the empty room.
        state.presence.remove(room_name);
    } else {
        // Notify remaining members with updated peer list.
        if let Some(members) = state.rooms.get(room_name) {
            let member_list: Vec<String> = members.iter().cloned().collect();
            let peers_json =
                serde_json::to_string(&member_list).unwrap_or_else(|_| "[]".to_string());
            let notification = format!(
                r#"{{"type":"ROOM-PEERS","room":"{}","payload":{}}}"#,
                room_name, peers_json
            );
            for member_id in members.iter() {
                if let Some(sender) = state.ws_senders.get(member_id.as_str()) {
                    let _ = sender.send(notification.clone());
                }
            }
        }
    }

    // Update reverse index.
    if let Some(mut rooms) = state.client_rooms.get_mut(client_id) {
        rooms.remove(room_name);
    }
}

/// Remove a client from ALL rooms they were in. Called on disconnect.
///
/// When `session_ttl > 0`, room memberships are deferred: the client stays
/// in its rooms for a grace period so brief disconnections (network blips,
/// tab backgrounding) don't cause visible leave/rejoin churn.
/// If the client reconnects within the TTL, memberships are restored in ws.rs.
pub fn remove_client_from_all_rooms(state: &AppState, client_id: &str) {
    let session_ttl = state.config.session_ttl;

    if session_ttl == 0 {
        // Immediate removal (backward compatible).
        immediate_remove_from_all_rooms(state, client_id);
        return;
    }

    // Get the rooms this client is in.
    if let Some((_, rooms)) = state.client_rooms.remove(client_id) {
        let room_list: Vec<String> = rooms.into_iter().collect();
        if !room_list.is_empty() {
            // Don't remove from rooms yet -- schedule deferred removal.
            state.pending_removals.insert(
                client_id.to_string(),
                PendingRemoval {
                    rooms: room_list,
                    disconnected_at: Instant::now(),
                },
            );
        }
    }
    state.replay_buffer.remove_client(client_id);
}

/// Immediate room removal -- the original logic before session TTL was added.
fn immediate_remove_from_all_rooms(state: &AppState, client_id: &str) {
    if let Some((_, rooms)) = state.client_rooms.remove(client_id) {
        for room_name in rooms {
            remove_client_from_room(state, client_id, &room_name);
        }
    }
    state.replay_buffer.remove_client(client_id);
}

/// Remove clients whose session TTL has expired from all their pending rooms.
/// Called periodically from the check_broken background task.
pub fn cleanup_expired_sessions(state: &AppState) {
    if state.config.session_ttl == 0 {
        return;
    }
    let ttl = std::time::Duration::from_millis(state.config.session_ttl);
    let now = Instant::now();

    let expired: Vec<String> = state
        .pending_removals
        .iter()
        .filter(|e| now.duration_since(e.value().disconnected_at) >= ttl)
        .map(|e| e.key().clone())
        .collect();

    for client_id in expired {
        if let Some((_, pending)) = state.pending_removals.remove(&client_id) {
            let room_count = pending.rooms.len();
            for room_name in &pending.rooms {
                remove_client_from_room(state, &client_id, room_name);
            }
            tracing::info!("Session expired for {client_id}, removed from {room_count} rooms");
        }
    }
}

/// Send an error message to a client and close them.
/// Used for protocol-level errors (invalid key, limit exceeded, etc.).
pub fn make_error_json(error: &PeerError) -> String {
    let error_msg = error.as_str();
    // Manual serialization for error messages (cold path, but consistent).
    format!(r#"{{"type":"ERROR","payload":{{"msg":"{}"}}}}"#, error_msg)
}
