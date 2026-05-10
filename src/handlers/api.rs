// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2025-2026 Dendri contributors

use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::Engine as _;
use hmac::{Hmac, Mac};
use serde::Deserialize;
use serde_json::{json, Value};
use sha1::Sha1;

use crate::redis_realm;
use crate::state::AppState;

type HmacSha1 = Hmac<Sha1>;

/// GET /health — server health check with runtime stats.
pub async fn health(State(state): State<AppState>) -> Json<serde_json::Value> {
    let uptime_ms = state.start_time.elapsed().as_millis() as u64;
    Json(json!({
        "status": "ok",
        "clients": state.clients.len(),
        "rooms": state.rooms.len(),
        "uptime_ms": uptime_ms,
        "relay_enabled": state.config.enable_relay
    }))
}

/// GET / — server metadata (matches app.json from the TS server).
pub async fn root() -> Json<serde_json::Value> {
    Json(json!({
        "name": "Dendri Server",
        "description": "A signaling server to broker connections between Dendri clients.",
        "website": "https://github.com/nicholasgasior/dendri",
        "license": "AGPL-3.0-only",
        "source": "https://github.com/afterrealism/dendri-server"
    }))
}

/// GET /:key/id — generate a unique peer ID.
/// Returns text/html content type to match the TS server behavior.
pub async fn get_id(Path(key): Path<String>, State(state): State<AppState>) -> Response {
    if key != state.config.key {
        return StatusCode::UNAUTHORIZED.into_response();
    }

    let result = redis_realm::generate_client_id(&state.redis)
        .await
        .map_err(|e| e.to_string());

    match result {
        Ok(id) => (StatusCode::OK, [("content-type", "text/html")], id).into_response(),
        Err(e) => {
            tracing::error!("Error generating client ID: {e}");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// Query parameters for the peers endpoint.
#[derive(Debug, Deserialize)]
pub struct PeersQuery {
    /// If provided, only return peers in this room.
    pub room: Option<String>,
    /// If `--discovery-token` is configured, callers must pass `?token=<value>`.
    pub token: Option<String>,
}

/// GET /:key/peers — list connected peer IDs (requires allow_discovery).
/// If `?room=NAME` is provided, returns only peers in that room.
/// If `--discovery-token` is configured, the caller must also pass `?token=<value>`.
pub async fn get_peers(
    Path(key): Path<String>,
    Query(params): Query<PeersQuery>,
    State(state): State<AppState>,
) -> Response {
    if key != state.config.key {
        return StatusCode::UNAUTHORIZED.into_response();
    }

    if !state.config.allow_discovery {
        return StatusCode::UNAUTHORIZED.into_response();
    }

    // If a discovery token is configured, the caller must provide it.
    if let Some(ref expected) = state.config.discovery_token {
        match params.token {
            Some(ref provided) if provided == expected => {}
            _ => return StatusCode::UNAUTHORIZED.into_response(),
        }
    }

    // If a room is specified, return only peers in that room.
    if let Some(ref room_name) = params.room {
        let members: Vec<String> = state
            .rooms
            .get(room_name)
            .map(|m| m.iter().cloned().collect())
            .unwrap_or_default();
        return Json(members).into_response();
    }

    // No room filter — return all connected peers (backward compatible).
    let result = redis_realm::get_all_client_ids(&state.redis)
        .await
        .map_err(|e| e.to_string());

    match result {
        Ok(ids) => Json(ids).into_response(),
        Err(e) => {
            tracing::error!("Error listing peers: {e}");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// Query parameters for the TURN credentials endpoint.
#[derive(Debug, Deserialize)]
pub struct TurnQuery {
    /// Optional peer ID to embed in the TURN username.
    /// If omitted, defaults to "dendri" (backward compatible).
    pub peer_id: Option<String>,
}

/// GET /turn — backward-compatible alias for `GET /:key/turn-credentials`.
///
/// Uses the server's configured key so clients that hit the flat `/turn` path
/// (e.g. older SDK versions, e2e tests) still get credentials.
pub async fn turn_credentials_root(
    Query(query): Query<TurnQuery>,
    State(state): State<AppState>,
) -> Response {
    let key = state.config.key.clone();
    turn_credentials(Path(key), Query(query), State(state)).await
}

/// GET /:key/turn-credentials — generate ephemeral TURN credentials.
///
/// Returns ICE server config with HMAC-SHA1 credentials compatible with
/// coturn's `lt-cred-mech`. Only available when `turn_secret` is configured.
///
/// The TURN username embeds a per-peer identifier (RFC 7635 convention)
/// so stolen credentials are tied to a specific client, not reusable
/// across all peers with the shared key.
pub async fn turn_credentials(
    Path(key): Path<String>,
    Query(query): Query<TurnQuery>,
    State(state): State<AppState>,
) -> Response {
    if key != state.config.key {
        return StatusCode::UNAUTHORIZED.into_response();
    }

    let peer_id = query.peer_id.as_deref().unwrap_or("dendri");

    let secret = match &state.config.turn_secret {
        Some(s) => s,
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error": "TURN not configured"})),
            )
                .into_response();
        }
    };

    let ttl = 86400u64; // 24 hours
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        + ttl;
    let username = format!("{timestamp}:{peer_id}");

    // HMAC-SHA1 credential (matches coturn lt-cred-mech).
    let credential = match HmacSha1::new_from_slice(secret.as_bytes()) {
        Ok(mut mac) => {
            mac.update(username.as_bytes());
            base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes())
        }
        Err(_) => {
            tracing::error!("Invalid TURN secret key length");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let ice_servers: Vec<Value> = state
        .config
        .turn_servers
        .iter()
        .map(|url| {
            json!({
                "urls": url,
                "username": username,
                "credential": credential,
            })
        })
        .collect();

    tracing::debug!(
        peer_id = %peer_id,
        username = %username,
        server_count = ice_servers.len(),
        ttl_secs = ttl,
        "TURN credentials issued"
    );

    (
        StatusCode::OK,
        Json(json!({ "iceServers": ice_servers, "ttl": ttl })),
    )
        .into_response()
}
