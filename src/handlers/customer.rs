// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2025-2026 Dendri contributors

//! Customer-facing API for the self-serve dashboard (app.dendri.dev).
//!
//! Two sign-in paths, both yielding a 7-day **session JWT** (HS256, signed with
//! the server's admin token) that the dashboard sends as `Authorization: Bearer`:
//!   1. API key — `POST /auth/login` exchanges a tenant's `dk_` key for a session.
//!   2. Email magic-link — `POST /auth/request` emails a 15-min link (DirectMail);
//!      `POST /auth/magic` exchanges that link's token for a session.
//! The JWT `purpose` claim ("session" vs "magic") stops a magic token from being
//! used as a session. Mounted only when `--admin-token` is set (the signing key).

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::state::AppState;
use crate::tenant;

/// Session lifetime: 7 days.
const SESSION_TTL_SECS: u64 = 7 * 24 * 60 * 60;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/auth/login", post(login))
        .route("/auth/request", post(request_magic_link))
        .route("/auth/magic", post(exchange_magic))
        .route("/me", get(me))
        .route("/me/rotate-key", post(rotate_key))
}

/// Magic-link lifetime: 15 minutes.
const MAGIC_TTL_SECS: u64 = 15 * 60;

#[derive(Debug, Serialize, Deserialize)]
struct SessionClaims {
    /// Tenant id.
    sub: String,
    /// "session" (dashboard bearer) or "magic" (one-time login link).
    #[serde(default)]
    purpose: String,
    exp: usize,
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn sign_token(secret: &str, tenant_id: &str, purpose: &str, ttl: u64) -> Option<String> {
    let claims = SessionClaims {
        sub: tenant_id.to_string(),
        purpose: purpose.to_string(),
        exp: (now_secs() + ttl) as usize,
    };
    jsonwebtoken::encode(
        &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256),
        &claims,
        &jsonwebtoken::EncodingKey::from_secret(secret.as_bytes()),
    )
    .ok()
}

fn decode_token(secret: &str, token: &str) -> Option<SessionClaims> {
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256);
    validation.required_spec_claims.insert("exp".to_string());
    jsonwebtoken::decode::<SessionClaims>(
        token,
        &jsonwebtoken::DecodingKey::from_secret(secret.as_bytes()),
        &validation,
    )
    .ok()
    .map(|d| d.claims)
}

fn signing_secret(state: &AppState) -> Option<&str> {
    state.config.admin_token.as_deref()
}

fn sign_session(secret: &str, tenant_id: &str) -> Option<String> {
    sign_token(secret, tenant_id, "session", SESSION_TTL_SECS)
}

/// Return the authenticated tenant id from the `Authorization: Bearer` session,
/// or a boxed 401 response. (Boxed to keep the Err variant small.) Only accepts
/// `purpose: "session"` tokens — a magic-link token can't be used as a session.
fn session_tenant_id(state: &AppState, headers: &HeaderMap) -> Result<String, Box<Response>> {
    let unauthorized = || {
        Box::new(
            (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "unauthorized"})),
            )
                .into_response(),
        )
    };
    let secret = signing_secret(state).ok_or_else(unauthorized)?;
    let token = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or_else(unauthorized)?;

    match decode_token(secret, token) {
        Some(claims) if claims.purpose == "session" => Ok(claims.sub),
        _ => Err(unauthorized()),
    }
}

/// Tenant view returned to the dashboard (never includes key material).
fn tenant_view(t: &tenant::Tenant) -> serde_json::Value {
    json!({
        "id": t.id,
        "name": t.name,
        "email": t.email,
        "active": t.active,
        "max_rooms": t.max_rooms,
        "max_peers": t.max_peers,
    })
}

#[derive(Debug, Deserialize)]
struct LoginRequest {
    api_key: String,
}

/// POST /auth/login — exchange an API key for a session token.
async fn login(State(state): State<AppState>, Json(req): Json<LoginRequest>) -> Response {
    let Some(secret) = signing_secret(&state).map(str::to_owned) else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "dashboard not configured"})),
        )
            .into_response();
    };

    let tenant =
        match tenant::resolve_api_key(&state.redis, &state.tenant_cache, &req.api_key).await {
            Some(t) => t,
            None => {
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(json!({"error": "invalid api key"})),
                )
                    .into_response();
            }
        };

    match sign_session(&secret, &tenant.id) {
        Some(token) => (
            StatusCode::OK,
            Json(json!({"token": token, "tenant": tenant_view(&tenant)})),
        )
            .into_response(),
        None => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "could not issue session"})),
        )
            .into_response(),
    }
}

#[derive(Debug, Deserialize)]
struct EmailRequest {
    email: String,
}

/// POST /auth/request — email a one-time magic-link login. Always returns 200
/// (never reveals whether an email is registered). Sends only when the email
/// maps to a tenant and DirectMail is configured.
async fn request_magic_link(
    State(state): State<AppState>,
    Json(req): Json<EmailRequest>,
) -> Response {
    let generic = || {
        (
            StatusCode::OK,
            Json(json!({"message": "If that email has an account, a login link is on its way."})),
        )
            .into_response()
    };

    let (Some(secret), Some(mailer)) = (
        signing_secret(&state).map(str::to_owned),
        state.mailer.clone(),
    ) else {
        return generic();
    };

    let email = req.email.trim().to_string();
    let tenant_id = match crate::tenant::get_tenant_id_by_email(&state.redis, &email).await {
        Ok(Some(id)) => id,
        _ => return generic(), // unknown email or lookup error — same response
    };

    if let Some(token) = sign_token(&secret, &tenant_id, "magic", MAGIC_TTL_SECS) {
        let link = format!(
            "{}/#magic={}",
            state.config.dashboard_url.trim_end_matches('/'),
            token
        );
        let html = format!(
            "<p>Click to sign in to your Dendri dashboard. This link expires in 15 minutes.</p>\
             <p><a href=\"{link}\">Sign in to Dendri</a></p>\
             <p>If you didn't request this, you can ignore this email.</p>"
        );
        // Fire-and-forget: don't block the response or leak send failures.
        tokio::spawn(async move {
            if let Err(e) = mailer.send(&email, "Sign in to Dendri", &html).await {
                tracing::error!(error = %e, "magic-link email send failed");
            }
        });
    }
    generic()
}

#[derive(Debug, Deserialize)]
struct MagicRequest {
    token: String,
}

/// POST /auth/magic — exchange a magic-link token for a session.
async fn exchange_magic(State(state): State<AppState>, Json(req): Json<MagicRequest>) -> Response {
    let Some(secret) = signing_secret(&state).map(str::to_owned) else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "dashboard not configured"})),
        )
            .into_response();
    };

    let claims = match decode_token(&secret, &req.token) {
        Some(c) if c.purpose == "magic" => c,
        _ => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "invalid or expired link"})),
            )
                .into_response();
        }
    };

    let tenant = match crate::tenant::get_tenant_by_id(&state.redis, &claims.sub).await {
        Ok(Some(t)) => t,
        _ => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "account not found"})),
            )
                .into_response();
        }
    };

    match sign_session(&secret, &tenant.id) {
        Some(token) => (
            StatusCode::OK,
            Json(json!({"token": token, "tenant": tenant_view(&tenant)})),
        )
            .into_response(),
        None => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "could not issue session"})),
        )
            .into_response(),
    }
}

/// GET /me — the signed-in tenant.
async fn me(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let tenant_id = match session_tenant_id(&state, &headers) {
        Ok(id) => id,
        Err(resp) => return *resp,
    };

    match tenant::get_tenant_by_id(&state.redis, &tenant_id).await {
        Ok(Some(t)) => (StatusCode::OK, Json(json!({"tenant": tenant_view(&t)}))).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "tenant not found"})),
        )
            .into_response(),
        Err(e) => {
            tracing::error!(error = %e, "me lookup failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "storage error"})),
            )
                .into_response()
        }
    }
}

/// POST /me/rotate-key — mint a new API key for the signed-in tenant. The old
/// key stops working; the new key is shown once.
async fn rotate_key(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let tenant_id = match session_tenant_id(&state, &headers) {
        Ok(id) => id,
        Err(resp) => return *resp,
    };

    match tenant::rotate_api_key(&state.redis, &tenant_id).await {
        Ok(Some(key)) => {
            state.tenant_cache.invalidate_all();
            (StatusCode::OK, Json(json!({"api_key": key}))).into_response()
        }
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "tenant not found"})),
        )
            .into_response(),
        Err(e) => {
            tracing::error!(error = %e, "rotate failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "storage error"})),
            )
                .into_response()
        }
    }
}
