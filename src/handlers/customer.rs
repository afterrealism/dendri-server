// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2025-2026 Dendri contributors

//! Customer-facing API for the self-serve dashboard (app.dendri.dev).
//!
//! Two sign-in paths, both yielding a 7-day **session JWT** (HS256, signed with
//! the server's admin token) that the dashboard sends as `Authorization: Bearer`:
//!
//!   1. API key — `POST /auth/login` exchanges a tenant's `dk_` key for a session.
//!   2. Email magic-link — `POST /auth/request` emails a 15-min link (DirectMail);
//!      `POST /auth/magic` exchanges that link's token for a session. An
//!      unregistered address gets a "no account — pick a plan or self-host"
//!      email instead (cooldown-limited), so the response stays generic and
//!      reveals nothing to enumeration.
//!
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

/// Cooldown for the "no account found" email: one per address per window, so
/// `POST /auth/request` can't be used to spam third parties.
const NO_ACCOUNT_COOLDOWN_SECS: u64 = 10 * 60;

/// Minimal shape check before an address is handed to the email API: one `@`
/// between non-empty local and domain parts, a dot in the domain, no
/// whitespace/control characters, sane length. Not RFC 5322 — DirectMail
/// rejects whatever this lets through, and this keeps junk out of the API.
fn plausible_email(email: &str) -> bool {
    if email.len() < 3 || email.len() > 254 {
        return false;
    }
    if email.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return false;
    }
    let Some((local, domain)) = email.split_once('@') else {
        return false;
    };
    !local.is_empty()
        && domain.contains('.')
        && !domain.contains('@')
        && !domain.starts_with('.')
        && !domain.ends_with('.')
}

/// Redis key for the no-account cooldown (mirrors the plaintext `tenant:email:`
/// key convention).
fn no_account_cooldown_key(email: &str) -> String {
    format!("auth:no-account:{}", email.to_ascii_lowercase())
}

/// Try to acquire the once-per-window send slot for a no-account email.
/// Returns false when a recent send is still cooling down *or* Redis errored —
/// fail closed: when in doubt, don't send.
async fn acquire_no_account_slot(redis: &redis::aio::ConnectionManager, email: &str) -> bool {
    let mut conn = redis.clone();
    let res: redis::RedisResult<Option<String>> = redis::cmd("SET")
        .arg(no_account_cooldown_key(email))
        .arg("1")
        .arg("EX")
        .arg(NO_ACCOUNT_COOLDOWN_SECS)
        .arg("NX")
        .query_async(&mut conn)
        .await;
    matches!(res, Ok(Some(_)))
}

/// Body of the "no account found" email: points the mailbox owner at the
/// pricing page (hosted plans) or the self-hosting guide (free forever).
fn no_account_email_html(website_url: &str, dashboard_url: &str) -> String {
    format!(
        "<p>You requested a sign-in link for the Dendri dashboard, but this email \
         address doesn't have a hosted account yet.</p>\
         <p><strong>To get one:</strong> choose a hosted plan on the \
         <a href=\"{website_url}/pricing/\">Dendri pricing page</a>. After checkout \
         your API key arrives by email, and you can sign in at the \
         <a href=\"{dashboard_url}\">Dendri dashboard</a> with this address.</p>\
         <p>Prefer to run it yourself? The Dendri server is open source and free \
         forever — follow the \
         <a href=\"{website_url}/docs/self-hosting/\">self-hosting guide</a>.</p>\
         <p>If you didn't request this, you can ignore this email.</p>"
    )
}

/// POST /auth/request — email a one-time magic-link login. Always returns 200
/// (never reveals whether an email is registered). A registered address gets a
/// login link; an unregistered address gets a "pick a plan or self-host" email
/// (at most one per cooldown window). Nothing is sent when DirectMail is not
/// configured or the address is junk.
async fn request_magic_link(
    State(state): State<AppState>,
    Json(req): Json<EmailRequest>,
) -> Response {
    let generic = || {
        (
            StatusCode::OK,
            Json(json!({"message": "Check your inbox for an email from Dendri."})),
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
    if !plausible_email(&email) {
        return generic(); // junk input — same response, nothing sent
    }

    match crate::tenant::get_tenant_id_by_email(&state.redis, &email).await {
        // Registered address → magic link (existing path).
        Ok(Some(tenant_id)) => {
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
                let mailer = mailer.clone();
                tokio::spawn(async move {
                    if let Err(e) = mailer.send(&email, "Sign in to Dendri", &html).await {
                        tracing::error!(error = %e, "magic-link email send failed");
                    }
                });
            }
        }
        // Unregistered address → tell the mailbox owner how to get an account.
        Ok(None) => {
            let redis = state.redis.clone();
            let website_url = state.config.website_url.trim_end_matches('/').to_string();
            let dashboard_url = state.config.dashboard_url.trim_end_matches('/').to_string();
            tokio::spawn(async move {
                if !acquire_no_account_slot(&redis, &email).await {
                    return; // a send is still cooling down — stay silent
                }
                let html = no_account_email_html(&website_url, &dashboard_url);
                match mailer
                    .send(&email, "Sign in to Dendri — no account found", &html)
                    .await
                {
                    Ok(()) => tracing::info!("no-account (get-a-plan) email sent"),
                    Err(e) => tracing::error!(error = %e, "no-account email send failed"),
                }
            });
        }
        // Lookup error → send nothing; same generic response.
        Err(_) => {}
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plausible_email_accepts_normal_addresses() {
        assert!(plausible_email("sheece.gardezi@afterrealism.com"));
        assert!(plausible_email("a@b.co"));
        assert!(plausible_email("first+tag@sub.example.org"));
    }

    #[test]
    fn plausible_email_rejects_junk() {
        assert!(!plausible_email(""));
        assert!(!plausible_email("no-at-sign"));
        assert!(!plausible_email("@no-local.com"));
        assert!(!plausible_email("no-domain@"));
        assert!(!plausible_email("no-dot@localhost"));
        assert!(!plausible_email("two@@example.com"));
        assert!(!plausible_email("spa ce@example.com"));
        assert!(!plausible_email("trailing@example.com "));
        assert!(!plausible_email("a@.example.com"));
        assert!(!plausible_email("a@example.com."));
        assert!(!plausible_email(&format!(
            "{}@example.com",
            "x".repeat(250)
        )));
    }

    #[test]
    fn cooldown_key_is_namespaced_and_lowercased() {
        assert_eq!(
            no_account_cooldown_key("Mixed@Example.COM"),
            "auth:no-account:mixed@example.com"
        );
    }

    #[test]
    fn no_account_email_points_at_pricing_and_self_hosting() {
        let html = no_account_email_html("https://dendri.dev", "https://app.dendri.dev");
        assert!(html.contains("https://dendri.dev/pricing/"));
        assert!(html.contains("https://dendri.dev/docs/self-hosting/"));
        assert!(html.contains("https://app.dendri.dev"));
        assert!(html.contains("doesn't have a hosted account"));
    }
}
