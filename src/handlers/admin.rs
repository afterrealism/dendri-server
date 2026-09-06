// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2025-2026 Dendri contributors

//! Admin API for tenant CRUD.
//!
//! Mounted only when `--admin-token` / `DENDRI_ADMIN_TOKEN` is configured;
//! every route requires `Authorization: Bearer <admin_token>`. The API key
//! for a tenant is returned exactly once, in the create response — only its
//! SHA-256 hash is persisted.

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::json;

use crate::state::AppState;
use crate::tenant::{self, Tenant};
use crate::validation::constant_time_str_eq;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/admin/tenants", post(create_tenant).get(list_tenants))
        .route("/admin/tenants/:id", delete(remove_tenant))
        .route(
            "/admin/tenants/:id/rotate-jwt-secret",
            post(rotate_jwt_secret),
        )
}

/// Returns `Some(rejection)` when the request is not authorized, `None` when it
/// may proceed. (Option rather than Result to avoid a large-Err variant.)
fn reject_unauthorized(state: &AppState, headers: &HeaderMap) -> Option<Response> {
    let expected = state.config.admin_token.as_deref().unwrap_or("");
    let provided = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .unwrap_or("");

    if expected.is_empty() || !constant_time_str_eq(provided, expected) {
        return Some(
            (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "unauthorized"})),
            )
                .into_response(),
        );
    }
    None
}

#[derive(Debug, Deserialize)]
pub struct CreateTenantRequest {
    pub name: String,
    #[serde(default)]
    pub origins: Vec<String>,
    #[serde(default)]
    pub max_rooms: usize,
    #[serde(default)]
    pub max_peers: usize,
    /// Billing/contact email — lets the customer sign in to the dashboard.
    #[serde(default)]
    pub email: Option<String>,
    /// Optional per-tenant JWT secret for room ACLs (hosted). Returned once,
    /// like the API key; if omitted the tenant can rotate one in later.
    #[serde(default)]
    pub jwt_secret: Option<String>,
}

/// Admin-facing tenant view for GET responses: everything except key
/// material. The raw `jwt_secret` is never serialized — only a presence flag.
#[derive(Debug, serde::Serialize)]
struct TenantView {
    id: String,
    name: String,
    origins: Vec<String>,
    active: bool,
    max_rooms: usize,
    max_peers: usize,
    email: Option<String>,
    has_jwt_secret: bool,
}

impl From<&Tenant> for TenantView {
    fn from(t: &Tenant) -> Self {
        Self {
            id: t.id.clone(),
            name: t.name.clone(),
            origins: t.origins.clone(),
            active: t.active,
            max_rooms: t.max_rooms,
            max_peers: t.max_peers,
            email: t.email.clone(),
            has_jwt_secret: t.jwt_secret.is_some(),
        }
    }
}

/// POST /admin/tenants — create a tenant and mint its API key.
async fn create_tenant(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CreateTenantRequest>,
) -> Response {
    if let Some(resp) = reject_unauthorized(&state, &headers) {
        return resp;
    }

    let name = req.name.trim();
    if name.is_empty() {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({"error": "name is required"})),
        )
            .into_response();
    }

    let tenant = Tenant {
        id: tenant::generate_tenant_id(),
        name: name.to_string(),
        origins: req.origins,
        active: true,
        max_rooms: req.max_rooms,
        max_peers: req.max_peers,
        email: req.email,
        jwt_secret: req.jwt_secret,
    };
    let api_key = tenant::generate_api_key();

    match tenant::create_tenant(&state.redis, &tenant, &api_key).await {
        Ok(()) => {
            state.tenant_cache.invalidate_all();
            tracing::info!(tenant = %tenant.id, name = %tenant.name, "tenant created");
            // The tenant blob echoes jwt_secret here and only here — the same
            // "shown once" contract as api_key. Later GETs go through
            // TenantView, which exposes has_jwt_secret only.
            (
                StatusCode::CREATED,
                Json(json!({"tenant": tenant, "api_key": api_key})),
            )
                .into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, "tenant create failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "storage error"})),
            )
                .into_response()
        }
    }
}

/// GET /admin/tenants — list tenants (never returns keys or hashes).
async fn list_tenants(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Some(resp) = reject_unauthorized(&state, &headers) {
        return resp;
    }

    match tenant::list_tenants(&state.redis).await {
        Ok(tenants) => {
            let views: Vec<TenantView> = tenants.iter().map(TenantView::from).collect();
            (StatusCode::OK, Json(json!({"tenants": views}))).into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, "tenant list failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "storage error"})),
            )
                .into_response()
        }
    }
}

/// DELETE /admin/tenants/:id — revoke a tenant. Existing connections drop at
/// their next authenticated request; new connections fail within one cache TTL.
async fn remove_tenant(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    if let Some(resp) = reject_unauthorized(&state, &headers) {
        return resp;
    }

    match tenant::delete_tenant(&state.redis, &id).await {
        Ok(true) => {
            state.tenant_cache.invalidate_all();
            tracing::info!(tenant = %id, "tenant deleted");
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "unknown tenant"})),
        )
            .into_response(),
        Err(e) => {
            tracing::error!(error = %e, "tenant delete failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "storage error"})),
            )
                .into_response()
        }
    }
}

/// POST /admin/tenants/:id/rotate-jwt-secret — mint a fresh JWT secret for a
/// tenant. The new secret is returned exactly once, like the API key at
/// create; the old secret stops verifying immediately after cache
/// invalidation.
async fn rotate_jwt_secret(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    if let Some(resp) = reject_unauthorized(&state, &headers) {
        return resp;
    }

    let mut tenant = match tenant::get_tenant_by_id(&state.redis, &id).await {
        Ok(Some(t)) => t,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "unknown tenant"})),
            )
                .into_response();
        }
        Err(e) => {
            tracing::error!(error = %e, "tenant load failed");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "storage error"})),
            )
                .into_response();
        }
    };

    let new_secret = tenant::generate_jwt_secret();
    tenant.jwt_secret = Some(new_secret.clone());

    match tenant::update_tenant(&state.redis, &tenant).await {
        Ok(true) => {
            state.tenant_cache.invalidate_all();
            tracing::info!(tenant = %id, "tenant JWT secret rotated");
            (StatusCode::OK, Json(json!({"jwt_secret": new_secret}))).into_response()
        }
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "unknown tenant"})),
        )
            .into_response(),
        Err(e) => {
            tracing::error!(error = %e, "tenant JWT secret rotation failed");
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

    fn tenant_with_secret() -> Tenant {
        Tenant {
            id: "t_1".into(),
            name: "Acme".into(),
            origins: vec![],
            active: true,
            max_rooms: 0,
            max_peers: 0,
            email: None,
            jwt_secret: Some("tenant-secret".into()),
        }
    }

    #[test]
    fn create_request_accepts_optional_jwt_secret() {
        let body = r#"{"name":"Acme","jwt_secret":"s3cret"}"#;
        let req: CreateTenantRequest = serde_json::from_str(body).unwrap();
        assert_eq!(req.jwt_secret.as_deref(), Some("s3cret"));
        let body = r#"{"name":"Acme"}"#;
        let req: CreateTenantRequest = serde_json::from_str(body).unwrap();
        assert_eq!(req.jwt_secret, None);
    }

    #[test]
    fn tenant_view_hides_jwt_secret() {
        let view = TenantView::from(&tenant_with_secret());
        let json = serde_json::to_value(&view).unwrap();
        assert_eq!(json["has_jwt_secret"], true);
        assert!(json.get("jwt_secret").is_none());

        let bare = TenantView::from(&Tenant {
            jwt_secret: None,
            ..tenant_with_secret()
        });
        let json = serde_json::to_value(&bare).unwrap();
        assert_eq!(json["has_jwt_secret"], false);
        assert!(json.get("jwt_secret").is_none());
    }
}
