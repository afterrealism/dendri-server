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
        jwt_secret: None,
    };
    let api_key = tenant::generate_api_key();

    match tenant::create_tenant(&state.redis, &tenant, &api_key).await {
        Ok(()) => {
            state.tenant_cache.invalidate_all();
            tracing::info!(tenant = %tenant.id, name = %tenant.name, "tenant created");
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
        Ok(tenants) => (StatusCode::OK, Json(json!({"tenants": tenants}))).into_response(),
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
