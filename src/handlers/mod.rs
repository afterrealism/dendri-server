// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2025-2026 Dendri contributors

pub mod admin;
pub mod api;
pub mod customer;
pub mod http;
pub mod message;
pub mod ws;

use crate::state::AppState;
use crate::tenant::Tenant;

/// Why a connection's JWT check failed. Callers map this to their transport's
/// rejection response (WS close frame vs HTTP 403).
pub enum AuthReject {
    InvalidToken,
}

/// Enforce the connection JWT rule for a signaling transport.
///
/// Per the precedence rule, the effective secret is the resolved tenant's
/// `jwt_secret` when set, else the global `config.jwt_secret`; when neither
/// is set, JWT is not enforced. On success the verified claims are stored in
/// `state.client_claims` keyed by `client_id`, which the `ROOM-JOIN` gate in
/// message.rs then applies.
pub async fn enforce_jwt(
    state: &AppState,
    resolved_tenant: Option<&Tenant>,
    jwt_param: Option<&str>,
    client_id: &str,
) -> Result<(), AuthReject> {
    let effective_secret = crate::jwt::effective_jwt_secret(
        resolved_tenant.and_then(|t| t.jwt_secret.as_deref()),
        state.config.jwt_secret.as_deref(),
    );
    let Some(secret) = effective_secret else {
        return Ok(());
    };

    let jwt_token = jwt_param.unwrap_or("");
    match crate::jwt::validate_jwt(secret, jwt_token) {
        Ok(claims) => {
            if let Some(t) = resolved_tenant {
                if !crate::jwt::tid_matches(&claims, &t.id) {
                    tracing::warn!(client = %client_id, tenant = %t.id, "JWT tid mismatch");
                    return Err(AuthReject::InvalidToken);
                }
            }
            tracing::debug!(client = %client_id, claims = ?claims, "JWT validated");
            state.client_claims.insert(client_id.to_string(), claims);
            Ok(())
        }
        Err(e) => {
            tracing::warn!(client = %client_id, error = %e, "JWT validation failed");
            Err(AuthReject::InvalidToken)
        }
    }
}
