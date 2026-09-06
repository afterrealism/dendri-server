// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2025-2026 Dendri contributors

//! Tenant model for hosted multi-tenant deployments.
//!
//! API keys resolve to tenants via Redis (`tenant:key:{sha256(api_key)}`),
//! fronted by a short-TTL in-process cache so the connect path stays off
//! Redis. Keys are stored only as SHA-256 hashes; the plaintext key is
//! returned exactly once, at creation.
//!
//! Self-host deployments never touch this module: connections without an
//! `api_key` keep the legacy shared-key contract unless `--require-api-key`
//! is set.

use std::time::{Duration, Instant};

use dashmap::DashMap;
use redis::aio::ConnectionManager;
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Redis key holding a tenant JSON blob, keyed by API-key hash.
fn key_by_hash(hash: &str) -> String {
    format!("tenant:key:{hash}")
}

/// Redis key mapping a tenant id to its API-key hash (for admin delete).
fn key_by_id(id: &str) -> String {
    format!("tenant:id:{id}")
}

/// Redis key mapping a (lowercased) email to a tenant id, for dashboard login.
fn key_by_email(email: &str) -> String {
    format!("tenant:email:{}", email.trim().to_ascii_lowercase())
}

const CACHE_TTL: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Tenant {
    pub id: String,
    pub name: String,
    /// Allowed `Origin` header values. Empty = any origin.
    #[serde(default)]
    pub origins: Vec<String>,
    /// Suspended tenants keep their record but cannot connect.
    #[serde(default = "default_true")]
    pub active: bool,
    /// Per-tenant cap on distinct rooms (0 = server default applies).
    #[serde(default)]
    pub max_rooms: usize,
    /// Per-tenant cap on concurrent connections (0 = unlimited).
    #[serde(default)]
    pub max_peers: usize,
    /// Billing/contact email (set at checkout). Used for the customer dashboard.
    #[serde(default)]
    pub email: Option<String>,
    /// Per-tenant JWT secret for room ACLs (hosted). When set, connections
    /// presenting this tenant's API key must also present a `jwt` verified
    /// with this secret; the JWT's `rooms` claim gates room joins.
    /// Never serialized into GET/admin view responses.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwt_secret: Option<String>,
}

fn default_true() -> bool {
    true
}

/// SHA-256 hex of an API key — the only form ever persisted.
pub fn hash_api_key(api_key: &str) -> String {
    let digest = Sha256::digest(api_key.as_bytes());
    let mut out = String::with_capacity(64);
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// Generate a new API key: `dk_` + 32 hex chars (~122 bits of entropy).
pub fn generate_api_key() -> String {
    format!("dk_{}", uuid::Uuid::new_v4().simple())
}

/// Generate a new JWT secret: `jwt_` + 32 hex chars (~122 bits of entropy).
/// Unlike API keys this must be stored in plaintext — HMAC verification needs it.
pub fn generate_jwt_secret() -> String {
    format!("jwt_{}", uuid::Uuid::new_v4().simple())
}

/// Generate a short tenant id: `t_` + 12 hex chars.
pub fn generate_tenant_id() -> String {
    let simple = uuid::Uuid::new_v4().simple().to_string();
    format!("t_{}", &simple[..12])
}

/// In-process cache for API-key lookups. Caches negative results too, so a
/// flood of bogus keys cannot hammer Redis.
#[derive(Default)]
pub struct TenantCache {
    inner: DashMap<String, (Option<Tenant>, Instant)>,
}

impl TenantCache {
    pub fn new() -> Self {
        Self::default()
    }

    fn get(&self, hash: &str) -> Option<Option<Tenant>> {
        let entry = self.inner.get(hash)?;
        let (value, stored_at) = entry.value();
        if stored_at.elapsed() > CACHE_TTL {
            return None;
        }
        Some(value.clone())
    }

    fn put(&self, hash: String, value: Option<Tenant>) {
        self.inner.insert(hash, (value, Instant::now()));
    }

    /// Drop everything — called after admin mutations so revocations take
    /// effect within one connect, not one TTL.
    pub fn invalidate_all(&self) {
        self.inner.clear();
    }
}

/// Resolve an API key to an active tenant. Returns `None` for unknown keys,
/// suspended tenants, and Redis errors (fail closed — an outage must not
/// grant access).
pub async fn resolve_api_key(
    redis: &ConnectionManager,
    cache: &TenantCache,
    api_key: &str,
) -> Option<Tenant> {
    let hash = hash_api_key(api_key);

    let value = match cache.get(&hash) {
        Some(cached) => cached,
        None => {
            let fetched = fetch_by_hash(redis, &hash).await.unwrap_or_else(|e| {
                tracing::error!(error = %e, "tenant lookup failed; failing closed");
                None
            });
            cache.put(hash, fetched.clone());
            fetched
        }
    };

    value.filter(|t| t.active)
}

async fn fetch_by_hash(
    redis: &ConnectionManager,
    hash: &str,
) -> redis::RedisResult<Option<Tenant>> {
    let mut conn = redis.clone();
    let raw: Option<String> = conn.get(key_by_hash(hash)).await?;
    Ok(raw.and_then(|json| serde_json::from_str(&json).ok()))
}

/// Persist a new tenant under its API-key hash (plus the id → hash index).
pub async fn create_tenant(
    redis: &ConnectionManager,
    tenant: &Tenant,
    api_key: &str,
) -> redis::RedisResult<()> {
    let mut conn = redis.clone();
    let hash = hash_api_key(api_key);
    let json = serde_json::to_string(tenant).unwrap_or_default();

    let mut pipe = redis::pipe();
    pipe.set(key_by_hash(&hash), json)
        .set(key_by_id(&tenant.id), &hash);
    if let Some(email) = &tenant.email {
        pipe.set(key_by_email(email), &tenant.id);
    }
    let _: () = pipe.query_async(&mut conn).await?;
    Ok(())
}

/// Persist an already-stored tenant after a mutation (e.g. JWT secret
/// rotation). Looks up the existing API-key hash via the id index so the
/// plaintext key is not needed. Returns false when the id is unknown.
pub async fn update_tenant(redis: &ConnectionManager, tenant: &Tenant) -> redis::RedisResult<bool> {
    let mut conn = redis.clone();
    let hash: Option<String> = conn.get(key_by_id(&tenant.id)).await?;
    let Some(hash) = hash else {
        return Ok(false);
    };
    let json = serde_json::to_string(tenant).unwrap_or_default();
    let _: () = conn.set(key_by_hash(&hash), json).await?;
    Ok(true)
}

/// Resolve a login email to a tenant id (dashboard magic-link).
pub async fn get_tenant_id_by_email(
    redis: &ConnectionManager,
    email: &str,
) -> redis::RedisResult<Option<String>> {
    let mut conn = redis.clone();
    conn.get(key_by_email(email)).await
}

/// Load a tenant by its id (via the id → hash index). For the customer
/// dashboard, where the session carries the tenant id, not the API key.
pub async fn get_tenant_by_id(
    redis: &ConnectionManager,
    id: &str,
) -> redis::RedisResult<Option<Tenant>> {
    let mut conn = redis.clone();
    let hash: Option<String> = conn.get(key_by_id(id)).await?;
    match hash {
        Some(h) => fetch_by_hash(redis, &h).await,
        None => Ok(None),
    }
}

/// Rotate a tenant's API key: mint a new key, re-store the tenant under the new
/// hash, drop the old hash. Returns the new plaintext key (shown once). The old
/// key stops working immediately (after cache TTL / invalidation).
pub async fn rotate_api_key(
    redis: &ConnectionManager,
    id: &str,
) -> redis::RedisResult<Option<String>> {
    let mut conn = redis.clone();
    let old_hash: Option<String> = conn.get(key_by_id(id)).await?;
    let Some(old_hash) = old_hash else {
        return Ok(None);
    };
    let Some(tenant) = fetch_by_hash(redis, &old_hash).await? else {
        return Ok(None);
    };

    let new_key = generate_api_key();
    let new_hash = hash_api_key(&new_key);
    let json = serde_json::to_string(&tenant).unwrap_or_default();

    let _: () = redis::pipe()
        .set(key_by_hash(&new_hash), json)
        .set(key_by_id(id), &new_hash)
        .del(key_by_hash(&old_hash))
        .query_async(&mut conn)
        .await?;
    Ok(Some(new_key))
}

/// Delete a tenant by id. Returns whether anything was deleted.
pub async fn delete_tenant(redis: &ConnectionManager, id: &str) -> redis::RedisResult<bool> {
    let mut conn = redis.clone();
    let hash: Option<String> = conn.get(key_by_id(id)).await?;
    let Some(hash) = hash else {
        return Ok(false);
    };
    // Load the tenant so we can also drop its email index.
    let email = fetch_by_hash(redis, &hash).await?.and_then(|t| t.email);

    let mut pipe = redis::pipe();
    pipe.del(key_by_hash(&hash)).del(key_by_id(id));
    if let Some(email) = email {
        pipe.del(key_by_email(&email));
    }
    let _: () = pipe.query_async(&mut conn).await?;
    Ok(true)
}

/// List all tenants. Uses KEYS — fine at admin scale (tens of tenants);
/// switch to SCAN if the tenant count ever grows past a few thousand.
pub async fn list_tenants(redis: &ConnectionManager) -> redis::RedisResult<Vec<Tenant>> {
    let mut conn = redis.clone();
    let keys: Vec<String> = conn.keys("tenant:key:*").await?;
    if keys.is_empty() {
        return Ok(Vec::new());
    }

    let raws: Vec<Option<String>> = conn.get(keys).await?;
    Ok(raws
        .into_iter()
        .flatten()
        .filter_map(|json| serde_json::from_str(&json).ok())
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_key_hash_is_stable_hex() {
        let hash = hash_api_key("dk_test");
        assert_eq!(hash.len(), 64);
        assert_eq!(hash, hash_api_key("dk_test"));
        assert_ne!(hash, hash_api_key("dk_other"));
        assert!(hash.bytes().all(|b| b.is_ascii_hexdigit()));
    }

    #[test]
    fn generated_key_and_id_have_expected_shape() {
        let key = generate_api_key();
        assert!(key.starts_with("dk_"));
        assert_eq!(key.len(), 3 + 32);

        let id = generate_tenant_id();
        assert!(id.starts_with("t_"));
        assert_eq!(id.len(), 2 + 12);
        // Tenant ids must satisfy the identifier charset — they may be used
        // as internal namespace prefixes.
        assert!(crate::validation::is_valid_identifier(&id));
    }

    #[test]
    fn generated_jwt_secret_has_expected_shape() {
        let secret = generate_jwt_secret();
        assert!(secret.starts_with("jwt_"));
        assert_eq!(secret.len(), 4 + 32);
        assert_ne!(secret, generate_jwt_secret());
    }

    #[test]
    fn tenant_json_roundtrip_with_defaults() {
        let json = r#"{"id":"t_abc","name":"Acme"}"#;
        let tenant: Tenant = serde_json::from_str(json).unwrap();
        assert!(tenant.active);
        assert!(tenant.origins.is_empty());
        assert_eq!(tenant.max_rooms, 0);
        assert_eq!(tenant.max_peers, 0);

        let full = Tenant {
            id: "t_x".into(),
            name: "X".into(),
            origins: vec!["https://app.example.com".into()],
            active: false,
            max_rooms: 5,
            max_peers: 100,
            email: Some("ops@example.com".into()),
            jwt_secret: None,
        };
        let round: Tenant = serde_json::from_str(&serde_json::to_string(&full).unwrap()).unwrap();
        assert_eq!(round, full);
    }

    #[test]
    fn cache_serves_hits_and_supports_invalidation() {
        let cache = TenantCache::new();
        let tenant = Tenant {
            id: "t_1".into(),
            name: "One".into(),
            origins: vec![],
            active: true,
            max_rooms: 0,
            max_peers: 0,
            email: None,
            jwt_secret: None,
        };

        cache.put("h1".into(), Some(tenant.clone()));
        cache.put("h2".into(), None); // negative result cached too
        assert_eq!(cache.get("h1"), Some(Some(tenant)));
        assert_eq!(cache.get("h2"), Some(None));
        assert_eq!(cache.get("h3"), None); // miss

        cache.invalidate_all();
        assert_eq!(cache.get("h1"), None);
    }

    #[test]
    fn tenant_roundtrip_with_jwt_secret() {
        let t = Tenant {
            id: "t_abc123def456".into(),
            name: "Acme".into(),
            origins: vec![],
            active: true,
            max_rooms: 0,
            max_peers: 0,
            email: None,
            jwt_secret: Some("tenant-secret".into()),
        };
        let json = serde_json::to_string(&t).unwrap();
        let back: Tenant = serde_json::from_str(&json).unwrap();
        assert_eq!(back.jwt_secret.as_deref(), Some("tenant-secret"));

        // Old records without the field still deserialize.
        let legacy =
            r#"{"id":"t_x","name":"Old","origins":[],"active":true,"max_rooms":0,"max_peers":0}"#;
        let old: Tenant = serde_json::from_str(legacy).unwrap();
        assert_eq!(old.jwt_secret, None);
    }
}
