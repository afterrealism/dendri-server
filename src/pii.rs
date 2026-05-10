// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2025-2026 Dendri contributors

use std::hash::{Hash, Hasher};

/// Redact a room name for logging: hashes to a stable, short identifier
/// unless `DENDRI_LOG_PII=true` is set, in which case the plain name is
/// returned. Room names are PII because they often encode workspace,
/// project, or group identifiers chosen by users.
///
/// The hash is deterministic within one process, so repeated log entries
/// for the same room produce the same redacted identifier, keeping event
/// correlation possible without exposing the actual name.
pub fn redact_room(name: &str) -> String {
    if std::env::var("DENDRI_LOG_PII").as_deref() == Ok("true") {
        name.to_string()
    } else {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        name.hash(&mut hasher);
        format!("room:{:08x}", hasher.finish())
    }
}
