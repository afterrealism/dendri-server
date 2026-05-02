//! Input validation for user-supplied identifiers and constant-time
//! comparison helpers for shared secrets.
//!
//! Peer IDs, tokens, and room names flow into hand-built JSON in the message
//! serializer (see `handlers::message::serialize_relay`) and into storage keys.
//! Treating them as "safe ASCII" is only safe if we enforce the constraint at
//! the boundary — that is this module's job.

use subtle::ConstantTimeEq;

/// Constant-time byte comparison for secret-like values (the shared
/// connection key). A naive `a != b` returns early on the first mismatched
/// byte, which leaks a timing signal the attacker can use to guess the key
/// byte-by-byte.
pub fn constant_time_str_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.as_bytes().ct_eq(b.as_bytes()).into()
}

/// Maximum length for identifiers (peer IDs, tokens, room names).
pub const MAX_IDENTIFIER_LEN: usize = 128;

/// Whether `s` is a valid identifier: 1..=MAX_IDENTIFIER_LEN bytes, each byte
/// in `[A-Za-z0-9_-]`.
///
/// This is deliberately conservative. UUIDs (`crypto.randomUUID()`), URL-safe
/// random tokens, and conventional room slugs all satisfy it; anything that
/// could break JSON framing (quotes, backslashes, control chars, non-ASCII)
/// is rejected.
pub fn is_valid_identifier(s: &str) -> bool {
    if s.is_empty() || s.len() > MAX_IDENTIFIER_LEN {
        return false;
    }
    s.bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_uuid_and_slugs() {
        assert!(is_valid_identifier("550e8400-e29b-41d4-a716-446655440000"));
        assert!(is_valid_identifier("game-lobby-42"));
        assert!(is_valid_identifier("a"));
        assert!(is_valid_identifier("ABC_123-xyz"));
    }

    #[test]
    fn rejects_json_breakers() {
        assert!(!is_valid_identifier("ab\"cd"));
        assert!(!is_valid_identifier("ab\\cd"));
        assert!(!is_valid_identifier(r#"{"inject":true}"#));
        assert!(!is_valid_identifier("room,\"payload\":null"));
    }

    #[test]
    fn rejects_control_and_whitespace() {
        assert!(!is_valid_identifier(" "));
        assert!(!is_valid_identifier("a b"));
        assert!(!is_valid_identifier("a\nb"));
        assert!(!is_valid_identifier("a\tb"));
    }

    #[test]
    fn rejects_non_ascii() {
        assert!(!is_valid_identifier("café"));
        assert!(!is_valid_identifier("日本語"));
    }

    #[test]
    fn rejects_empty_and_over_limit() {
        assert!(!is_valid_identifier(""));
        let too_long: String = "a".repeat(MAX_IDENTIFIER_LEN + 1);
        assert!(!is_valid_identifier(&too_long));
        let exactly_limit: String = "a".repeat(MAX_IDENTIFIER_LEN);
        assert!(is_valid_identifier(&exactly_limit));
    }
}
