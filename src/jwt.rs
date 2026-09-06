//! Shared JWT validation for signaling transports (WS + HTTP).

/// Validate an HS256 JWT and return its claims.
///
/// Pinned to HS256: `Validation::default()` would accept whatever algorithm
/// the token header declares (algorithm confusion). `exp` is mandatory.
pub fn validate_jwt(
    secret: &str,
    token: &str,
) -> Result<serde_json::Value, jsonwebtoken::errors::Error> {
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256);
    validation.required_spec_claims.insert("exp".to_string());
    let key = jsonwebtoken::DecodingKey::from_secret(secret.as_bytes());
    jsonwebtoken::decode::<serde_json::Value>(token, &key, &validation).map(|t| t.claims)
}

/// Room ACL semantics: no `rooms` claim (or non-array) → all rooms allowed;
/// otherwise the room must be listed. Mirrors the historical behavior of
/// `handle_room_join` (message.rs).
pub fn room_allowed(claims: &serde_json::Value, room: &str) -> bool {
    match claims.get("rooms").and_then(|r| r.as_array()) {
        None => true,
        Some(rooms) => rooms.iter().any(|r| r.as_str() == Some(room)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{encode, EncodingKey, Header};
    use serde_json::json;

    fn make_jwt(secret: &str, claims: &serde_json::Value) -> String {
        encode(
            &Header::default(),
            claims,
            &EncodingKey::from_secret(secret.as_bytes()),
        )
        .unwrap()
    }

    #[test]
    fn validate_jwt_accepts_valid_token() {
        let tok = make_jwt(
            "s3cret",
            &json!({"sub":"u1","rooms":["a"],"exp":4102444800u64}),
        );
        let claims = validate_jwt("s3cret", &tok).unwrap();
        assert_eq!(claims["rooms"][0], "a");
    }

    #[test]
    fn validate_jwt_rejects_wrong_secret_and_missing_exp() {
        let tok = make_jwt("s3cret", &json!({"sub":"u1","exp":4102444800u64}));
        assert!(validate_jwt("other", &tok).is_err());
        let no_exp = make_jwt("s3cret", &json!({"sub":"u1"}));
        assert!(validate_jwt("s3cret", &no_exp).is_err());
    }

    #[test]
    fn validate_jwt_rejects_garbage_and_expired_tokens() {
        assert!(validate_jwt("s3cret", "not.a.valid.jwt").is_err());
        assert!(validate_jwt("s3cret", "").is_err());
        let expired = make_jwt("s3cret", &json!({"sub":"u1","exp":1000000000u64})); // year 2001
        assert!(validate_jwt("s3cret", &expired).is_err());
    }

    #[test]
    fn room_allowed_follows_claims_semantics() {
        assert!(room_allowed(&json!({"sub":"u1"}), "anything")); // no rooms claim
        assert!(room_allowed(&json!({"rooms":["lobby","game"]}), "game")); // listed
        assert!(!room_allowed(&json!({"rooms":["lobby"]}), "game")); // not listed
        assert!(room_allowed(&json!({"rooms":"not-an-array"}), "game")); // non-array ignored
    }
}
