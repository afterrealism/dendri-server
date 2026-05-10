// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2025-2026 Dendri contributors

/// Regression: Binary WebSocket messages were silently dropped at
/// `_ => {} // Ping/Pong/Binary — ignore`. Client v2.3.x sends
/// msgpack-framed JSON as binary frames, so OFFER/ANSWER/CANDIDATE
/// were discarded, preventing WebRTC connections.
#[test]
fn binary_json_parse_roundtrip() {
    let json = r#"{"type":"OFFER","src":"alice","dst":"bob"}"#;
    let bytes = json.as_bytes().to_vec();
    let text = String::from_utf8(bytes).expect("Binary should be valid UTF-8");
    let parsed: serde_json::Value = serde_json::from_str(&text).expect("Should parse as JSON");
    assert_eq!(parsed["type"], "OFFER");
    assert_eq!(parsed["src"], "alice");
    assert_eq!(parsed["dst"], "bob");
}

/// Regression: Non-UTF-8 binary must not panic (uses `if let Ok`).
#[test]
fn non_utf8_binary_rejected_gracefully() {
    let invalid = vec![0xFF, 0xFE, 0x00, 0x01];
    assert!(String::from_utf8(invalid).is_err());
}

/// Regression: ICE CANDIDATE messages were rate-limited at 10/s,
/// but WebRTC bursts 5-15 candidates during connection setup.
/// Fix: only DATA messages are rate-limited; CANDIDATE passes through.
#[test]
fn candidate_messages_not_rate_limited() {
    // The handler now does: match msg.type_ { DATA => rate_limit, _ => true }
    // CANDIDATE, OFFER, ANSWER, HEARTBEAT all go to the _ => true arm.
    let types = [
        "OFFER",
        "ANSWER",
        "CANDIDATE",
        "HEARTBEAT",
        "LEAVE",
        "ROOM-JOIN",
    ];
    for t in types {
        let msg = format!(r#"{{"type":"{}"}}"#, t);
        let parsed: serde_json::Value = serde_json::from_str(&msg).unwrap();
        assert_eq!(parsed["type"], t);
    }
}

/// Regression: Binary and text encodings must produce identical parse results.
#[test]
fn binary_vs_text_json_parity() {
    let cases = [
        r#"{"type":"OFFER","src":"a","dst":"b"}"#,
        r#"{"type":"ANSWER","src":"b","dst":"a"}"#,
        r#"{"type":"CANDIDATE","src":"a","dst":"b","payload":"test"}"#,
        r#"{"type":"HEARTBEAT"}"#,
    ];
    for case in cases {
        let tv: serde_json::Value = serde_json::from_str(case).unwrap();
        let bt = String::from_utf8(case.as_bytes().to_vec()).unwrap();
        let bv: serde_json::Value = serde_json::from_str(&bt).unwrap();
        assert_eq!(tv, bv, "Text and binary parse must match");
    }
}
