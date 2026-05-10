// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2025-2026 Dendri contributors

use reqwest::Client;
use serde::Serialize;
use std::time::Duration;
use tokio::sync::mpsc;

/// Hard cap on the webhook delivery queue. Events beyond this are dropped
/// (with a warning) so a slow or dead endpoint can't consume unbounded memory.
const WEBHOOK_QUEUE_CAPACITY: usize = 1024;

/// Per-request HTTP timeout for webhook POSTs. A hung webhook endpoint
/// otherwise blocks the delivery loop indefinitely.
const WEBHOOK_HTTP_TIMEOUT: Duration = Duration::from_secs(5);

/// Webhook delivery retry configuration.
/// 3 attempts total with exponential backoff: 1s, 5s, 25s.
const MAX_RETRIES: u32 = 3;
const RETRY_DELAYS: [Duration; 3] = [
    Duration::from_secs(1),
    Duration::from_secs(5),
    Duration::from_secs(25),
];

#[derive(Debug, Clone, Serialize)]
pub struct WebhookEvent {
    pub event: String,
    pub timestamp: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peer_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub room: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

pub struct WebhookSender {
    tx: mpsc::Sender<WebhookEvent>,
}

impl WebhookSender {
    pub fn new(url: String, secret: Option<String>) -> Self {
        // Bounded so a slow endpoint can't leak memory. try_send drops
        // overflow events rather than back-pressuring callers (which run
        // on the signaling hot path).
        let (tx, mut rx) = mpsc::channel::<WebhookEvent>(WEBHOOK_QUEUE_CAPACITY);

        let client = Client::builder()
            .timeout(WEBHOOK_HTTP_TIMEOUT)
            .build()
            .unwrap_or_else(|_| Client::new());

        tokio::spawn(async move {
            while let Some(event) = rx.recv().await {
                let payload = serde_json::to_string(&event).unwrap_or_default();

                let mut last_error = None;
                for attempt in 0..MAX_RETRIES {
                    // Rebuild the request body for each attempt (reqwest consumes it).
                    let mut req = client
                        .post(&url)
                        .header("Content-Type", "application/json")
                        .header("X-Dendri-Event", &event.event);

                    if let Some(ref secret) = secret {
                        use hmac::{Hmac, Mac};
                        use sha2::Sha256;
                        let mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes());
                        match mac {
                            Ok(mut mac) => {
                                mac.update(payload.as_bytes());
                                let signature = hex::encode(mac.finalize().into_bytes());
                                req = req
                                    .header("X-Dendri-Signature", format!("sha256={}", signature));
                            }
                            Err(e) => {
                                tracing::error!(error = %e, "Webhook HMAC init failed");
                                continue;
                            }
                        }
                    }

                    match req.body(payload.clone()).send().await {
                        Ok(_) => {
                            last_error = None;
                            break;
                        }
                        Err(e) => {
                            last_error = Some(e);
                            if attempt + 1 < MAX_RETRIES {
                                tracing::warn!(
                                    event = %event.event,
                                    attempt = attempt + 1,
                                    error = %last_error.as_ref().unwrap(),
                                    retry_in_ms = RETRY_DELAYS[attempt as usize].as_millis(),
                                    "Webhook delivery failed, retrying"
                                );
                                tokio::time::sleep(RETRY_DELAYS[attempt as usize]).await;
                            }
                        }
                    }
                }

                if let Some(e) = last_error {
                    tracing::error!(
                        event = %event.event,
                        attempts = MAX_RETRIES,
                        error = %e,
                        "Webhook delivery failed after all retries"
                    );
                }
            }
        });

        Self { tx }
    }

    pub fn emit(&self, event: WebhookEvent) {
        // Drop on full queue rather than block the caller. Emits happen
        // from the signaling hot path; we can lose a webhook event
        // without losing message delivery.
        if let Err(e) = self.tx.try_send(event) {
            use mpsc::error::TrySendError;
            match e {
                TrySendError::Full(dropped) => {
                    tracing::warn!(
                        event = %dropped.event,
                        "Webhook queue full, dropping event"
                    );
                }
                TrySendError::Closed(_) => {
                    // Delivery task died — nothing more we can do here.
                }
            }
        }
    }
}

/// Reject obviously-dangerous webhook URLs at config-parse time.
/// Operator misconfiguration pointing this at a loopback or cloud-metadata
/// endpoint would leak signed events to unintended targets. This is a best
/// effort: it does not protect against DNS rebinding and skipping the
/// check with an explicit opt-out is not supported.
pub fn is_safe_webhook_url(url: &str) -> bool {
    let Ok(parsed) = reqwest::Url::parse(url) else {
        return false;
    };
    match parsed.scheme() {
        "http" | "https" => {}
        _ => return false,
    }
    let Some(host) = parsed.host_str() else {
        return false;
    };
    // Block loopback, link-local, unique-local, and the AWS/GCP metadata IP.
    const BLOCKED_LITERALS: &[&str] = &[
        // IPv4
        "localhost",
        "127.0.0.1",
        "0.0.0.0",
        "169.254.169.254",
        // IPv6 loopback, link-local, unique-local (ULA), and cloud metadata
        "::1",
        "fd00::",
        "fe80::",
    ];
    let prefix_blocks: &[&str] = &[
        "127.",     // IPv4 loopback
        "fc00:",    // ULA lower half
        "fd00:",    // ULA upper half
        "fe80:",    // IPv6 link-local
        "10.",      // RFC 1918 private
        "172.16.",  // RFC 1918 private range start (172.16.0.0/12)
        "192.168.", // RFC 1918 private
    ];

    if BLOCKED_LITERALS
        .iter()
        .any(|b| host.eq_ignore_ascii_case(b))
    {
        return false;
    }
    if prefix_blocks
        .iter()
        .any(|p| host.len() >= p.len() && host[..p.len()].eq_ignore_ascii_case(p))
    {
        return false;
    }
    // Check the broader 172.16.0.0/12 private range (172.16.0.0 - 172.31.255.255).
    if host.len() >= 7 && host.starts_with("172.") {
        if let Some(second) = host[4..].split('.').next() {
            if let Ok(n) = second.parse::<u8>() {
                if (16..=31).contains(&n) {
                    return false;
                }
            }
        }
    }
    true
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

impl WebhookEvent {
    pub fn peer_connected(peer_id: &str) -> Self {
        Self {
            event: "peer.connected".into(),
            timestamp: now_ms(),
            peer_id: Some(peer_id.into()),
            room: None,
            data: None,
        }
    }

    pub fn peer_disconnected(peer_id: &str) -> Self {
        Self {
            event: "peer.disconnected".into(),
            timestamp: now_ms(),
            peer_id: Some(peer_id.into()),
            room: None,
            data: None,
        }
    }

    pub fn room_joined(peer_id: &str, room: &str) -> Self {
        Self {
            event: "room.joined".into(),
            timestamp: now_ms(),
            peer_id: Some(peer_id.into()),
            room: Some(room.into()),
            data: None,
        }
    }

    pub fn room_left(peer_id: &str, room: &str) -> Self {
        Self {
            event: "room.left".into(),
            timestamp: now_ms(),
            peer_id: Some(peer_id.into()),
            room: Some(room.into()),
            data: None,
        }
    }

    pub fn rate_limited(peer_id: &str, bucket: &str) -> Self {
        Self {
            event: "rate.limited".into(),
            timestamp: now_ms(),
            peer_id: Some(peer_id.into()),
            room: None,
            data: Some(serde_json::json!({ "bucket": bucket })),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_connected_creates_correct_json() {
        let event = WebhookEvent::peer_connected("alice");
        let json = serde_json::to_value(&event).unwrap();

        assert_eq!(json["event"], "peer.connected");
        assert_eq!(json["peer_id"], "alice");
        assert!(json["timestamp"].as_i64().unwrap() > 0);
        assert!(json.get("room").is_none());
        assert!(json.get("data").is_none());
    }

    #[test]
    fn peer_disconnected_creates_correct_json() {
        let event = WebhookEvent::peer_disconnected("bob");
        let json = serde_json::to_value(&event).unwrap();

        assert_eq!(json["event"], "peer.disconnected");
        assert_eq!(json["peer_id"], "bob");
    }

    #[test]
    fn room_joined_includes_room_field() {
        let event = WebhookEvent::room_joined("alice", "lobby");
        let json = serde_json::to_value(&event).unwrap();

        assert_eq!(json["event"], "room.joined");
        assert_eq!(json["peer_id"], "alice");
        assert_eq!(json["room"], "lobby");
        assert!(json.get("data").is_none());
    }

    #[test]
    fn room_left_includes_room_field() {
        let event = WebhookEvent::room_left("bob", "game-room");
        let json = serde_json::to_value(&event).unwrap();

        assert_eq!(json["event"], "room.left");
        assert_eq!(json["peer_id"], "bob");
        assert_eq!(json["room"], "game-room");
    }

    #[test]
    fn rate_limited_includes_bucket_data() {
        let event = WebhookEvent::rate_limited("charlie", "signaling");
        let json = serde_json::to_value(&event).unwrap();

        assert_eq!(json["event"], "rate.limited");
        assert_eq!(json["peer_id"], "charlie");
        assert_eq!(json["data"]["bucket"], "signaling");
    }

    #[test]
    fn webhook_events_serialize_correctly() {
        // All fields set.
        let event = WebhookEvent {
            event: "custom.event".into(),
            timestamp: 1700000000000,
            peer_id: Some("peer1".into()),
            room: Some("room1".into()),
            data: Some(serde_json::json!({"key": "value"})),
        };
        let json_str = serde_json::to_string(&event).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();

        assert_eq!(parsed["event"], "custom.event");
        assert_eq!(parsed["timestamp"], 1700000000000i64);
        assert_eq!(parsed["peer_id"], "peer1");
        assert_eq!(parsed["room"], "room1");
        assert_eq!(parsed["data"]["key"], "value");
    }

    #[test]
    fn webhook_event_omits_none_fields() {
        let event = WebhookEvent {
            event: "test".into(),
            timestamp: 123,
            peer_id: None,
            room: None,
            data: None,
        };
        let json_str = serde_json::to_string(&event).unwrap();

        assert!(!json_str.contains("peer_id"));
        assert!(!json_str.contains("room"));
        assert!(!json_str.contains("data"));
    }

    #[test]
    fn serialization_round_trip_preserves_all_fields() {
        let original = WebhookEvent {
            event: "custom.event".into(),
            timestamp: 1700000000000,
            peer_id: Some("peer-abc".into()),
            room: Some("room-xyz".into()),
            data: Some(serde_json::json!({"action": "move", "x": 42})),
        };

        let serialized = serde_json::to_string(&original).unwrap();
        let deserialized: serde_json::Value = serde_json::from_str(&serialized).unwrap();

        assert_eq!(deserialized["event"], "custom.event");
        assert_eq!(deserialized["timestamp"], 1700000000000i64);
        assert_eq!(deserialized["peer_id"], "peer-abc");
        assert_eq!(deserialized["room"], "room-xyz");
        assert_eq!(deserialized["data"]["action"], "move");
        assert_eq!(deserialized["data"]["x"], 42);
    }

    #[test]
    fn serialization_round_trip_none_fields() {
        let original = WebhookEvent {
            event: "minimal".into(),
            timestamp: 999,
            peer_id: None,
            room: None,
            data: None,
        };

        let serialized = serde_json::to_string(&original).unwrap();
        let deserialized: serde_json::Value = serde_json::from_str(&serialized).unwrap();

        assert_eq!(deserialized["event"], "minimal");
        assert_eq!(deserialized["timestamp"], 999);
        // None fields should be absent, not null.
        assert!(deserialized.get("peer_id").is_none());
        assert!(deserialized.get("room").is_none());
        assert!(deserialized.get("data").is_none());
    }

    #[test]
    fn all_event_constructors_produce_valid_json() {
        let events = vec![
            WebhookEvent::peer_connected("alice"),
            WebhookEvent::peer_disconnected("bob"),
            WebhookEvent::room_joined("carol", "lobby"),
            WebhookEvent::room_left("dave", "game"),
            WebhookEvent::rate_limited("eve", "signaling"),
        ];

        for event in events {
            let json_str = serde_json::to_string(&event).unwrap();
            // Verify it parses as valid JSON.
            let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
            // Every event must have "event" and "timestamp".
            assert!(parsed.get("event").is_some(), "Missing 'event' field");
            assert!(
                parsed.get("timestamp").is_some(),
                "Missing 'timestamp' field"
            );
            // timestamp must be a number.
            assert!(parsed["timestamp"].is_i64(), "timestamp should be i64");
        }
    }

    #[test]
    fn rate_limited_event_includes_bucket_data() {
        let event = WebhookEvent::rate_limited("alice", "data");
        let json = serde_json::to_value(&event).unwrap();

        assert_eq!(json["event"], "rate.limited");
        assert_eq!(json["peer_id"], "alice");
        // data field must contain the bucket name.
        assert!(json["data"].is_object());
        assert_eq!(json["data"]["bucket"], "data");
    }

    #[test]
    fn timestamp_is_reasonable_and_recent() {
        let before_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;

        let event = WebhookEvent::peer_connected("test-peer");

        let after_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;

        assert!(
            event.timestamp >= before_ms,
            "timestamp should be >= before_ms"
        );
        assert!(
            event.timestamp <= after_ms,
            "timestamp should be <= after_ms"
        );
        // Must be positive and not zero.
        assert!(event.timestamp > 0, "timestamp should be positive");
        // Sanity check: should be after 2020-01-01 (1577836800000 ms).
        assert!(
            event.timestamp > 1_577_836_800_000,
            "timestamp should be after 2020"
        );
    }

    #[test]
    fn event_names_are_correct_for_all_constructors() {
        assert_eq!(WebhookEvent::peer_connected("x").event, "peer.connected");
        assert_eq!(
            WebhookEvent::peer_disconnected("x").event,
            "peer.disconnected"
        );
        assert_eq!(WebhookEvent::room_joined("x", "r").event, "room.joined");
        assert_eq!(WebhookEvent::room_left("x", "r").event, "room.left");
        assert_eq!(WebhookEvent::rate_limited("x", "b").event, "rate.limited");
    }

    #[test]
    fn room_events_include_room_field_but_not_data() {
        let joined = WebhookEvent::room_joined("peer1", "lobby");
        assert_eq!(joined.room.as_deref(), Some("lobby"));
        assert!(joined.data.is_none());

        let left = WebhookEvent::room_left("peer1", "lobby");
        assert_eq!(left.room.as_deref(), Some("lobby"));
        assert!(left.data.is_none());
    }

    #[test]
    fn peer_events_do_not_include_room_field() {
        let connected = WebhookEvent::peer_connected("peer1");
        assert!(connected.room.is_none());
        assert!(connected.data.is_none());

        let disconnected = WebhookEvent::peer_disconnected("peer1");
        assert!(disconnected.room.is_none());
        assert!(disconnected.data.is_none());
    }
}
