use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;

use crate::enums::MessageType;

#[derive(Debug, Serialize, Deserialize)]
pub struct Message {
    #[serde(rename = "type")]
    pub type_: MessageType,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub src: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dst: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<Box<RawValue>>,
    /// Server-assigned sequence number for message ordering.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seq: Option<u64>,
    /// Room name for room-scoped messages.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub room: Option<String>,
    /// Server timestamp (epoch ms).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<i64>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enums::MessageType;

    #[test]
    fn deserialize_minimal_message() {
        let json = r#"{"type":"OFFER"}"#;
        let msg: Message = serde_json::from_str(json).unwrap();
        assert_eq!(msg.type_, MessageType::OFFER);
        assert!(msg.src.is_none());
        assert!(msg.dst.is_none());
        assert!(msg.payload.is_none());
        assert!(msg.seq.is_none());
        assert!(msg.room.is_none());
        assert!(msg.timestamp.is_none());
    }

    #[test]
    fn deserialize_full_message() {
        let json = r#"{"type":"DATA","src":"alice","dst":"bob","payload":{"cursor":[1,2]},"seq":42,"room":"lobby","timestamp":1700000000000}"#;
        let msg: Message = serde_json::from_str(json).unwrap();
        assert_eq!(msg.type_, MessageType::DATA);
        assert_eq!(msg.src.as_deref(), Some("alice"));
        assert_eq!(msg.dst.as_deref(), Some("bob"));
        assert_eq!(msg.seq, Some(42));
        assert_eq!(msg.room.as_deref(), Some("lobby"));
        assert_eq!(msg.timestamp, Some(1700000000000));
        assert!(msg.payload.is_some());
    }

    #[test]
    fn deserialize_room_join_message() {
        // This is what the client sends: type uses hyphens on the wire
        let json = r#"{"type":"ROOM-JOIN","room":"lobby"}"#;
        let msg: Message = serde_json::from_str(json).unwrap();
        assert_eq!(msg.type_, MessageType::RoomJoin);
        assert_eq!(msg.room.as_deref(), Some("lobby"));
    }

    #[test]
    fn deserialize_room_leave_message() {
        let json = r#"{"type":"ROOM-LEAVE","room":"lobby"}"#;
        let msg: Message = serde_json::from_str(json).unwrap();
        assert_eq!(msg.type_, MessageType::RoomLeave);
    }

    #[test]
    fn serialize_skips_none_fields() {
        let msg = Message {
            type_: MessageType::OPEN,
            src: None,
            dst: None,
            payload: None,
            seq: None,
            room: None,
            timestamp: None,
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert_eq!(json, r#"{"type":"OPEN"}"#);
    }

    #[test]
    fn serialize_includes_present_fields() {
        let msg = Message {
            type_: MessageType::DATA,
            src: Some("alice".to_string()),
            dst: Some("bob".to_string()),
            payload: None,
            seq: Some(5),
            room: Some("room1".to_string()),
            timestamp: Some(1700000000000),
        };
        let json = serde_json::to_string(&msg).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["type"], "DATA");
        assert_eq!(v["src"], "alice");
        assert_eq!(v["dst"], "bob");
        assert_eq!(v["seq"], 5);
        assert_eq!(v["room"], "room1");
        assert_eq!(v["timestamp"], 1700000000000i64);
    }

    #[test]
    fn round_trip_preserves_raw_payload() {
        let json = r#"{"type":"OFFER","payload":{"sdp":"v=0\r\n","nested":{"deep":true}}}"#;
        let msg: Message = serde_json::from_str(json).unwrap();
        let re_serialized = serde_json::to_string(&msg).unwrap();
        let v: serde_json::Value = serde_json::from_str(&re_serialized).unwrap();
        assert_eq!(v["payload"]["sdp"], "v=0\r\n");
        assert_eq!(v["payload"]["nested"]["deep"], true);
    }
}
