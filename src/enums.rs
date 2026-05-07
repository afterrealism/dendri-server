use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[allow(clippy::upper_case_acronyms)]
pub enum MessageType {
    OPEN,
    LEAVE,
    CANDIDATE,
    OFFER,
    ANSWER,
    EXPIRE,
    HEARTBEAT,
    #[serde(rename = "ID-TAKEN")]
    IdTaken,
    ERROR,
    DATA,
    ACK,
    #[serde(rename = "ROOM-JOIN")]
    RoomJoin,
    #[serde(rename = "ROOM-LEAVE")]
    RoomLeave,
    #[serde(rename = "ROOM-PEERS")]
    RoomPeers,
    #[serde(rename = "PRESENCE-UPDATE")]
    PresenceUpdate,
}

impl MessageType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::OPEN => "OPEN",
            Self::LEAVE => "LEAVE",
            Self::CANDIDATE => "CANDIDATE",
            Self::OFFER => "OFFER",
            Self::ANSWER => "ANSWER",
            Self::EXPIRE => "EXPIRE",
            Self::HEARTBEAT => "HEARTBEAT",
            Self::IdTaken => "ID-TAKEN",
            Self::ERROR => "ERROR",
            Self::DATA => "DATA",
            Self::ACK => "ACK",
            Self::RoomJoin => "ROOM-JOIN",
            Self::RoomLeave => "ROOM-LEAVE",
            Self::RoomPeers => "ROOM-PEERS",
            Self::PresenceUpdate => "PRESENCE-UPDATE",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub enum PeerError {
    #[serde(rename = "Invalid key provided")]
    InvalidKey,
    #[serde(rename = "Invalid token provided")]
    InvalidToken,
    #[serde(rename = "No id, token, or key supplied to websocket server")]
    InvalidWsParameters,
    #[serde(rename = "Server has reached its concurrent user limit")]
    ConnectionLimitExceed,
}

impl PeerError {
    pub fn as_str(&self) -> &'static str {
        match self {
            PeerError::InvalidKey => "Invalid key provided",
            PeerError::InvalidToken => "Invalid token provided",
            PeerError::InvalidWsParameters => "No id, token, or key supplied to websocket server",
            PeerError::ConnectionLimitExceed => "Server has reached its concurrent user limit",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn message_type_as_str_never_panics(variant in 0u8..15) {
            // Enumerate all variants
            let types = [
                MessageType::OPEN, MessageType::LEAVE, MessageType::CANDIDATE,
                MessageType::OFFER, MessageType::ANSWER, MessageType::EXPIRE,
                MessageType::HEARTBEAT, MessageType::IdTaken, MessageType::ERROR,
                MessageType::DATA, MessageType::ACK, MessageType::RoomJoin,
                MessageType::RoomLeave, MessageType::RoomPeers, MessageType::PresenceUpdate,
            ];
            if (variant as usize) < types.len() {
                let _ = types[variant as usize].as_str(); // Should never panic
            }
        }
    }

    // -----------------------------------------------------------------------
    // MessageType serialization/deserialization round-trips
    // -----------------------------------------------------------------------

    #[test]
    fn message_type_serializes_with_correct_wire_names() {
        assert_eq!(
            serde_json::to_string(&MessageType::OPEN).unwrap(),
            r#""OPEN""#
        );
        assert_eq!(
            serde_json::to_string(&MessageType::LEAVE).unwrap(),
            r#""LEAVE""#
        );
        assert_eq!(
            serde_json::to_string(&MessageType::CANDIDATE).unwrap(),
            r#""CANDIDATE""#
        );
        assert_eq!(
            serde_json::to_string(&MessageType::OFFER).unwrap(),
            r#""OFFER""#
        );
        assert_eq!(
            serde_json::to_string(&MessageType::ANSWER).unwrap(),
            r#""ANSWER""#
        );
        assert_eq!(
            serde_json::to_string(&MessageType::EXPIRE).unwrap(),
            r#""EXPIRE""#
        );
        assert_eq!(
            serde_json::to_string(&MessageType::HEARTBEAT).unwrap(),
            r#""HEARTBEAT""#
        );
        assert_eq!(
            serde_json::to_string(&MessageType::ERROR).unwrap(),
            r#""ERROR""#
        );
        assert_eq!(
            serde_json::to_string(&MessageType::DATA).unwrap(),
            r#""DATA""#
        );
        assert_eq!(
            serde_json::to_string(&MessageType::ACK).unwrap(),
            r#""ACK""#
        );
    }

    #[test]
    fn room_message_types_use_hyphens_on_wire() {
        // These MUST match what the client sends/expects.
        assert_eq!(
            serde_json::to_string(&MessageType::IdTaken).unwrap(),
            r#""ID-TAKEN""#
        );
        assert_eq!(
            serde_json::to_string(&MessageType::RoomJoin).unwrap(),
            r#""ROOM-JOIN""#
        );
        assert_eq!(
            serde_json::to_string(&MessageType::RoomLeave).unwrap(),
            r#""ROOM-LEAVE""#
        );
        assert_eq!(
            serde_json::to_string(&MessageType::RoomPeers).unwrap(),
            r#""ROOM-PEERS""#
        );
        assert_eq!(
            serde_json::to_string(&MessageType::PresenceUpdate).unwrap(),
            r#""PRESENCE-UPDATE""#
        );
    }

    #[test]
    fn message_type_deserializes_from_wire_names() {
        assert_eq!(
            serde_json::from_str::<MessageType>(r#""ROOM-JOIN""#).unwrap(),
            MessageType::RoomJoin
        );
        assert_eq!(
            serde_json::from_str::<MessageType>(r#""ROOM-LEAVE""#).unwrap(),
            MessageType::RoomLeave
        );
        assert_eq!(
            serde_json::from_str::<MessageType>(r#""ROOM-PEERS""#).unwrap(),
            MessageType::RoomPeers
        );
        assert_eq!(
            serde_json::from_str::<MessageType>(r#""ID-TAKEN""#).unwrap(),
            MessageType::IdTaken
        );
        assert_eq!(
            serde_json::from_str::<MessageType>(r#""PRESENCE-UPDATE""#).unwrap(),
            MessageType::PresenceUpdate
        );
    }

    #[test]
    fn message_type_as_str_matches_serde() {
        // Verify as_str() output matches the serde serialization (minus quotes).
        let types = [
            MessageType::OPEN,
            MessageType::LEAVE,
            MessageType::CANDIDATE,
            MessageType::OFFER,
            MessageType::ANSWER,
            MessageType::EXPIRE,
            MessageType::HEARTBEAT,
            MessageType::IdTaken,
            MessageType::ERROR,
            MessageType::DATA,
            MessageType::ACK,
            MessageType::RoomJoin,
            MessageType::RoomLeave,
            MessageType::RoomPeers,
            MessageType::PresenceUpdate,
        ];

        for t in types {
            let serde_str = serde_json::to_string(&t).unwrap();
            let serde_inner = serde_str.trim_matches('"');
            assert_eq!(
                t.as_str(),
                serde_inner,
                "as_str() mismatch for {:?}: {} vs {}",
                t,
                t.as_str(),
                serde_inner
            );
        }
    }

    // -----------------------------------------------------------------------
    // PeerError serialization
    // -----------------------------------------------------------------------

    #[test]
    fn peer_error_as_str_returns_expected_messages() {
        assert_eq!(PeerError::InvalidKey.as_str(), "Invalid key provided");
        assert_eq!(
            PeerError::InvalidWsParameters.as_str(),
            "No id, token, or key supplied to websocket server"
        );
        assert_eq!(
            PeerError::ConnectionLimitExceed.as_str(),
            "Server has reached its concurrent user limit"
        );
    }
}
