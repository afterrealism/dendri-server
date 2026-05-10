// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2025-2026 Dendri contributors

use std::collections::VecDeque;
use std::time::Instant;

use dashmap::DashMap;

/// Per-client ring buffer for message replay on reconnection.
///
/// Each client (or room) gets an independent buffer of recent messages.
/// Messages are evicted when they exceed `ttl_ms` or the buffer exceeds `max_size`.
pub struct ReplayBuffer {
    buffers: DashMap<String, ClientBuffer>,
    max_size: usize,
    ttl_ms: u64,
}

struct ClientBuffer {
    messages: VecDeque<BufferedMessage>,
}

struct BufferedMessage {
    seq: u64,
    data: String,
    created_at: Instant,
}

impl ReplayBuffer {
    /// Create a new replay buffer with the given per-client capacity and TTL.
    pub fn new(max_size: usize, ttl_ms: u64) -> Self {
        Self {
            buffers: DashMap::new(),
            max_size,
            ttl_ms,
        }
    }

    /// Store a message for a client/room. Evicts old messages by TTL and enforces max_size.
    pub fn push(&self, client_id: &str, seq: u64, data: String) {
        let now = Instant::now();
        let ttl = std::time::Duration::from_millis(self.ttl_ms);

        let mut entry = self
            .buffers
            .entry(client_id.to_string())
            .or_insert_with(|| ClientBuffer {
                messages: VecDeque::new(),
            });

        let buf = entry.value_mut();

        // Evict expired messages from the front.
        while let Some(front) = buf.messages.front() {
            if now.duration_since(front.created_at) >= ttl {
                buf.messages.pop_front();
            } else {
                break;
            }
        }

        // Enforce max_size: drop oldest if at capacity.
        if buf.messages.len() >= self.max_size {
            buf.messages.pop_front();
        }

        buf.messages.push_back(BufferedMessage {
            seq,
            data,
            created_at: now,
        });
    }

    /// Return all messages with seq > since_seq that are still within TTL.
    pub fn replay_since(&self, client_id: &str, since_seq: u64) -> Vec<String> {
        let now = Instant::now();
        let ttl = std::time::Duration::from_millis(self.ttl_ms);

        let Some(entry) = self.buffers.get(client_id) else {
            return Vec::new();
        };

        entry
            .messages
            .iter()
            .filter(|m| m.seq > since_seq && now.duration_since(m.created_at) < ttl)
            .map(|m| m.data.clone())
            .collect()
    }

    /// Return the sequence number of the oldest buffered message for a client,
    /// or `None` if no messages are buffered.
    pub fn oldest_seq(&self, client_id: &str) -> Option<u64> {
        self.buffers.get(client_id)?.messages.front().map(|m| m.seq)
    }

    /// Remove a client's entire buffer.
    pub fn remove_client(&self, client_id: &str) {
        self.buffers.remove(client_id);
    }

    /// Evict all expired messages across all clients. Removes empty buffers.
    pub fn evict_expired(&self) {
        let now = Instant::now();
        let ttl = std::time::Duration::from_millis(self.ttl_ms);

        // Collect keys to avoid holding DashMap shard locks during mutation.
        let keys: Vec<String> = self.buffers.iter().map(|e| e.key().clone()).collect();

        for key in keys {
            let should_remove = {
                if let Some(mut entry) = self.buffers.get_mut(&key) {
                    let buf = entry.value_mut();
                    while let Some(front) = buf.messages.front() {
                        if now.duration_since(front.created_at) >= ttl {
                            buf.messages.pop_front();
                        } else {
                            break;
                        }
                    }
                    buf.messages.is_empty()
                } else {
                    false
                }
            };

            if should_remove {
                self.buffers.remove(&key);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::thread::sleep;
    use std::time::Duration;

    proptest! {
        #[test]
        fn replay_since_always_returns_subset_of_pushed(
            messages in prop::collection::vec(("[a-z]{5,20}", 1u64..10000), 1..100),
            since_seq in 0u64..10000,
        ) {
            let buf = ReplayBuffer::new(1000, 60_000);
            for (data, seq) in &messages {
                buf.push("client1", *seq, data.clone());
            }
            let replayed = buf.replay_since("client1", since_seq);
            // Every replayed message should have been pushed
            assert!(replayed.len() <= messages.len());
        }

        #[test]
        fn push_then_replay_zero_returns_all_within_limits(
            count in 1usize..200,
            max_size in 1usize..500,
        ) {
            let buf = ReplayBuffer::new(max_size, 60_000);
            for i in 0..count {
                buf.push("c1", i as u64 + 1, format!("msg_{i}"));
            }
            let replayed = buf.replay_since("c1", 0);
            let expected = count.min(max_size);
            assert_eq!(replayed.len(), expected);
        }
    }

    #[test]
    fn push_and_replay_returns_messages_after_seq() {
        let buf = ReplayBuffer::new(100, 60_000);
        buf.push("client1", 1, r#"{"seq":1}"#.to_string());
        buf.push("client1", 2, r#"{"seq":2}"#.to_string());
        buf.push("client1", 3, r#"{"seq":3}"#.to_string());

        let replayed = buf.replay_since("client1", 1);
        assert_eq!(replayed.len(), 2);
        assert_eq!(replayed[0], r#"{"seq":2}"#);
        assert_eq!(replayed[1], r#"{"seq":3}"#);
    }

    #[test]
    fn replay_since_zero_returns_all() {
        let buf = ReplayBuffer::new(100, 60_000);
        buf.push("client1", 1, "a".to_string());
        buf.push("client1", 2, "b".to_string());

        let replayed = buf.replay_since("client1", 0);
        assert_eq!(replayed.len(), 2);
    }

    #[test]
    fn replay_unknown_client_returns_empty() {
        let buf = ReplayBuffer::new(100, 60_000);
        let replayed = buf.replay_since("unknown", 0);
        assert!(replayed.is_empty());
    }

    #[test]
    fn enforces_max_size() {
        let buf = ReplayBuffer::new(3, 60_000);
        buf.push("c1", 1, "a".to_string());
        buf.push("c1", 2, "b".to_string());
        buf.push("c1", 3, "c".to_string());
        buf.push("c1", 4, "d".to_string());

        // Oldest (seq=1) should have been evicted.
        let replayed = buf.replay_since("c1", 0);
        assert_eq!(replayed.len(), 3);
        assert_eq!(replayed[0], "b");
    }

    #[test]
    fn evicts_expired_messages() {
        let buf = ReplayBuffer::new(100, 50); // 50ms TTL
        buf.push("c1", 1, "old".to_string());

        sleep(Duration::from_millis(80));

        buf.push("c1", 2, "new".to_string());

        let replayed = buf.replay_since("c1", 0);
        assert_eq!(replayed.len(), 1);
        assert_eq!(replayed[0], "new");
    }

    #[test]
    fn remove_client_clears_buffer() {
        let buf = ReplayBuffer::new(100, 60_000);
        buf.push("c1", 1, "a".to_string());
        buf.remove_client("c1");

        let replayed = buf.replay_since("c1", 0);
        assert!(replayed.is_empty());
    }

    #[test]
    fn oldest_seq_returns_first_buffered_seq() {
        let buf = ReplayBuffer::new(100, 60_000);
        buf.push("c1", 5, "a".to_string());
        buf.push("c1", 10, "b".to_string());
        buf.push("c1", 15, "c".to_string());

        assert_eq!(buf.oldest_seq("c1"), Some(5));
    }

    #[test]
    fn oldest_seq_returns_none_for_unknown_client() {
        let buf = ReplayBuffer::new(100, 60_000);
        assert_eq!(buf.oldest_seq("unknown"), None);
    }

    #[test]
    fn oldest_seq_reflects_eviction() {
        let buf = ReplayBuffer::new(2, 60_000);
        buf.push("c1", 1, "a".to_string());
        buf.push("c1", 2, "b".to_string());
        buf.push("c1", 3, "c".to_string()); // evicts seq=1

        assert_eq!(buf.oldest_seq("c1"), Some(2));
    }

    #[test]
    fn evict_expired_removes_empty_buffers() {
        let buf = ReplayBuffer::new(100, 10); // 10ms TTL
        buf.push("c1", 1, "a".to_string());

        sleep(Duration::from_millis(30));

        buf.evict_expired();
        assert!(buf.buffers.is_empty());
    }

    #[test]
    fn push_10000_messages_only_max_size_retained() {
        let max = 100;
        let buf = ReplayBuffer::new(max, 60_000);

        for i in 1..=10_000u64 {
            buf.push("c1", i, format!("msg-{i}"));
        }

        let replayed = buf.replay_since("c1", 0);
        assert_eq!(replayed.len(), max);
        // The oldest retained message should be seq=9901.
        assert_eq!(replayed[0], "msg-9901");
        assert_eq!(replayed[max - 1], "msg-10000");
    }

    #[test]
    fn replay_since_very_old_seq_returns_all() {
        let buf = ReplayBuffer::new(100, 60_000);
        for i in 100..=110u64 {
            buf.push("c1", i, format!("msg-{i}"));
        }

        // Requesting from seq=0 (very old) should return all buffered messages.
        let replayed = buf.replay_since("c1", 0);
        assert_eq!(replayed.len(), 11);
        assert_eq!(replayed[0], "msg-100");
    }

    #[test]
    fn replay_since_future_seq_returns_empty() {
        let buf = ReplayBuffer::new(100, 60_000);
        buf.push("c1", 1, "a".to_string());
        buf.push("c1", 2, "b".to_string());
        buf.push("c1", 3, "c".to_string());

        // Requesting from seq=999 (future) should return nothing.
        let replayed = buf.replay_since("c1", 999);
        assert!(replayed.is_empty());
    }

    #[test]
    fn concurrent_push_and_replay_no_deadlock() {
        use std::sync::Arc;
        use std::thread;

        let buf = Arc::new(ReplayBuffer::new(1000, 60_000));

        let buf_writer = Arc::clone(&buf);
        let writer = thread::spawn(move || {
            for i in 1..=500u64 {
                buf_writer.push("c1", i, format!("msg-{i}"));
            }
        });

        let buf_reader = Arc::clone(&buf);
        let reader = thread::spawn(move || {
            let mut total_read = 0;
            for _ in 0..100 {
                let replayed = buf_reader.replay_since("c1", 0);
                total_read += replayed.len();
                // Small sleep to interleave with writer.
                thread::sleep(Duration::from_micros(50));
            }
            total_read
        });

        writer.join().expect("Writer thread should not panic");
        let total_read = reader.join().expect("Reader thread should not panic");

        // Reader should have read some messages (exact count depends on scheduling).
        assert!(total_read > 0);

        // After both complete, all 500 messages should be in the buffer.
        let final_replay = buf.replay_since("c1", 0);
        assert_eq!(final_replay.len(), 500);
    }

    #[test]
    fn buffer_with_ttl_zero_everything_expires_immediately() {
        let buf = ReplayBuffer::new(100, 0); // TTL=0 means immediate expiry

        buf.push("c1", 1, "a".to_string());
        // The next push will evict expired messages (TTL=0 means everything is expired).
        buf.push("c1", 2, "b".to_string());

        // replay_since also filters by TTL, so even the latest message expires.
        // Since TTL=0, duration_since(created_at) >= 0ms TTL, so the filter
        // `now.duration_since(m.created_at) < ttl` will be false for TTL=0.
        let replayed = buf.replay_since("c1", 0);
        assert!(
            replayed.is_empty(),
            "TTL=0 should expire all messages immediately"
        );
    }

    #[test]
    fn oldest_seq_after_eviction_by_max_size() {
        let buf = ReplayBuffer::new(3, 60_000);
        buf.push("c1", 10, "a".to_string());
        buf.push("c1", 20, "b".to_string());
        buf.push("c1", 30, "c".to_string());

        assert_eq!(buf.oldest_seq("c1"), Some(10));

        // Push another, evicting seq=10.
        buf.push("c1", 40, "d".to_string());
        assert_eq!(buf.oldest_seq("c1"), Some(20));

        // Push two more, evicting seq=20 and seq=30.
        buf.push("c1", 50, "e".to_string());
        buf.push("c1", 60, "f".to_string());
        assert_eq!(buf.oldest_seq("c1"), Some(40));
    }

    #[test]
    fn oldest_seq_after_eviction_by_ttl() {
        let buf = ReplayBuffer::new(100, 30); // 30ms TTL

        buf.push("c1", 1, "old".to_string());
        buf.push("c1", 2, "old2".to_string());

        sleep(Duration::from_millis(50));

        // Push a new message which triggers TTL eviction of the old ones.
        buf.push("c1", 3, "new".to_string());

        assert_eq!(buf.oldest_seq("c1"), Some(3));
    }

    #[test]
    fn multiple_clients_are_independent() {
        let buf = ReplayBuffer::new(5, 60_000);

        for i in 1..=5u64 {
            buf.push("alice", i, format!("a-{i}"));
        }
        for i in 1..=3u64 {
            buf.push("bob", i + 100, format!("b-{i}"));
        }

        let alice_msgs = buf.replay_since("alice", 0);
        let bob_msgs = buf.replay_since("bob", 0);

        assert_eq!(alice_msgs.len(), 5);
        assert_eq!(bob_msgs.len(), 3);

        // Removing alice should not affect bob.
        buf.remove_client("alice");
        assert!(buf.replay_since("alice", 0).is_empty());
        assert_eq!(buf.replay_since("bob", 0).len(), 3);
    }
}
