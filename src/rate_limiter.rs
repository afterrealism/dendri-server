use std::time::Instant;

use dashmap::DashMap;

/// Per-client token bucket rate limiter.
///
/// Each client gets independent buckets for different message categories
/// (e.g. "signaling" vs "data"). Buckets refill at a steady rate and
/// reject messages when empty — no disconnection, just rejection.
pub struct RateLimiter {
    buckets: DashMap<String, TokenBucket>,
}

struct TokenBucket {
    tokens: f64,
    max_tokens: f64,
    refill_rate: f64, // tokens per second
    last_refill: Instant,
}

impl TokenBucket {
    fn new(max_tokens: f64) -> Self {
        Self {
            tokens: max_tokens,
            max_tokens,
            refill_rate: max_tokens, // refill to full in 1 second
            last_refill: Instant::now(),
        }
    }

    /// Refill tokens based on elapsed time, then try to consume one.
    /// Returns `true` if the request is allowed.
    fn try_consume(&mut self) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.refill_rate).min(self.max_tokens);
        self.last_refill = now;

        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

impl RateLimiter {
    /// Create an empty rate limiter with no buckets.
    pub fn new() -> Self {
        Self {
            buckets: DashMap::new(),
        }
    }

    /// Check whether `client_id` is allowed to send a message of `bucket_type`.
    ///
    /// `limit` is the maximum messages-per-second for this bucket type.
    /// Returns `true` if the message is allowed, `false` if rate-limited.
    ///
    /// Buckets are created lazily on first access per (client, type) pair.
    pub fn check_and_consume(&self, client_id: &str, bucket_type: &str, limit: u32) -> bool {
        let key = format!("{client_id}:{bucket_type}");
        let mut entry = self
            .buckets
            .entry(key)
            .or_insert_with(|| TokenBucket::new(f64::from(limit)));
        let allowed = entry.try_consume();
        if !allowed {
            tracing::debug!(client = %client_id, bucket = %bucket_type, "Rate limited");
        }
        allowed
    }

    /// Remove all buckets for a disconnected client.
    pub fn remove_client(&self, client_id: &str) {
        let prefix = format!("{client_id}:");
        self.buckets.retain(|key, _| !key.starts_with(&prefix));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn check_and_consume_never_panics(
            client_id in "[a-z]{3,10}",
            bucket in "[a-z]{3,10}",
            limit in 1u32..1000,
        ) {
            let rl = RateLimiter::new();
            // Should never panic regardless of inputs
            let _ = rl.check_and_consume(&client_id, &bucket, limit);
        }

        #[test]
        fn remove_nonexistent_client_never_panics(client_id in ".*") {
            let rl = RateLimiter::new();
            rl.remove_client(&client_id); // Should not panic
        }
    }

    #[test]
    fn allows_messages_within_limit() {
        let limiter = RateLimiter::new();
        // With limit=5, we should be able to send 5 messages immediately.
        for _ in 0..5 {
            assert!(limiter.check_and_consume("client1", "signaling", 5));
        }
    }

    #[test]
    fn rejects_messages_over_limit() {
        let limiter = RateLimiter::new();
        // Exhaust the bucket.
        for _ in 0..10 {
            limiter.check_and_consume("client1", "signaling", 10);
        }
        // Next message should be rejected.
        assert!(!limiter.check_and_consume("client1", "signaling", 10));
    }

    #[test]
    fn separate_buckets_per_type() {
        let limiter = RateLimiter::new();
        // Exhaust signaling bucket.
        for _ in 0..2 {
            limiter.check_and_consume("client1", "signaling", 2);
        }
        assert!(!limiter.check_and_consume("client1", "signaling", 2));
        // Data bucket should still be available.
        assert!(limiter.check_and_consume("client1", "data", 100));
    }

    #[test]
    fn separate_buckets_per_client() {
        let limiter = RateLimiter::new();
        // Exhaust client1's bucket.
        for _ in 0..3 {
            limiter.check_and_consume("client1", "signaling", 3);
        }
        assert!(!limiter.check_and_consume("client1", "signaling", 3));
        // client2 should still be allowed.
        assert!(limiter.check_and_consume("client2", "signaling", 3));
    }

    #[test]
    fn remove_client_cleans_all_buckets() {
        let limiter = RateLimiter::new();
        limiter.check_and_consume("client1", "signaling", 10);
        limiter.check_and_consume("client1", "data", 100);
        limiter.check_and_consume("client2", "signaling", 10);

        limiter.remove_client("client1");

        // client1 buckets removed — next access creates a fresh bucket.
        // client2 buckets should still exist.
        assert!(limiter
            .buckets
            .iter()
            .all(|e| !e.key().starts_with("client1:")));
        assert!(limiter
            .buckets
            .iter()
            .any(|e| e.key().starts_with("client2:")));
    }

    #[test]
    fn tokens_refill_after_time_passes() {
        let limiter = RateLimiter::new();
        // Exhaust all 5 tokens.
        for _ in 0..5 {
            limiter.check_and_consume("c1", "sig", 5);
        }
        assert!(!limiter.check_and_consume("c1", "sig", 5));

        // Wait > 1 second for full refill (refill_rate = max_tokens per second).
        std::thread::sleep(std::time::Duration::from_millis(1100));

        // Should be able to consume again after refill.
        assert!(limiter.check_and_consume("c1", "sig", 5));
    }

    #[test]
    fn burst_consume_all_wait_consume_again() {
        let limiter = RateLimiter::new();
        let limit = 3u32;

        // Consume all tokens in a burst.
        for _ in 0..limit {
            assert!(limiter.check_and_consume("burst", "data", limit));
        }
        // Bucket is now empty.
        assert!(!limiter.check_and_consume("burst", "data", limit));

        // Wait for partial refill (~0.5 seconds should refill ~1.5 tokens).
        std::thread::sleep(std::time::Duration::from_millis(600));

        // Should be able to consume at least 1 token.
        assert!(limiter.check_and_consume("burst", "data", limit));
    }

    #[test]
    fn two_bucket_types_for_same_client_are_independent() {
        let limiter = RateLimiter::new();

        // Exhaust the "signaling" bucket for client1.
        for _ in 0..2 {
            limiter.check_and_consume("client1", "signaling", 2);
        }
        assert!(!limiter.check_and_consume("client1", "signaling", 2));

        // The "data" bucket for the same client should be unaffected.
        for _ in 0..5 {
            assert!(limiter.check_and_consume("client1", "data", 5));
        }
        // And a third bucket type should also be independent.
        assert!(limiter.check_and_consume("client1", "heartbeat", 10));
    }

    #[test]
    fn rapid_requests_first_n_pass_rest_fail() {
        let limiter = RateLimiter::new();
        let limit = 20u32;
        let total_requests = 100;

        let mut passed = 0;
        let mut failed = 0;
        for _ in 0..total_requests {
            if limiter.check_and_consume("rapid", "sig", limit) {
                passed += 1;
            } else {
                failed += 1;
            }
        }

        // Exactly `limit` should pass (the initial bucket), remainder should fail.
        assert_eq!(passed, limit as usize);
        assert_eq!(failed, total_requests - limit as usize);
    }

    #[test]
    fn remove_client_with_nonexistent_client_does_not_panic() {
        let limiter = RateLimiter::new();
        // Should not panic or error when removing a client that was never registered.
        limiter.remove_client("ghost");
        limiter.remove_client("");
        limiter.remove_client("nonexistent-client-id-12345");

        // Verify the limiter is still functional afterward.
        assert!(limiter.check_and_consume("new_client", "sig", 5));
    }
}
