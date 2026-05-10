// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2025-2026 Dendri contributors

use dashmap::DashMap;
use governor::{
    clock::DefaultClock,
    middleware::NoOpMiddleware,
    state::{InMemoryState, NotKeyed},
    Quota, RateLimiter as GovRateLimiter,
};
use std::num::NonZeroU32;

type GovLimiter = GovRateLimiter<NotKeyed, InMemoryState, DefaultClock, NoOpMiddleware>;

pub struct RateLimiter {
    buckets: DashMap<(String, String), GovLimiter>,
}

impl RateLimiter {
    pub fn new() -> Self {
        Self {
            buckets: DashMap::new(),
        }
    }

    pub fn check_and_consume(&self, client_id: &str, bucket_type: &str, limit: u32) -> bool {
        let key = (client_id.to_string(), bucket_type.to_string());
        let limit_nz = NonZeroU32::new(limit).unwrap_or(NonZeroU32::MIN);
        let entry = self
            .buckets
            .entry(key)
            .or_insert_with(|| GovRateLimiter::direct(Quota::per_second(limit_nz)));
        let allowed = entry.check().is_ok();
        if !allowed {
            tracing::debug!(client = %client_id, bucket = %bucket_type, "Rate limited");
        }
        allowed
    }

    pub fn remove_client(&self, client_id: &str) {
        let key = client_id.to_string();
        self.buckets.retain(|(c, _), _| c.as_str() != key.as_str());
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
            let _ = rl.check_and_consume(&client_id, &bucket, limit);
        }

        #[test]
        fn remove_nonexistent_client_never_panics(client_id in ".*") {
            let rl = RateLimiter::new();
            rl.remove_client(&client_id);
        }
    }

    #[test]
    fn allows_messages_within_limit() {
        let limiter = RateLimiter::new();
        for _ in 0..5 {
            assert!(limiter.check_and_consume("client1", "signaling", 5));
        }
    }

    #[test]
    fn rejects_messages_over_limit() {
        let limiter = RateLimiter::new();
        for _ in 0..10 {
            limiter.check_and_consume("client1", "signaling", 10);
        }
        assert!(!limiter.check_and_consume("client1", "signaling", 10));
    }

    #[test]
    fn separate_buckets_per_type() {
        let limiter = RateLimiter::new();
        for _ in 0..2 {
            limiter.check_and_consume("client1", "signaling", 2);
        }
        assert!(!limiter.check_and_consume("client1", "signaling", 2));
        assert!(limiter.check_and_consume("client1", "data", 100));
    }

    #[test]
    fn separate_buckets_per_client() {
        let limiter = RateLimiter::new();
        for _ in 0..3 {
            limiter.check_and_consume("client1", "signaling", 3);
        }
        assert!(!limiter.check_and_consume("client1", "signaling", 3));
        assert!(limiter.check_and_consume("client2", "signaling", 3));
    }

    #[test]
    fn remove_client_cleans_all_buckets() {
        let limiter = RateLimiter::new();
        limiter.check_and_consume("client1", "signaling", 10);
        limiter.check_and_consume("client1", "data", 100);
        limiter.check_and_consume("client2", "signaling", 10);

        limiter.remove_client("client1");

        // client1 buckets removed, client2 buckets kept.
        let keys: Vec<_> = limiter.buckets.iter().map(|e| e.key().clone()).collect();
        assert!(!keys.iter().any(|(c, _)| c == "client1"));
        assert!(keys.iter().any(|(c, _)| c == "client2"));
    }

    #[test]
    fn tokens_refill_after_time_passes() {
        let limiter = RateLimiter::new();
        for _ in 0..5 {
            limiter.check_and_consume("c1", "sig", 5);
        }
        assert!(!limiter.check_and_consume("c1", "sig", 5));

        // GCRA refills over time; 1.1 s is enough for a full refill at 5/s.
        std::thread::sleep(std::time::Duration::from_millis(1100));
        assert!(limiter.check_and_consume("c1", "sig", 5));
    }

    #[test]
    fn burst_consume_all_wait_consume_again() {
        let limiter = RateLimiter::new();
        let limit = 3u32;

        for _ in 0..limit {
            assert!(limiter.check_and_consume("burst", "data", limit));
        }
        assert!(!limiter.check_and_consume("burst", "data", limit));

        std::thread::sleep(std::time::Duration::from_millis(600));
        // GCRA allows one more after partial refill.
        assert!(limiter.check_and_consume("burst", "data", limit));
    }

    #[test]
    fn two_bucket_types_for_same_client_are_independent() {
        let limiter = RateLimiter::new();

        for _ in 0..2 {
            limiter.check_and_consume("client1", "signaling", 2);
        }
        assert!(!limiter.check_and_consume("client1", "signaling", 2));

        for _ in 0..5 {
            assert!(limiter.check_and_consume("client1", "data", 5));
        }
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

        // GCRA may allow slightly more or fewer than `limit` in a burst
        // depending on the timing of the test, but we should see roughly
        // `limit` passes and the rest failures.
        assert!(passed >= limit as usize);
        assert!(failed > 0);
    }

    #[test]
    fn remove_client_with_nonexistent_client_does_not_panic() {
        let limiter = RateLimiter::new();
        limiter.remove_client("ghost");
        limiter.remove_client("");
        limiter.remove_client("nonexistent-client-id-12345");
        assert!(limiter.check_and_consume("new_client", "sig", 5));
    }
}
