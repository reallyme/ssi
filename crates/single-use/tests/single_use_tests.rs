// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Single-use store behavior tests.

#![allow(clippy::expect_used)]

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;

use reallyme_single_use::{
    InMemorySingleUseStore as RawInMemorySingleUseStore, SingleUseClock, SingleUseError,
    SingleUseNamespace, SingleUseResult, SingleUseStore, SingleUseTime,
    DEFAULT_MAX_SINGLE_USE_TTL_SECS,
};

const NOW: u64 = 1_700_000_000;
const NAMESPACE: SingleUseNamespace = SingleUseNamespace::Application;

#[derive(Default)]
struct TestClock {
    wall: AtomicU64,
    monotonic: AtomicU64,
}

impl TestClock {
    fn at(now_unix: u64) -> Self {
        Self {
            wall: AtomicU64::new(now_unix),
            monotonic: AtomicU64::new(now_unix),
        }
    }

    fn set(&self, now_unix: u64) {
        self.wall.store(now_unix, Ordering::SeqCst);
        self.monotonic.store(now_unix, Ordering::SeqCst);
    }

    fn set_wall(&self, now_unix: u64) {
        self.wall.store(now_unix, Ordering::SeqCst);
    }
}

impl SingleUseClock for TestClock {
    fn now(&self) -> SingleUseResult<SingleUseTime> {
        Ok(SingleUseTime {
            unix_seconds: self.wall.load(Ordering::SeqCst),
            monotonic_seconds: self.monotonic.load(Ordering::SeqCst),
        })
    }
}

struct InMemorySingleUseStore {
    inner: RawInMemorySingleUseStore,
    clock: Arc<TestClock>,
}

impl Default for InMemorySingleUseStore {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemorySingleUseStore {
    fn new() -> Self {
        Self::with_limits(65_536, DEFAULT_MAX_SINGLE_USE_TTL_SECS)
            .expect("the fixed test limits are valid")
    }

    fn with_max_entries(max_entries: usize) -> SingleUseResult<Self> {
        Self::with_limits(max_entries, DEFAULT_MAX_SINGLE_USE_TTL_SECS)
    }

    fn with_limits(max_entries: usize, max_ttl_secs: u64) -> SingleUseResult<Self> {
        let clock = Arc::new(TestClock::at(NOW));
        let clock_source: Arc<dyn SingleUseClock> = clock.clone();
        let inner = RawInMemorySingleUseStore::with_clock_and_limits(
            clock_source,
            max_entries,
            max_ttl_secs,
        )?;
        Ok(Self { inner, clock })
    }

    fn put(&self, key: &str, now_unix: u64, expires_at_unix: u64) -> SingleUseResult<()> {
        self.clock.set(now_unix);
        self.inner.put(NAMESPACE, key, expires_at_unix)
    }

    fn record_once(&self, key: &str, now_unix: u64, expires_at_unix: u64) -> SingleUseResult<()> {
        self.clock.set(now_unix);
        self.inner.record_once(NAMESPACE, key, expires_at_unix)
    }

    fn consume(&self, key: &str, now_unix: u64) -> SingleUseResult<()> {
        self.clock.set(now_unix);
        self.inner.consume(NAMESPACE, key)
    }

    fn prune(&self, now_unix: u64) -> SingleUseResult<()> {
        self.clock.set(now_unix);
        self.inner.prune()
    }
}

#[test]
fn stored_value_can_be_consumed() {
    let store = InMemorySingleUseStore::new();
    assert_eq!(store.put("nonce-ok", NOW, NOW + 60), Ok(()));

    assert_eq!(store.consume("nonce-ok", NOW), Ok(()));
}

#[test]
fn value_can_be_consumed_exactly_once() {
    let store = InMemorySingleUseStore::new();
    assert_eq!(store.put("nonce-1", NOW, NOW + 60), Ok(()));

    assert_eq!(store.consume("nonce-1", NOW), Ok(()));
    // A second consume of the same value must be rejected (replay).
    assert_eq!(store.consume("nonce-1", NOW), Err(SingleUseError::Rejected));
}

#[test]
fn replay_value_is_rejected_after_first_consume() {
    let store = InMemorySingleUseStore::new();
    assert_eq!(store.put("nonce-replay", NOW, NOW + 60), Ok(()));

    assert_eq!(store.consume("nonce-replay", NOW), Ok(()));
    assert_eq!(
        store.consume("nonce-replay", NOW),
        Err(SingleUseError::Rejected)
    );
}

#[test]
fn concurrent_consume_allows_one_success() {
    let store = Arc::new(InMemorySingleUseStore::new());
    assert_eq!(store.put("nonce-concurrent", NOW, NOW + 60), Ok(()));

    let first_store = Arc::clone(&store);
    let first = thread::spawn(move || first_store.consume("nonce-concurrent", NOW));
    let second_store = Arc::clone(&store);
    let second = thread::spawn(move || second_store.consume("nonce-concurrent", NOW));

    let first_join = first.join();
    let second_join = second.join();
    assert!(first_join.is_ok(), "first consume thread must not panic");
    assert!(second_join.is_ok(), "second consume thread must not panic");
    let first_result = first_join.unwrap_or(Err(SingleUseError::Unavailable));
    let second_result = second_join.unwrap_or(Err(SingleUseError::Unavailable));
    let successes = usize::from(first_result == Ok(())) + usize::from(second_result == Ok(()));
    let rejections = usize::from(first_result == Err(SingleUseError::Rejected))
        + usize::from(second_result == Err(SingleUseError::Rejected));

    assert_eq!(successes, 1);
    assert_eq!(rejections, 1);
}

#[test]
fn unknown_value_is_rejected() {
    let store = InMemorySingleUseStore::new();
    assert_eq!(
        store.consume("never-issued", NOW),
        Err(SingleUseError::Rejected)
    );
}

#[test]
fn expired_value_is_rejected() {
    let store = InMemorySingleUseStore::new();
    assert_eq!(store.put("nonce-2", NOW - 60, NOW), Ok(()));
    // Consuming exactly at expiry (expires_at == now) is rejected.
    assert_eq!(store.consume("nonce-2", NOW), Err(SingleUseError::Rejected));
}

#[test]
fn prune_removes_expired_entries() {
    let store = InMemorySingleUseStore::new();
    assert_eq!(store.put("stale", NOW - 60, NOW), Ok(()));
    assert_eq!(store.put("fresh", NOW, NOW + 60), Ok(()));
    assert_eq!(store.prune(NOW), Ok(()));

    assert_eq!(store.consume("stale", NOW), Err(SingleUseError::Rejected));
    assert_eq!(store.consume("fresh", NOW), Ok(()));
}

#[test]
fn namespaces_have_independent_keys_and_share_global_capacity() {
    let clock = Arc::new(TestClock::at(NOW));
    let clock_source: Arc<dyn SingleUseClock> = clock;
    let store = RawInMemorySingleUseStore::with_clock_and_limits(clock_source, 1, 300)
        .expect("the fixed test limits are valid");

    assert_eq!(
        store.record_once(SingleUseNamespace::Dpop, "shared", NOW + 60),
        Ok(())
    );
    assert_eq!(
        store.record_once(SingleUseNamespace::WalletAttestation, "shared", NOW + 60),
        Err(SingleUseError::CapacityExceeded)
    );
}

#[test]
fn one_protocol_cannot_exhaust_another_protocols_quota() {
    let clock = Arc::new(TestClock::at(NOW));
    let clock_source: Arc<dyn SingleUseClock> = clock;
    let store = RawInMemorySingleUseStore::with_clock_and_limits(clock_source, 10, 300)
        .expect("the fixed test limits are valid");

    for key in ["dpop-1", "dpop-2"] {
        assert_eq!(
            store.record_once(SingleUseNamespace::Dpop, key, NOW + 60),
            Ok(())
        );
    }
    assert_eq!(
        store.record_once(SingleUseNamespace::Dpop, "dpop-3", NOW + 60),
        Err(SingleUseError::CapacityExceeded)
    );
    assert_eq!(
        store.record_once(SingleUseNamespace::WalletAttestation, "wallet-1", NOW + 60,),
        Ok(())
    );
}

#[test]
fn clock_rollback_is_clamped_without_pruning_replay_state() {
    let clock = Arc::new(TestClock::at(NOW));
    let clock_source: Arc<dyn SingleUseClock> = clock.clone();
    let store = RawInMemorySingleUseStore::with_clock_and_limits(clock_source, 8, 300)
        .expect("the fixed test limits are valid");
    assert_eq!(
        store.record_once(SingleUseNamespace::Dpop, "jti", NOW + 60),
        Ok(())
    );

    clock.set(NOW - 1);
    assert_eq!(
        store.record_once(SingleUseNamespace::Dpop, "other", NOW + 60),
        Ok(())
    );
    clock.set(NOW);
    assert_eq!(
        store.record_once(SingleUseNamespace::Dpop, "jti", NOW + 60),
        Err(SingleUseError::Rejected)
    );
}

#[test]
fn forward_wall_clock_jump_does_not_release_replay_records() {
    let clock = Arc::new(TestClock::at(NOW));
    let clock_source: Arc<dyn SingleUseClock> = clock.clone();
    let store = RawInMemorySingleUseStore::with_clock_and_limits(clock_source, 8, 300)
        .expect("the fixed test limits are valid");
    assert_eq!(
        store.record_once(SingleUseNamespace::Dpop, "retained-jti", NOW + 60),
        Ok(())
    );

    clock.set_wall(NOW + 10_000);
    assert_eq!(
        store.record_once(SingleUseNamespace::Dpop, "during-jump", NOW + 60),
        Err(SingleUseError::InvalidExpiry)
    );

    clock.set_wall(NOW);
    assert_eq!(
        store.record_once(SingleUseNamespace::Dpop, "retained-jti", NOW + 60),
        Err(SingleUseError::Rejected)
    );
    assert_eq!(
        store.record_once(SingleUseNamespace::Dpop, "after-correction", NOW + 60),
        Ok(())
    );
}

#[test]
fn absolute_deadline_expires_consumables_but_not_replay_records_during_a_clock_jump() {
    let clock = Arc::new(TestClock::at(NOW));
    let clock_source: Arc<dyn SingleUseClock> = clock.clone();
    let store = RawInMemorySingleUseStore::with_clock_and_limits(clock_source, 8, 300)
        .expect("the fixed test limits are valid");
    assert_eq!(
        store.put(
            SingleUseNamespace::OpenId4VciCredentialNonce,
            "nonce",
            NOW + 60,
        ),
        Ok(())
    );
    assert_eq!(
        store.record_once(SingleUseNamespace::Dpop, "jti", NOW + 60),
        Ok(())
    );

    clock.set_wall(NOW + 3_600);
    assert_eq!(
        store.consume(SingleUseNamespace::OpenId4VciCredentialNonce, "nonce"),
        Err(SingleUseError::Rejected)
    );

    clock.set_wall(NOW);
    assert_eq!(
        store.record_once(SingleUseNamespace::Dpop, "jti", NOW + 60),
        Err(SingleUseError::Rejected)
    );
}

#[test]
fn consume_rejects_absolute_expiry_when_monotonic_time_pauses() {
    let clock = Arc::new(TestClock::at(NOW));
    let clock_source: Arc<dyn SingleUseClock> = clock.clone();
    let store = RawInMemorySingleUseStore::with_clock_and_limits(clock_source, 8, 300)
        .expect("the fixed test limits are valid");
    assert_eq!(
        store.put(
            SingleUseNamespace::OpenId4VciCredentialNonce,
            "sleep-spanning-nonce",
            NOW + 60,
        ),
        Ok(())
    );

    // A suspended process may observe wall-clock progress without equivalent
    // progress from its process-monotonic clock.
    clock.set_wall(NOW + 3_600);
    assert_eq!(
        store.consume(
            SingleUseNamespace::OpenId4VciCredentialNonce,
            "sleep-spanning-nonce",
        ),
        Err(SingleUseError::Rejected)
    );
}

#[test]
fn prune_preserves_unexpired_value() {
    let store = InMemorySingleUseStore::new();
    assert_eq!(store.put("fresh-only", NOW, NOW + 60), Ok(()));
    assert_eq!(store.prune(NOW), Ok(()));

    assert_eq!(store.consume("fresh-only", NOW), Ok(()));
}

#[test]
fn empty_key_is_invalid() {
    let store = InMemorySingleUseStore::new();
    assert_eq!(
        store.put("", NOW, NOW + 60),
        Err(SingleUseError::InvalidKey)
    );
    assert_eq!(store.consume("", NOW), Err(SingleUseError::InvalidKey));
}

#[test]
fn oversized_key_is_invalid() {
    let store = InMemorySingleUseStore::new();
    let key = "x".repeat(1_025);
    assert_eq!(
        store.put(&key, NOW, NOW + 60),
        Err(SingleUseError::InvalidKey)
    );
}

#[test]
fn bounded_store_rejects_new_entries_at_capacity() {
    let store = InMemorySingleUseStore::with_max_entries(1);
    assert!(store.is_ok());
    let store = store.expect("the fixed test limits are valid");
    assert_eq!(store.put("first", NOW, NOW + 60), Ok(()));
    assert_eq!(
        store.put("second", NOW, NOW + 60),
        Err(SingleUseError::CapacityExceeded)
    );
    assert_eq!(store.put("first", NOW, NOW + 120), Ok(()));
}

#[test]
fn replacement_expiry_supersedes_the_previous_schedule() {
    let store =
        InMemorySingleUseStore::with_max_entries(1).expect("the fixed test limits are valid");
    assert_eq!(store.put("reissued", NOW, NOW + 1), Ok(()));
    assert_eq!(store.put("reissued", NOW, NOW + 60), Ok(()));

    assert_eq!(store.prune(NOW + 1), Ok(()));
    assert_eq!(store.consume("reissued", NOW + 2), Ok(()));
}

#[test]
fn record_once_rejects_replay_and_reclaims_expired_capacity() {
    let store =
        InMemorySingleUseStore::with_max_entries(1).expect("the fixed test limits are valid");
    assert_eq!(store.record_once("jti-1", NOW, NOW + 1), Ok(()));
    assert_eq!(
        store.record_once("jti-1", NOW, NOW + 60),
        Err(SingleUseError::Rejected)
    );
    assert_eq!(store.record_once("jti-2", NOW + 1, NOW + 60), Ok(()));
}

#[test]
fn consumable_and_recorded_values_use_separate_keyspaces() {
    let store =
        InMemorySingleUseStore::with_max_entries(10).expect("the fixed test limits are valid");
    assert_eq!(store.put("shared-value", NOW, NOW + 60), Ok(()));
    assert_eq!(store.record_once("shared-value", NOW, NOW + 60), Ok(()));

    assert_eq!(store.consume("shared-value", NOW), Ok(()));
    assert_eq!(
        store.record_once("shared-value", NOW, NOW + 60),
        Err(SingleUseError::Rejected)
    );
}

#[test]
fn expiry_must_follow_now_and_respect_max_lifetime() {
    let store = InMemorySingleUseStore::new();
    let latest = NOW + DEFAULT_MAX_SINGLE_USE_TTL_SECS;

    assert_eq!(
        store.put("at-now", NOW, NOW),
        Err(SingleUseError::InvalidExpiry)
    );
    assert_eq!(
        store.put("past", NOW, NOW - 1),
        Err(SingleUseError::InvalidExpiry)
    );
    assert_eq!(
        store.put("too-long", NOW, latest + 1),
        Err(SingleUseError::InvalidExpiry)
    );
    assert_eq!(
        store.put("forever", NOW, u64::MAX),
        Err(SingleUseError::InvalidExpiry)
    );
    assert_eq!(store.put("longest", NOW, latest), Ok(()));

    assert_eq!(
        store.record_once("jti-forever", NOW, u64::MAX),
        Err(SingleUseError::InvalidExpiry)
    );
    assert_eq!(
        store.record_once("jti-expired", NOW, NOW),
        Err(SingleUseError::InvalidExpiry)
    );
    assert_eq!(
        store.put("overflow", u64::MAX, u64::MAX),
        Err(SingleUseError::InvalidExpiry)
    );
}

#[test]
fn custom_lifetime_ceiling_is_enforced() {
    let store =
        InMemorySingleUseStore::with_limits(8, 300).expect("the fixed test limits are valid");

    assert_eq!(store.put("ok", NOW, NOW + 300), Ok(()));
    assert_eq!(
        store.record_once("too-long", NOW, NOW + 301),
        Err(SingleUseError::InvalidExpiry)
    );
    assert_eq!(
        InMemorySingleUseStore::with_limits(8, 0).map(|_| ()),
        Err(SingleUseError::InvalidExpiry)
    );
}

#[test]
fn put_reclaims_expired_capacity_before_rejecting() {
    let store =
        InMemorySingleUseStore::with_max_entries(1).expect("the fixed test limits are valid");
    assert_eq!(store.put("first", NOW, NOW + 1), Ok(()));
    assert_eq!(
        store.put("second", NOW, NOW + 60),
        Err(SingleUseError::CapacityExceeded)
    );

    // Once "first" has expired, put prunes it instead of failing closed.
    assert_eq!(store.put("second", NOW + 1, NOW + 60), Ok(()));
    assert_eq!(
        store.consume("first", NOW + 1),
        Err(SingleUseError::Rejected)
    );
    assert_eq!(store.consume("second", NOW + 2), Ok(()));
}
