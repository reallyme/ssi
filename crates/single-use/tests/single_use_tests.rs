// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Single-use store behavior tests.

use std::sync::Arc;
use std::thread;

use reallyme_single_use::{
    InMemorySingleUseStore, SingleUseError, SingleUseStore, DEFAULT_MAX_SINGLE_USE_TTL_SECS,
};

const NOW: u64 = 1_700_000_000;

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
    assert_eq!(store.put("fresh", NOW, NOW + 60), Ok(()));
    assert_eq!(store.put("stale", NOW - 60, NOW), Ok(()));
    assert_eq!(store.prune(NOW), Ok(()));

    assert_eq!(store.consume("stale", NOW), Err(SingleUseError::Rejected));
    assert_eq!(store.consume("fresh", NOW), Ok(()));
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
    let store = store.unwrap_or_default();
    assert_eq!(store.put("first", NOW, NOW + 60), Ok(()));
    assert_eq!(
        store.put("second", NOW, NOW + 60),
        Err(SingleUseError::CapacityExceeded)
    );
    assert_eq!(store.put("first", NOW, NOW + 120), Ok(()));
}

#[test]
fn replacement_expiry_supersedes_the_previous_schedule() {
    let store = InMemorySingleUseStore::with_max_entries(1).unwrap_or_default();
    assert_eq!(store.put("reissued", NOW, NOW + 1), Ok(()));
    assert_eq!(store.put("reissued", NOW, NOW + 60), Ok(()));

    assert_eq!(store.prune(NOW + 1), Ok(()));
    assert_eq!(store.consume("reissued", NOW + 2), Ok(()));
}

#[test]
fn record_once_rejects_replay_and_reclaims_expired_capacity() {
    let store = InMemorySingleUseStore::with_max_entries(1).unwrap_or_default();
    assert_eq!(store.record_once("jti-1", NOW, NOW + 1), Ok(()));
    assert_eq!(
        store.record_once("jti-1", NOW, NOW + 60),
        Err(SingleUseError::Rejected)
    );
    assert_eq!(store.record_once("jti-2", NOW + 1, NOW + 60), Ok(()));
}

#[test]
fn consumable_and_recorded_values_use_separate_keyspaces() {
    let store = InMemorySingleUseStore::with_max_entries(2).unwrap_or_default();
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
    let store = InMemorySingleUseStore::with_limits(8, 300).unwrap_or_default();

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
    let store = InMemorySingleUseStore::with_max_entries(1).unwrap_or_default();
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
