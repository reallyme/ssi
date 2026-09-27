// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Expiration-index regression coverage for the in-memory single-use store.

#![allow(clippy::expect_used)]

use std::collections::BTreeSet;
use std::sync::Arc;

use super::{
    InMemorySingleUseStore, SingleUseClock, SingleUseNamespace, SingleUseResult, SingleUseStore,
    SingleUseTime,
};

const NOW: u64 = 1_700_000_000;

struct FixedClock;

impl SingleUseClock for FixedClock {
    fn now(&self) -> SingleUseResult<SingleUseTime> {
        Ok(SingleUseTime {
            unix_seconds: NOW,
            monotonic_seconds: NOW,
        })
    }
}

#[test]
fn repeated_put_replaces_one_bounded_expiration_record() {
    let store = InMemorySingleUseStore::with_clock_and_limits(Arc::new(FixedClock), 1, 86_400);
    assert!(store.is_ok());
    let store = store.expect("the fixed test limits are valid");

    for offset in 1..=1_024 {
        assert_eq!(
            store.put(
                SingleUseNamespace::Application,
                "reusable-identifier",
                NOW + offset
            ),
            Ok(())
        );
    }

    let counts = store.lock().map(|state| {
        (
            state.entries.len(),
            state
                .monotonic_expirations
                .values()
                .map(BTreeSet::len)
                .sum(),
            state.absolute_expirations.values().map(BTreeSet::len).sum(),
        )
    });
    assert_eq!(counts, Ok((1, 1, 1)));

    assert_eq!(
        store.consume(SingleUseNamespace::Application, "reusable-identifier"),
        Ok(())
    );
    let expiration_counts = store.lock().map(|state| {
        (
            state
                .monotonic_expirations
                .values()
                .map(BTreeSet::len)
                .sum::<usize>(),
            state
                .absolute_expirations
                .values()
                .map(BTreeSet::len)
                .sum::<usize>(),
        )
    });
    assert_eq!(expiration_counts, Ok((0, 0)));
}
