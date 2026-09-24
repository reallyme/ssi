// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Expiration-index regression coverage for the in-memory single-use store.

use std::collections::BTreeSet;

use super::{InMemorySingleUseStore, SingleUseStore};

const NOW: u64 = 1_700_000_000;

#[test]
fn repeated_put_replaces_one_bounded_expiration_record() {
    let store = InMemorySingleUseStore::with_max_entries(1);
    assert!(store.is_ok());
    let store = store.unwrap_or_default();

    for offset in 1..=1_024 {
        assert_eq!(store.put("reusable-identifier", NOW + offset), Ok(()));
    }

    let counts = store.lock().map(|state| {
        (
            state.entries.len(),
            state.expirations.values().map(BTreeSet::len).sum(),
        )
    });
    assert_eq!(counts, Ok((1, 1)));

    assert_eq!(store.consume("reusable-identifier", NOW), Ok(()));
    let expiration_count = store
        .lock()
        .map(|state| state.expirations.values().map(BTreeSet::len).sum());
    assert_eq!(expiration_count, Ok(0));
}
