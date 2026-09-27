// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{SingleUseKeyKind, SingleUseNamespace, SingleUseState, StoredExpiration, StoredKey};

#[test]
fn clock_rollback_reschedules_recorded_key_beyond_current_time() {
    let mut state = SingleUseState::default();
    let key = StoredKey::new(
        SingleUseNamespace::Application,
        SingleUseKeyKind::Recorded,
        "recorded",
    );
    let expiration = StoredExpiration {
        expires_at_unix: 2_000,
        monotonic_deadline: 1_000,
    };
    state.entries.insert(key.clone(), expiration);
    let namespace_index = super::namespace_index(SingleUseNamespace::Application);
    assert!(state.namespace_counts.get(namespace_index).is_some());
    if let Some(count) = state.namespace_counts.get_mut(namespace_index) {
        *count = 1;
    }
    state.schedule_expiration(&key, expiration);

    state.prune(1_000, 1_500);

    assert!(state.entries.contains_key(&key));
    assert!(!state.monotonic_expirations.contains_key(&1_000));
    assert!(state.monotonic_expirations.contains_key(&1_500));
}
