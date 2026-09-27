// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Tracks bounded replay entries and their monotonic expiration index.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use zeroize::Zeroize;

use super::{namespace_index, SingleUseNamespace, SINGLE_USE_NAMESPACE_COUNT};

#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(super) enum SingleUseKeyKind {
    Consumable,
    Recorded,
}

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(super) struct StoredKey {
    namespace: SingleUseNamespace,
    kind: SingleUseKeyKind,
    value: String,
}

impl StoredKey {
    pub(super) fn new(namespace: SingleUseNamespace, kind: SingleUseKeyKind, value: &str) -> Self {
        Self {
            namespace,
            kind,
            value: value.to_owned(),
        }
    }

    const fn is_recorded(&self) -> bool {
        matches!(self.kind, SingleUseKeyKind::Recorded)
    }
}

impl Drop for StoredKey {
    fn drop(&mut self) {
        self.value.zeroize();
    }
}

#[derive(Default)]
pub(super) struct SingleUseState {
    pub(super) entries: HashMap<StoredKey, StoredExpiration>,
    pub(super) monotonic_expirations: BTreeMap<u64, BTreeSet<StoredKey>>,
    pub(super) absolute_expirations: BTreeMap<u64, BTreeSet<StoredKey>>,
    pub(super) namespace_counts: [usize; SINGLE_USE_NAMESPACE_COUNT],
    latest_monotonic_seconds: Option<u64>,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) struct StoredExpiration {
    pub(super) expires_at_unix: u64,
    pub(super) monotonic_deadline: u64,
}

impl SingleUseState {
    pub(super) fn remove_entry(
        &mut self,
        key: &StoredKey,
    ) -> Option<(StoredKey, StoredExpiration)> {
        let index = namespace_index(key.namespace);
        let next_count = self.namespace_counts.get(index)?.checked_sub(1)?;
        let removed = self.entries.remove_entry(key)?;
        let count = self.namespace_counts.get_mut(index)?;
        *count = next_count;
        Some(removed)
    }

    pub(super) fn schedule_expiration(&mut self, key: &StoredKey, expiration: StoredExpiration) {
        self.monotonic_expirations
            .entry(expiration.monotonic_deadline)
            .or_default()
            .insert(key.clone());
        self.absolute_expirations
            .entry(expiration.expires_at_unix)
            .or_default()
            .insert(key.clone());
    }

    pub(super) fn unschedule_expiration(&mut self, key: &StoredKey, expiration: StoredExpiration) {
        remove_scheduled_key(
            &mut self.monotonic_expirations,
            expiration.monotonic_deadline,
            key,
        );
        remove_scheduled_key(
            &mut self.absolute_expirations,
            expiration.expires_at_unix,
            key,
        );
    }

    pub(super) fn prune(&mut self, monotonic_now: u64, unix_now: u64) {
        self.prune_monotonic(monotonic_now, unix_now);
        self.prune_absolute(monotonic_now, unix_now);
    }

    pub(super) fn observe_monotonic_time(&mut self, observed: u64) -> u64 {
        let effective = self
            .latest_monotonic_seconds
            .map_or(observed, |latest| latest.max(observed));
        self.latest_monotonic_seconds = Some(effective);
        effective
    }

    fn prune_monotonic(&mut self, monotonic_now: u64, unix_now: u64) {
        let mut deferred = Vec::new();
        while self
            .monotonic_expirations
            .first_key_value()
            .is_some_and(|(deadline, _)| *deadline <= monotonic_now)
        {
            let Some((deadline, mut keys)) = self.monotonic_expirations.pop_first() else {
                break;
            };
            while let Some(key) = keys.pop_first() {
                let expiration = self.entries.get(&key).copied();
                let Some(value) = expiration.filter(|value| value.monotonic_deadline == deadline)
                else {
                    continue;
                };
                if key.is_recorded() && value.expires_at_unix > unix_now {
                    let remaining = value.expires_at_unix.saturating_sub(unix_now);
                    let next_deadline = monotonic_now.saturating_add(remaining);
                    if let Some(entry) = self.entries.get_mut(&key) {
                        entry.monotonic_deadline = next_deadline;
                    }
                    deferred.push((next_deadline, key));
                    continue;
                }
                let _removed_entry = self.remove_entry(&key);
                remove_scheduled_key(&mut self.absolute_expirations, value.expires_at_unix, &key);
            }
        }
        for (deadline, key) in deferred {
            self.monotonic_expirations
                .entry(deadline)
                .or_default()
                .insert(key);
        }
    }

    fn prune_absolute(&mut self, monotonic_now: u64, unix_now: u64) {
        let mut deferred = Vec::new();
        while self
            .absolute_expirations
            .first_key_value()
            .is_some_and(|(deadline, _)| *deadline <= unix_now)
        {
            let Some((deadline, mut keys)) = self.absolute_expirations.pop_first() else {
                break;
            };
            while let Some(key) = keys.pop_first() {
                let expiration = self.entries.get(&key).copied();
                let Some(value) = expiration.filter(|value| value.expires_at_unix == deadline)
                else {
                    continue;
                };
                if key.is_recorded() && value.monotonic_deadline > monotonic_now {
                    let remaining = value.monotonic_deadline.saturating_sub(monotonic_now);
                    let next_deadline = unix_now.saturating_add(remaining);
                    if let Some(entry) = self.entries.get_mut(&key) {
                        entry.expires_at_unix = next_deadline;
                    }
                    deferred.push((next_deadline, key));
                    continue;
                }
                let _removed_entry = self.remove_entry(&key);
                remove_scheduled_key(
                    &mut self.monotonic_expirations,
                    value.monotonic_deadline,
                    &key,
                );
            }
        }
        for (deadline, key) in deferred {
            self.absolute_expirations
                .entry(deadline)
                .or_default()
                .insert(key);
        }
    }
}

fn remove_scheduled_key(
    expirations: &mut BTreeMap<u64, BTreeSet<StoredKey>>,
    deadline: u64,
    key: &StoredKey,
) {
    let remove_bucket = if let Some(keys) = expirations.get_mut(&deadline) {
        let _removed_key = keys.take(key);
        keys.is_empty()
    } else {
        false
    };
    if remove_bucket {
        expirations.remove(&deadline);
    }
}

#[cfg(test)]
mod tests {
    use super::{
        SingleUseKeyKind, SingleUseNamespace, SingleUseState, StoredExpiration, StoredKey,
    };

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
}
