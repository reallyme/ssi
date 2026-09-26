// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Single-use value store trait, typed errors, and an in-memory implementation.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{Mutex, MutexGuard};

use reallyme_ssi_proto::generated::proto::reallyme::identity_core::v1::IdentityCoreErrorReason;
use thiserror::Error;
use zeroize::Zeroize;

const DEFAULT_MAX_ENTRIES: usize = 65_536;
const MAX_SINGLE_USE_KEY_BYTES: usize = 1_024;
/// Default maximum lifetime of a stored value, in seconds.
///
/// Nonces and `jti` values are short-lived; a bounded lifetime ensures stored
/// entries are always reclaimed by pruning, so hostile expiry values cannot
/// pin capacity indefinitely.
pub const DEFAULT_MAX_SINGLE_USE_TTL_SECS: u64 = 86_400;

/// Result alias for single-use store operations.
pub type SingleUseResult<T> = Result<T, SingleUseError>;

/// Stable, non-secret failure reasons for single-use store operations.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SingleUseError {
    /// The value was unknown, already consumed, or expired.
    ///
    /// The reasons are deliberately merged into one variant so the store does
    /// not become an oracle that distinguishes "never issued" from "already
    /// used" from "expired" for an attacker probing values.
    #[error("rejected")]
    Rejected,
    /// The backing store was unavailable (for example, a poisoned lock).
    #[error("unavailable")]
    Unavailable,
    /// The supplied key was empty.
    #[error("invalid_key")]
    InvalidKey,
    /// The bounded in-memory store cannot accept another distinct value.
    #[error("capacity_exceeded")]
    CapacityExceeded,
    /// The expiry is not after the supplied time or exceeds the store's
    /// maximum lifetime.
    #[error("invalid_expiry")]
    InvalidExpiry,
}

impl From<SingleUseError> for IdentityCoreErrorReason {
    fn from(reason: SingleUseError) -> Self {
        match reason {
            SingleUseError::Rejected => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_SINGLE_USE_REJECTED
            }
            SingleUseError::Unavailable => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_SINGLE_USE_UNAVAILABLE
            }
            SingleUseError::InvalidKey | SingleUseError::InvalidExpiry => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_SINGLE_USE_INVALID_KEY
            }
            SingleUseError::CapacityExceeded => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_SINGLE_USE_UNAVAILABLE
            }
        }
    }
}

/// Stores opaque, server-issued values that may be consumed exactly once before
/// they expire.
///
/// Implementations MUST make [`SingleUseStore::consume`] atomic: a value that is
/// consumed once must never be consumable again, even under concurrent callers.
pub trait SingleUseStore: Send + Sync {
    /// Stores a freshly issued value with an absolute expiry timestamp.
    ///
    /// `expires_at_unix` must be after `now_unix` and within the store's
    /// maximum lifetime; otherwise [`SingleUseError::InvalidExpiry`] is
    /// returned. Values expired at `now_unix` are pruned before capacity is
    /// checked.
    fn put(&self, key: &str, now_unix: u64, expires_at_unix: u64) -> SingleUseResult<()>;

    /// Atomically records an unexpired value only if it has never been seen.
    ///
    /// The same expiry bounds as [`SingleUseStore::put`] apply.
    fn record_once(&self, key: &str, now_unix: u64, expires_at_unix: u64) -> SingleUseResult<()>;

    /// Consumes a value if it is present and unexpired, removing it so it can
    /// never be consumed again. Returns [`SingleUseError::Rejected`] otherwise.
    fn consume(&self, key: &str, now_unix: u64) -> SingleUseResult<()>;

    /// Opportunistically removes values that expired at or before `now_unix`.
    fn prune(&self, now_unix: u64) -> SingleUseResult<()>;
}

/// In-memory, single-process [`SingleUseStore`].
///
/// Useful for tests and small single-replica deployments. Production services
/// that run multiple replicas should back the trait with durable, shared
/// storage so single-use semantics hold across replicas.
pub struct InMemorySingleUseStore {
    inner: Mutex<SingleUseState>,
    max_entries: usize,
    max_ttl_secs: u64,
}

#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
enum SingleUseKeyKind {
    Consumable,
    Recorded,
}

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
struct StoredKey {
    kind: SingleUseKeyKind,
    value: String,
}

impl StoredKey {
    fn new(kind: SingleUseKeyKind, value: &str) -> Self {
        Self {
            kind,
            value: value.to_owned(),
        }
    }
}

impl Drop for StoredKey {
    fn drop(&mut self) {
        self.value.zeroize();
    }
}

#[derive(Default)]
struct SingleUseState {
    entries: HashMap<StoredKey, u64>,
    expirations: BTreeMap<u64, BTreeSet<StoredKey>>,
}

impl SingleUseState {
    fn schedule_expiration(&mut self, key: &StoredKey, expires_at_unix: u64) {
        self.expirations
            .entry(expires_at_unix)
            .or_default()
            .insert(key.clone());
    }

    fn unschedule_expiration(&mut self, key: &StoredKey, expires_at_unix: u64) {
        let remove_bucket = if let Some(keys) = self.expirations.get_mut(&expires_at_unix) {
            let _removed_key = keys.take(key);
            keys.is_empty()
        } else {
            false
        };

        if remove_bucket {
            self.expirations.remove(&expires_at_unix);
        }
    }

    fn prune(&mut self, now_unix: u64) {
        while let Some((&expires_at_unix, _)) = self.expirations.first_key_value() {
            if expires_at_unix > now_unix {
                break;
            }

            let Some((_, mut keys)) = self.expirations.pop_first() else {
                break;
            };
            while let Some(key) = keys.pop_first() {
                if self.entries.get(&key).copied() == Some(expires_at_unix) {
                    let _removed_entry = self.entries.remove_entry(&key);
                }
            }
        }
    }
}

impl core::fmt::Debug for InMemorySingleUseStore {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("InMemorySingleUseStore")
            .field("entries", &"<redacted>")
            .field("max_entries", &self.max_entries)
            .field("max_ttl_secs", &self.max_ttl_secs)
            .finish()
    }
}

impl Drop for InMemorySingleUseStore {
    fn drop(&mut self) {
        let entries = match self.inner.get_mut() {
            Ok(entries) => entries,
            Err(poisoned) => poisoned.into_inner(),
        };
        entries.entries.clear();
        while let Some((_, mut keys)) = entries.expirations.pop_first() {
            keys.clear();
        }
    }
}

impl Default for InMemorySingleUseStore {
    fn default() -> Self {
        Self {
            inner: Mutex::new(SingleUseState::default()),
            max_entries: DEFAULT_MAX_ENTRIES,
            max_ttl_secs: DEFAULT_MAX_SINGLE_USE_TTL_SECS,
        }
    }
}

impl InMemorySingleUseStore {
    /// Creates an empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates an empty store with an explicit hard entry ceiling.
    pub fn with_max_entries(max_entries: usize) -> SingleUseResult<Self> {
        Self::with_limits(max_entries, DEFAULT_MAX_SINGLE_USE_TTL_SECS)
    }

    /// Creates an empty store with explicit entry and lifetime ceilings.
    pub fn with_limits(max_entries: usize, max_ttl_secs: u64) -> SingleUseResult<Self> {
        if max_entries == 0 {
            return Err(SingleUseError::CapacityExceeded);
        }
        if max_ttl_secs == 0 {
            return Err(SingleUseError::InvalidExpiry);
        }
        Ok(Self {
            inner: Mutex::new(SingleUseState::default()),
            max_entries,
            max_ttl_secs,
        })
    }

    fn lock(&self) -> SingleUseResult<MutexGuard<'_, SingleUseState>> {
        self.inner.lock().map_err(|_| SingleUseError::Unavailable)
    }

    fn validate_key(key: &str) -> SingleUseResult<()> {
        if key.is_empty() || key.len() > MAX_SINGLE_USE_KEY_BYTES {
            return Err(SingleUseError::InvalidKey);
        }
        Ok(())
    }

    fn validate_expiry(&self, now_unix: u64, expires_at_unix: u64) -> SingleUseResult<()> {
        let latest_expiry = now_unix
            .checked_add(self.max_ttl_secs)
            .ok_or(SingleUseError::InvalidExpiry)?;
        if expires_at_unix <= now_unix || expires_at_unix > latest_expiry {
            return Err(SingleUseError::InvalidExpiry);
        }
        Ok(())
    }
}

impl SingleUseStore for InMemorySingleUseStore {
    fn put(&self, key: &str, now_unix: u64, expires_at_unix: u64) -> SingleUseResult<()> {
        Self::validate_key(key)?;
        self.validate_expiry(now_unix, expires_at_unix)?;
        let stored_key = StoredKey::new(SingleUseKeyKind::Consumable, key);
        let mut state = self.lock()?;
        state.prune(now_unix);
        if let Some(previous_expiry) = state.entries.get_mut(&stored_key) {
            if *previous_expiry == expires_at_unix {
                return Ok(());
            }
            let replaced_expiry = *previous_expiry;
            *previous_expiry = expires_at_unix;
            state.unschedule_expiration(&stored_key, replaced_expiry);
            state.schedule_expiration(&stored_key, expires_at_unix);
            return Ok(());
        }
        if state.entries.len() >= self.max_entries {
            return Err(SingleUseError::CapacityExceeded);
        }
        state.schedule_expiration(&stored_key, expires_at_unix);
        state.entries.insert(stored_key, expires_at_unix);
        Ok(())
    }

    fn record_once(&self, key: &str, now_unix: u64, expires_at_unix: u64) -> SingleUseResult<()> {
        Self::validate_key(key)?;
        self.validate_expiry(now_unix, expires_at_unix)?;
        let stored_key = StoredKey::new(SingleUseKeyKind::Recorded, key);
        let mut state = self.lock()?;
        state.prune(now_unix);
        if state.entries.contains_key(&stored_key) {
            return Err(SingleUseError::Rejected);
        }
        if state.entries.len() >= self.max_entries {
            return Err(SingleUseError::CapacityExceeded);
        }
        state.schedule_expiration(&stored_key, expires_at_unix);
        state.entries.insert(stored_key, expires_at_unix);
        Ok(())
    }

    fn consume(&self, key: &str, now_unix: u64) -> SingleUseResult<()> {
        Self::validate_key(key)?;
        let stored_key = StoredKey::new(SingleUseKeyKind::Consumable, key);
        let mut state = self.lock()?;
        match state.entries.remove_entry(&stored_key) {
            Some((owned_key, expires_at)) if expires_at > now_unix => {
                state.unschedule_expiration(&owned_key, expires_at);
                Ok(())
            }
            Some((owned_key, expires_at)) => {
                state.unschedule_expiration(&owned_key, expires_at);
                Err(SingleUseError::Rejected)
            }
            _ => Err(SingleUseError::Rejected),
        }
    }

    fn prune(&self, now_unix: u64) -> SingleUseResult<()> {
        let mut entries = self.lock()?;
        entries.prune(now_unix);
        Ok(())
    }
}

#[cfg(test)]
#[path = "store_proto_error_tests.rs"]
mod proto_error_tests;

#[cfg(test)]
#[path = "store_expiration_index_tests.rs"]
mod expiration_index_tests;
