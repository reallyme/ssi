// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Single-use value store trait, typed errors, and an in-memory implementation.

use std::sync::{Arc, Mutex, MutexGuard};
#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use reallyme_ssi_proto::generated::proto::reallyme::identity_core::v1::IdentityCoreErrorReason;
use thiserror::Error;

mod track_expirations;

use track_expirations::{SingleUseKeyKind, SingleUseState, StoredExpiration, StoredKey};

#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
const DEFAULT_MAX_ENTRIES: usize = 65_536;
const SINGLE_USE_NAMESPACE_COUNT: usize = 5;
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

/// Protocol partition for a single-use value.
///
/// The namespace is part of the stored key. A value used by one protocol
/// therefore cannot collide with or consume a value from another protocol.
/// The in-memory implementation applies both a global memory ceiling and a
/// per-namespace quota so one protocol cannot exhaust every slot.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[non_exhaustive]
pub enum SingleUseNamespace {
    /// RFC 9449 DPoP proof identifiers.
    Dpop,
    /// OAuth wallet-attestation proof identifiers.
    WalletAttestation,
    /// OpenID4VCI credential nonces.
    OpenId4VciCredentialNonce,
    /// OpenID4VP request nonces.
    OpenId4VpRequestNonce,
    /// Application-owned single-use values.
    Application,
}

/// Wall and monotonic time sampled as one clock reading.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SingleUseTime {
    /// Current Unix time used to validate caller-supplied absolute expiries.
    pub unix_seconds: u64,
    /// Process-monotonic seconds used for stored expiry deadlines.
    pub monotonic_seconds: u64,
}

/// Trusted time source owned by the store boundary.
pub trait SingleUseClock: Send + Sync {
    /// Returns wall and monotonic time from a trusted, process-owned source.
    fn now(&self) -> SingleUseResult<SingleUseTime>;
}

/// Operating-system clock used by the default in-memory store.
#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
#[derive(Debug)]
pub struct SystemSingleUseClock {
    monotonic_origin: Instant,
}

#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
impl Default for SystemSingleUseClock {
    fn default() -> Self {
        Self {
            monotonic_origin: Instant::now(),
        }
    }
}

#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
impl SingleUseClock for SystemSingleUseClock {
    fn now(&self) -> SingleUseResult<SingleUseTime> {
        let unix_seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| SingleUseError::Unavailable)?
            .as_secs();
        Ok(SingleUseTime {
            unix_seconds,
            monotonic_seconds: self.monotonic_origin.elapsed().as_secs(),
        })
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
    /// `expires_at_unix` must be after the clock's current Unix time and within the store's
    /// maximum lifetime; otherwise [`SingleUseError::InvalidExpiry`] is
    /// returned. Values whose absolute or monotonic deadlines have elapsed are pruned before capacity is
    /// checked.
    fn put(
        &self,
        namespace: SingleUseNamespace,
        key: &str,
        expires_at_unix: u64,
    ) -> SingleUseResult<()>;

    /// Atomically records an unexpired value only if it has never been seen.
    ///
    /// The same expiry bounds as [`SingleUseStore::put`] apply.
    fn record_once(
        &self,
        namespace: SingleUseNamespace,
        key: &str,
        expires_at_unix: u64,
    ) -> SingleUseResult<()>;

    /// Consumes a value if it is present and unexpired, removing it so it can
    /// never be consumed again. Returns [`SingleUseError::Rejected`] otherwise.
    fn consume(&self, namespace: SingleUseNamespace, key: &str) -> SingleUseResult<()>;

    /// Opportunistically removes values whose absolute or monotonic deadline has elapsed.
    fn prune(&self) -> SingleUseResult<()>;
}

/// In-memory, single-process [`SingleUseStore`].
///
/// Useful for tests and small single-replica deployments. Production services
/// that run multiple replicas should back the trait with durable, shared
/// storage so single-use semantics hold across replicas.
pub struct InMemorySingleUseStore {
    inner: Mutex<SingleUseState>,
    clock: Arc<dyn SingleUseClock>,
    max_entries: usize,
    max_entries_per_namespace: usize,
    max_ttl_secs: u64,
}

impl core::fmt::Debug for InMemorySingleUseStore {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("InMemorySingleUseStore")
            .field("entries", &"<redacted>")
            .field("max_entries", &self.max_entries)
            .field("max_entries_per_namespace", &self.max_entries_per_namespace)
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
        while let Some((_, mut keys)) = entries.monotonic_expirations.pop_first() {
            keys.clear();
        }
        while let Some((_, mut keys)) = entries.absolute_expirations.pop_first() {
            keys.clear();
        }
    }
}

#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
impl Default for InMemorySingleUseStore {
    fn default() -> Self {
        Self {
            inner: Mutex::new(SingleUseState::default()),
            clock: Arc::new(SystemSingleUseClock::default()),
            max_entries: DEFAULT_MAX_ENTRIES,
            max_entries_per_namespace: namespace_limit(DEFAULT_MAX_ENTRIES),
            max_ttl_secs: DEFAULT_MAX_SINGLE_USE_TTL_SECS,
        }
    }
}

impl InMemorySingleUseStore {
    /// Creates an empty store.
    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates an empty store with an explicit hard entry ceiling.
    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    pub fn with_max_entries(max_entries: usize) -> SingleUseResult<Self> {
        Self::with_limits(max_entries, DEFAULT_MAX_SINGLE_USE_TTL_SECS)
    }

    /// Creates an empty store with explicit entry and lifetime ceilings.
    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    pub fn with_limits(max_entries: usize, max_ttl_secs: u64) -> SingleUseResult<Self> {
        Self::with_clock_and_limits(
            Arc::new(SystemSingleUseClock::default()),
            max_entries,
            max_ttl_secs,
        )
    }

    /// Creates an empty store with an injected trusted clock and explicit
    /// global entry and lifetime limits.
    pub fn with_clock_and_limits(
        clock: Arc<dyn SingleUseClock>,
        max_entries: usize,
        max_ttl_secs: u64,
    ) -> SingleUseResult<Self> {
        if max_entries == 0 {
            return Err(SingleUseError::CapacityExceeded);
        }
        if max_ttl_secs == 0 {
            return Err(SingleUseError::InvalidExpiry);
        }
        Ok(Self {
            inner: Mutex::new(SingleUseState::default()),
            clock,
            max_entries,
            max_entries_per_namespace: namespace_limit(max_entries),
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

    fn expiration(
        &self,
        now: SingleUseTime,
        expires_at_unix: u64,
    ) -> SingleUseResult<StoredExpiration> {
        let latest_expiry = now
            .unix_seconds
            .checked_add(self.max_ttl_secs)
            .ok_or(SingleUseError::InvalidExpiry)?;
        if expires_at_unix <= now.unix_seconds || expires_at_unix > latest_expiry {
            return Err(SingleUseError::InvalidExpiry);
        }
        let ttl = expires_at_unix
            .checked_sub(now.unix_seconds)
            .ok_or(SingleUseError::InvalidExpiry)?;
        let monotonic_deadline = now
            .monotonic_seconds
            .checked_add(ttl)
            .ok_or(SingleUseError::InvalidExpiry)?;
        Ok(StoredExpiration {
            expires_at_unix,
            monotonic_deadline,
        })
    }

    fn lock_at_current_time(
        &self,
    ) -> SingleUseResult<(MutexGuard<'_, SingleUseState>, SingleUseTime)> {
        let mut state = self.lock()?;
        // Read the clock after acquiring the state lock. Otherwise two callers
        // can sample time in one order and update state in the opposite order.
        let mut now = self.clock.now()?;
        now.monotonic_seconds = state.observe_monotonic_time(now.monotonic_seconds);
        state.prune(now.monotonic_seconds, now.unix_seconds);
        Ok((state, now))
    }

    fn ensure_capacity(
        &self,
        state: &SingleUseState,
        namespace: SingleUseNamespace,
    ) -> SingleUseResult<()> {
        let namespace_count = state
            .namespace_counts
            .get(namespace_index(namespace))
            .ok_or(SingleUseError::CapacityExceeded)?;
        if state.entries.len() >= self.max_entries
            || *namespace_count >= self.max_entries_per_namespace
        {
            return Err(SingleUseError::CapacityExceeded);
        }
        Ok(())
    }
}

const fn namespace_limit(max_entries: usize) -> usize {
    max_entries.div_ceil(SINGLE_USE_NAMESPACE_COUNT)
}

const fn namespace_index(namespace: SingleUseNamespace) -> usize {
    match namespace {
        SingleUseNamespace::Dpop => 0,
        SingleUseNamespace::WalletAttestation => 1,
        SingleUseNamespace::OpenId4VciCredentialNonce => 2,
        SingleUseNamespace::OpenId4VpRequestNonce => 3,
        SingleUseNamespace::Application => 4,
    }
}

impl SingleUseStore for InMemorySingleUseStore {
    fn put(
        &self,
        namespace: SingleUseNamespace,
        key: &str,
        expires_at_unix: u64,
    ) -> SingleUseResult<()> {
        Self::validate_key(key)?;
        let (mut state, now) = self.lock_at_current_time()?;
        let expiration = self.expiration(now, expires_at_unix)?;
        let stored_key = StoredKey::new(namespace, SingleUseKeyKind::Consumable, key);
        if let Some(previous_expiration) = state.entries.get_mut(&stored_key) {
            if previous_expiration.expires_at_unix == expires_at_unix {
                return Ok(());
            }
            let replaced_expiration = *previous_expiration;
            *previous_expiration = expiration;
            state.unschedule_expiration(&stored_key, replaced_expiration);
            state.schedule_expiration(&stored_key, expiration);
            return Ok(());
        }
        self.ensure_capacity(&state, namespace)?;
        let namespace_index = namespace_index(namespace);
        let next_count = state
            .namespace_counts
            .get(namespace_index)
            .ok_or(SingleUseError::CapacityExceeded)?
            .checked_add(1)
            .ok_or(SingleUseError::CapacityExceeded)?;
        state.schedule_expiration(&stored_key, expiration);
        state.entries.insert(stored_key, expiration);
        let count = state
            .namespace_counts
            .get_mut(namespace_index)
            .ok_or(SingleUseError::CapacityExceeded)?;
        *count = next_count;
        Ok(())
    }

    fn record_once(
        &self,
        namespace: SingleUseNamespace,
        key: &str,
        expires_at_unix: u64,
    ) -> SingleUseResult<()> {
        Self::validate_key(key)?;
        let (mut state, now) = self.lock_at_current_time()?;
        let expiration = self.expiration(now, expires_at_unix)?;
        let stored_key = StoredKey::new(namespace, SingleUseKeyKind::Recorded, key);
        if state.entries.contains_key(&stored_key) {
            return Err(SingleUseError::Rejected);
        }
        self.ensure_capacity(&state, namespace)?;
        let namespace_index = namespace_index(namespace);
        let next_count = state
            .namespace_counts
            .get(namespace_index)
            .ok_or(SingleUseError::CapacityExceeded)?
            .checked_add(1)
            .ok_or(SingleUseError::CapacityExceeded)?;
        state.schedule_expiration(&stored_key, expiration);
        state.entries.insert(stored_key, expiration);
        let count = state
            .namespace_counts
            .get_mut(namespace_index)
            .ok_or(SingleUseError::CapacityExceeded)?;
        *count = next_count;
        Ok(())
    }

    fn consume(&self, namespace: SingleUseNamespace, key: &str) -> SingleUseResult<()> {
        Self::validate_key(key)?;
        let stored_key = StoredKey::new(namespace, SingleUseKeyKind::Consumable, key);
        let (mut state, now) = self.lock_at_current_time()?;
        match state.remove_entry(&stored_key) {
            Some((owned_key, expiration))
                if expiration.monotonic_deadline > now.monotonic_seconds
                    && expiration.expires_at_unix > now.unix_seconds =>
            {
                state.unschedule_expiration(&owned_key, expiration);
                Ok(())
            }
            Some((owned_key, expiration)) => {
                state.unschedule_expiration(&owned_key, expiration);
                Err(SingleUseError::Rejected)
            }
            _ => Err(SingleUseError::Rejected),
        }
    }

    fn prune(&self) -> SingleUseResult<()> {
        let _state = self.lock_at_current_time()?;
        Ok(())
    }
}

#[cfg(test)]
#[path = "store_proto_error_tests.rs"]
mod proto_error_tests;

#[cfg(test)]
#[path = "store_expiration_index_tests.rs"]
mod expiration_index_tests;
