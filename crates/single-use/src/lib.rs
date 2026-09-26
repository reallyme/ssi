// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Single-use, expiring, server-issued value store.
//!
//! This crate provides one small abstraction shared across ReallyMe protocol
//! layers: a store of opaque values that are issued once, expire, and may be
//! consumed exactly once. It backs replay protection for DPoP `jti`, wallet
//! attestation `jti`, OpenID4VCI credential nonces (`c_nonce`), and OpenID4VP
//! request nonces, so those consumers do not each reimplement the same policy.

mod store;

pub use store::{
    InMemorySingleUseStore, SingleUseError, SingleUseResult, SingleUseStore,
    DEFAULT_MAX_SINGLE_USE_TTL_SECS,
};
