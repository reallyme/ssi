// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Public facade for ReallyMe identity primitives.
//!
//! The facade mounts each support crate under a stable identity path instead of
//! glob-re-exporting its symbols. That keeps public API ownership explicit while
//! preserving the ergonomic module paths used by protocol, wallet, and SDK
//! repositories.

/// QEAA compliance metadata and audit evidence validation.
pub mod audit;

/// Credential claim registries and disclosure validation.
pub mod claims;

/// Bounded compression helpers for identity envelope payloads.
pub mod compression;

/// Cross-repository identity stack contracts.
pub mod common;

/// CBOR Object Signing and Encryption helpers.
pub use reallyme_cose as cose;

/// Credential issuance, envelope model, and validation.
pub mod credential;

/// DID document generation, validation, update, and protobuf transport helpers.
pub mod did;

/// Reusable disclosure policy profiles and evaluation helpers.
pub use reallyme_disclosure_policy as disclosure_policy;

/// Credential or presentation delivery artifact helpers.
pub mod delivery;

/// Credential envelope formats used by issuance and presentation protocols.
pub mod envelopes;

/// EUDI Wallet Relying Party registration, WRPRC, and WRPAC profiles.
pub mod eudi;

/// JSON Object Signing and Encryption helpers.
pub use reallyme_jose as jose;

/// Identity-core public boundary contracts.
pub mod identity_core;

/// Key-set helpers for identity document construction.
pub use reallyme_keys as keys;

/// Shared OAuth substrate helpers.
pub use reallyme_openid_oauth as oauth;

/// Shared identity interoperability profile identifiers.
pub use reallyme_openid4vc_profiles as profiles;

/// Credential revocation and suspension policy helpers.
pub use reallyme_revocation as revocation;

/// Single-use server value store helpers for nonces and replay protection.
pub use reallyme_single_use as single_use;

/// Credential status-list models and verification policy.
pub mod status;

/// Verifiable Presentation models and reusable presentation helpers.
pub mod presentation;

/// Trust evaluation, X.509, and trust protobuf helpers.
pub mod trust;
