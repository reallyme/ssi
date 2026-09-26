// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Resource limits applied to untrusted did:me documents before semantic validation.
//!
//! Every limit is checked before any per-entry cryptographic or cross-reference
//! work so that hostile documents cannot force unbounded CPU or memory use.

/// Maximum number of `@context` entries.
pub const MAX_CONTEXT_ENTRIES: usize = 16;

/// Maximum number of DID controllers.
pub const MAX_CONTROLLERS: usize = 16;

/// Maximum number of `alsoKnownAs` entries.
pub const MAX_ALSO_KNOWN_AS: usize = 64;

/// Maximum number of verification methods (and core controller keys).
pub const MAX_VERIFICATION_METHODS: usize = 64;

/// Maximum number of references in any single relationship array or update policy.
pub const MAX_RELATIONSHIP_REFERENCES: usize = 64;

/// Maximum number of service entries.
pub const MAX_SERVICES: usize = 64;

/// Maximum number of core attestations.
pub const MAX_ATTESTATIONS: usize = 64;

/// Maximum number of domain-verification entries.
pub const MAX_DOMAIN_VERIFICATIONS: usize = 16;

/// Maximum number of previous core CIDs carried in `keyHistory`.
pub const MAX_KEY_HISTORY_ENTRIES: usize = 4096;

/// Maximum base64url-encoded `coreCbor` length in bytes.
pub const MAX_CORE_CBOR_ENCODED_BYTES: usize = 512 * 1024;
