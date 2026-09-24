// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::collections::BTreeMap;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Default encoding label for JSON-canonicalized credential claim values.
pub const ENCODING_JCS_UTF8: &str = "JCS-UTF8";

/// Semantic type of a credential claim value.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Zeroize)]
pub enum ClaimType {
    /// Type has not been specified.
    Unspecified,

    /// String value.
    String,

    /// Boolean value.
    Boolean,

    /// Integer value.
    Integer,

    /// Signed integer value.
    SignedInteger,

    /// Unsigned integer value.
    UnsignedInteger,

    /// Floating or decimal number value.
    Number,

    /// Fixed-point decimal value with canonical lexical form.
    Decimal,

    /// Opaque byte string value.
    Bytes,

    /// ISO 8601 calendar date value.
    Date,

    /// RFC 3339 date-time value.
    DateTime,

    /// Null value.
    Null,

    /// Structured object value.
    Object,

    /// Array value.
    Array,
}

/// Supported disclosure modes for a claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Zeroize)]
pub enum DisclosureMode {
    /// Mode has not been specified.
    Unspecified,

    /// Claim is hidden.
    Hidden,

    /// Exact value reveal.
    Reveal,

    /// Equality predicate.
    Eq,

    /// Greater-than-or-equal predicate.
    Gte,

    /// Less-than-or-equal predicate.
    Lte,

    /// Range predicate.
    Range,

    /// Set membership predicate.
    MemberOfSet,
}

/// Disclosure policy attached to a claim definition.
#[derive(Eq, PartialEq, Zeroize, ZeroizeOnDrop)]
pub struct ClaimDisclosurePolicy {
    /// Whether exact value reveal is permitted.
    pub allow_reveal: bool,

    /// Allowed predicate disclosure modes.
    pub predicates: Vec<DisclosureMode>,
}

/// Definition of one credential claim.
#[derive(Eq, PartialEq, Zeroize, ZeroizeOnDrop)]
pub struct ClaimDefinition {
    /// Canonical claim identifier.
    pub claim_id: String,

    /// Semantic value type.
    pub claim_type: ClaimType,

    /// Encoding of committed value bytes.
    pub encoding: String,

    /// Disclosure rules for this claim.
    pub disclosure: ClaimDisclosurePolicy,
}

/// Registry of claims for a credential profile.
#[derive(Eq, PartialEq)]
pub struct ClaimsRegistry {
    /// Credential claimset/profile identifier.
    pub claimset_id: String,

    /// Map from canonical claim identifier to definition.
    pub claims: BTreeMap<String, ClaimDefinition>,
}

impl Zeroize for ClaimsRegistry {
    fn zeroize(&mut self) {
        self.claimset_id.zeroize();

        // BTreeMap keys cannot be reached mutably. Taking ownership ensures
        // both canonical paths and their definitions are wiped before the
        // backing allocations are released.
        let claims = core::mem::take(&mut self.claims);
        for (mut path, mut definition) in claims {
            path.zeroize();
            definition.zeroize();
        }
    }
}

impl Drop for ClaimsRegistry {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for ClaimsRegistry {}

// Registry identifiers and paths can disclose the shape of identity data.
// Uniform redaction prevents future fields from silently widening diagnostics.
macro_rules! impl_redacted_debug {
    ($($type_name:ty),+ $(,)?) => {
        $(
            impl core::fmt::Debug for $type_name {
                fn fmt(
                    &self,
                    formatter: &mut core::fmt::Formatter<'_>,
                ) -> core::fmt::Result {
                    formatter
                        .debug_struct(stringify!($type_name))
                        .field("contents", &"<redacted>")
                        .finish()
                }
            }
        )+
    };
}

impl_redacted_debug!(ClaimDisclosurePolicy, ClaimDefinition, ClaimsRegistry);
