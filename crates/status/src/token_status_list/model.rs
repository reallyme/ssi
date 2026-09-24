// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Protected JWT `typ` value required by OAuth Token Status List draft-21.
pub const STATUS_LIST_JWT_TYPE: &str = "statuslist+jwt";
/// HTTP media type for a Token Status List JWT response.
pub const STATUS_LIST_JWT_MEDIA_TYPE: &str = "application/statuslist+jwt";
/// CWT media type required by OAuth Token Status List draft-21.
pub const STATUS_LIST_CWT_MEDIA_TYPE: &str = "application/statuslist+cwt";
/// Registered CoAP Content-Format identifier for a Token Status List CWT.
pub const STATUS_LIST_CWT_CONTENT_FORMAT: u64 = 279;

/// Maximum number of status entries accepted by this profile implementation.
pub const MAX_TOKEN_STATUS_ENTRIES: usize = 1_048_576;
/// Maximum compressed status-list byte length accepted at the boundary.
pub const MAX_COMPRESSED_STATUS_BYTES: usize = 600_000;
/// Maximum encoded COSE_Sign1 bytes accepted for a Status List CWT.
#[cfg(any(feature = "native", feature = "wasm"))]
pub const MAX_TOKEN_STATUS_CWT_BYTES: usize = 700_000;
/// Maximum URI byte length accepted for subject and aggregation identifiers.
#[cfg(any(feature = "native", feature = "wasm"))]
pub const MAX_STATUS_URI_BYTES: usize = 2_048;

/// Wire profile selected for Token Status List processing.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub enum TokenStatusListProfile {
    /// `draft-ietf-oauth-status-list-21` (June 2026).
    #[default]
    IetfDraft21,
}

/// Number of bits allocated to one status value.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[repr(u8)]
pub enum TokenStatusBits {
    /// One bit per status value (eight entries per byte).
    One = 1,
    /// Four possible status values.
    Two = 2,
    /// Sixteen possible status values.
    Four = 4,
    /// One full byte per status value.
    Eight = 8,
}

impl TokenStatusBits {
    pub(crate) const fn width(self) -> u8 {
        self as u8
    }

    pub(crate) const fn maximum_value(self) -> u8 {
        match self {
            Self::One => 1,
            Self::Two => 3,
            Self::Four => 15,
            Self::Eight => u8::MAX,
        }
    }
}

/// JSON representation of the `status_list` claim.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenStatusListPayload {
    /// Bits allocated to each status value.
    pub bits: u8,
    /// Base64url-without-padding encoded ZLIB-compressed status bytes.
    pub lst: String,
    /// Optional URI of a Status List Aggregation document.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aggregation_uri: Option<String>,
}

/// JWT claim set for an IETF Token Status List.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TokenStatusListClaims {
    /// Explicit local wire profile; it is not serialized as a token claim.
    #[serde(skip)]
    pub profile: TokenStatusListProfile,
    /// URI that uniquely identifies this status list.
    pub sub: String,
    /// NumericDate at which the list was issued.
    pub iat: u64,
    /// Optional NumericDate after which the token is invalid.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<u64>,
    /// Optional maximum cache lifetime in seconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl: Option<u64>,
    /// Compressed status-list claim.
    pub status_list: TokenStatusListPayload,
}

/// Authenticated and decompressed Token Status List.
#[derive(Debug, Eq, PartialEq)]
pub struct VerifiedTokenStatusList {
    /// Authenticated claims.
    pub claims: TokenStatusListClaims,
    /// Packed status bytes in draft-defined least-significant-bit-first order.
    pub packed_statuses: Vec<u8>,
}

/// Stable invalid-input reasons for the Token Status List profile.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum TokenStatusListInvalidReason {
    /// The caller selected a profile this implementation does not support.
    #[error("unsupported token status list profile")]
    UnsupportedProfile,
    /// A required URI is absent, oversized, or not an absolute URI.
    #[error("invalid token status list URI")]
    InvalidUri,
    /// The selected bit width is not one of 1, 2, 4, or 8.
    #[error("invalid token status bit width")]
    InvalidBits,
    /// A status value cannot be represented by the selected bit width.
    #[error("token status value exceeds bit width")]
    StatusValueOutOfRange,
    /// The status list is empty or exceeds the local resource limit.
    #[error("invalid token status list length")]
    InvalidLength,
    /// The requested status index does not address a packed status value.
    #[error("invalid token status list index")]
    InvalidIndex,
    /// Expiration precedes issuance or TTL is zero.
    #[error("invalid token status time claims")]
    InvalidTimeClaims,
    /// Compressed status bytes are malformed or exceed the resource limit.
    #[error("invalid compressed token status list")]
    InvalidCompressedList,
    /// Authenticated CWT claims do not match the required profile shape.
    #[error("invalid token status list CWT claims")]
    InvalidCwtClaims,
}

/// Token Status List profile error.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum TokenStatusListError {
    /// Claims or status values violate the profile.
    #[error("invalid token status list input")]
    InvalidInput(TokenStatusListInvalidReason),
    /// JSON or CBOR serialization failed.
    #[error("token status list encoding failed")]
    Encoding,
    /// Authentication failed or the JOSE envelope was invalid.
    #[error("token status list authentication failed")]
    Authentication,
    /// The authenticated token is expired at the supplied verification time.
    #[error("token status list expired")]
    Expired,
    /// The authenticated token was issued after the supplied verification time.
    #[error("token status list not yet valid")]
    NotYetValid,
    /// The authenticated subject does not equal the expected publication URI.
    #[error("token status list subject mismatch")]
    SubjectMismatch,
}
