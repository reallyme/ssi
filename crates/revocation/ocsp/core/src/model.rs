// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use serde::{Deserialize, Serialize};

/// Default maximum age for an OCSP `thisUpdate` when no tighter profile is supplied.
pub const DEFAULT_MAX_OCSP_AGE_SECS: u64 = 86_400;

/// Certificate status reported by an OCSP response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OcspCertStatus {
    /// Certificate is not revoked according to the responder.
    Good,
    /// Certificate is revoked.
    Revoked,
    /// Responder does not know the certificate status.
    Unknown,
}

/// OCSP evaluation policy knobs (profile-dependent).
///
/// This is intentionally small and portable so it can be used across native/wasm/swift/kotlin.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct OcspPolicy {
    /// If true, missing `nextUpdate` is treated as invalid for this profile.
    pub require_next_update: bool,

    /// Maximum allowed age of `thisUpdate` (seconds). If `None`, do not enforce max age.
    pub max_age_secs: Option<u64>,

    /// Allowed clock skew (seconds) used when comparing `thisUpdate`/`nextUpdate` to `now`.
    pub allowed_skew_secs: u64,

    /// If true, the OCSP entry must be marked as verified (signature + responder authorization).
    pub require_verified: bool,
}

impl Default for OcspPolicy {
    fn default() -> Self {
        Self {
            require_next_update: false,
            // RFC 6960 §4.2.2.1 permits nextUpdate to be absent, but a relying
            // party still needs a local freshness ceiling to prevent indefinite
            // replay of an otherwise valid response.
            max_age_secs: Some(DEFAULT_MAX_OCSP_AGE_SECS),
            allowed_skew_secs: 300,
            require_verified: true,
        }
    }
}

/// Portable parsed OCSP response consumed by the core checker.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedOcspResponse {
    /// Issuer key identifier used to match certificates to responses.
    pub issuer_key: Vec<u8>,
    /// Certificate serial number.
    pub serial: Vec<u8>,
    /// Reported certificate status.
    pub status: OcspCertStatus,
    /// `thisUpdate` as Unix seconds.
    pub this_update: u64,
    /// Optional `nextUpdate` as Unix seconds.
    pub next_update: Option<u64>,

    // ---------------------------------------------------------------------
    // Verification metadata (provided by backends; enforced by policy)
    // ---------------------------------------------------------------------
    /// Whether the OCSP response signature was validated successfully.
    pub signature_valid: Option<bool>,

    /// Whether the OCSP responder was authorized by the issuing CA.
    pub responder_authorized: Option<bool>,

    /// Whether the responder signing cert satisfied OCSP signing requirements (EKU, etc).
    pub responder_eku_ocsp_signing: Option<bool>,

    /// Optional extension bytes (future-proofing; e.g. LoTI, ETSI qualifiers).
    pub extensions: Option<Vec<OcspExtension>>,
}

/// OCSP extension preserved from a parsed response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OcspExtension {
    /// OID string, e.g. "1.2.3.4".
    pub oid: String,
    /// Whether the extension was marked critical.
    pub critical: bool,
    /// Raw extension value bytes.
    pub value: Vec<u8>,
}
