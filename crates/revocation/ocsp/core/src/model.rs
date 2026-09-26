// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use serde::{Deserialize, Serialize};

pub use identity_revocation_core::{OcspPolicy, DEFAULT_MAX_OCSP_AGE_SECS};

/// Certificate status reported by an OCSP response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OcspCertStatus {
    /// Certificate is not revoked according to the responder.
    Good,
    /// Certificate is revoked.
    Revoked,
    /// Responder does not know the certificate status.
    Unknown,
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
