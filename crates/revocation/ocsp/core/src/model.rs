// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

pub use identity_revocation_core::{OcspPolicy, DEFAULT_MAX_OCSP_AGE_SECS};

/// Largest OCSP nonce accepted from a responder.
pub const MAX_OCSP_NONCE_BYTES: usize = 32;

/// Certificate status reported by an OCSP response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OcspCertStatus {
    /// Certificate is not revoked according to the responder.
    Good,
    /// Certificate is revoked.
    Revoked,
    /// Responder does not know the certificate status.
    Unknown,
}

/// OCSP extension preserved from a parsed response.
#[derive(Debug, Clone)]
pub struct OcspExtension {
    /// OID string, e.g. "1.2.3.4".
    pub oid: String,
    /// Whether the extension was marked critical.
    pub critical: bool,
    /// Raw extension value bytes.
    pub value: Vec<u8>,
}
