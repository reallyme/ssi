// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

pub use identity_revocation_core::{OcspPolicy, DEFAULT_MAX_OCSP_AGE_SECS};

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

/// Portable parsed OCSP response consumed by the core checker.
pub struct ParsedOcspResponse {
    /// Issuer key identifier used to match certificates to responses.
    pub(crate) issuer_key: Vec<u8>,
    /// SHA-256 of the exact certificate whose CertID was authenticated.
    pub(crate) certificate_sha256: [u8; 32],
    /// Certificate serial number.
    pub(crate) serial: Vec<u8>,
    /// Reported certificate status.
    pub(crate) status: OcspCertStatus,
    /// `thisUpdate` as Unix seconds.
    pub(crate) this_update: u64,
    /// Optional `nextUpdate` as Unix seconds.
    pub(crate) next_update: Option<u64>,

    /// Nonce authenticated by the OCSP response signature, when present.
    pub(crate) response_nonce: Option<Vec<u8>>,
}

impl core::fmt::Debug for ParsedOcspResponse {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ParsedOcspResponse([VERIFIED])")
    }
}

impl ParsedOcspResponse {
    pub(crate) fn from_verified_backend(
        issuer_key: Vec<u8>,
        certificate_sha256: [u8; 32],
        serial: Vec<u8>,
        status: OcspCertStatus,
        this_update: u64,
        next_update: Option<u64>,
        response_nonce: Option<Vec<u8>>,
    ) -> Self {
        Self {
            issuer_key,
            certificate_sha256,
            serial,
            status,
            this_update,
            next_update,
            response_nonce,
        }
    }

    /// Return the authenticated certificate status.
    pub const fn status(&self) -> OcspCertStatus {
        self.status
    }

    /// Return the authenticated `thisUpdate` timestamp.
    pub const fn this_update(&self) -> u64 {
        self.this_update
    }

    /// Return the authenticated `nextUpdate` timestamp when present.
    pub const fn next_update(&self) -> Option<u64> {
        self.next_update
    }

    /// Return the certificate serial authenticated by the response CertID.
    pub fn serial(&self) -> &[u8] {
        &self.serial
    }

    /// Return the issuer-key identifier derived from verified issuer key material.
    pub fn issuer_key(&self) -> &[u8] {
        &self.issuer_key
    }

    /// Return the authenticated OCSP nonce when present.
    pub fn response_nonce(&self) -> Option<&[u8]> {
        self.response_nonce.as_deref()
    }
}

/// Untrusted OCSP projection awaiting binding to exact certificate DER.
///
/// This type is intentionally constructible by platform adapters. It cannot be
/// passed to [`crate::OcspChecker`]; only [`crate::bind_response_to_certificates`]
/// can turn it into the sealed verified capability.
#[derive(Debug, Clone)]
pub struct UnverifiedOcspResponse {
    pub(crate) issuer_key: Vec<u8>,
    pub(crate) serial: Vec<u8>,
    pub(crate) status: OcspCertStatus,
    pub(crate) this_update: u64,
    pub(crate) next_update: Option<u64>,
    pub(crate) response_nonce: Option<Vec<u8>>,
    pub(crate) extensions: Option<Vec<OcspExtension>>,
}

impl UnverifiedOcspResponse {
    /// Construct a bounded host/backend projection for exact DER binding.
    pub fn new(
        issuer_key: Vec<u8>,
        serial: Vec<u8>,
        status: OcspCertStatus,
        this_update: u64,
        next_update: Option<u64>,
        response_nonce: Option<Vec<u8>>,
        extensions: Option<Vec<OcspExtension>>,
    ) -> Self {
        Self {
            issuer_key,
            serial,
            status,
            this_update,
            next_update,
            response_nonce,
            extensions,
        }
    }
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
