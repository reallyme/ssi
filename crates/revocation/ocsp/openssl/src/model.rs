// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use identity_revocation_ocsp_core::{OcspCertStatus, OcspExtension};

/// Signature-verified OCSP response produced only by this backend.
///
/// All fields are private so downstream callers cannot synthesize a positive
/// status receipt. The only production constructor is reached after OpenSSL
/// has authenticated the response signature and responder path.
pub struct VerifiedOcspResponse {
    pub(crate) issuer_key: Vec<u8>,
    pub(crate) certificate_sha256: [u8; 32],
    pub(crate) serial: Vec<u8>,
    pub(crate) status: OcspCertStatus,
    pub(crate) this_update: u64,
    pub(crate) next_update: Option<u64>,
    pub(crate) response_nonce: Option<Vec<u8>>,
}

impl core::fmt::Debug for VerifiedOcspResponse {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("VerifiedOcspResponse([VERIFIED])")
    }
}

impl VerifiedOcspResponse {
    pub(crate) fn new(
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

    /// Return SHA-256 of the exact certificate authenticated by the CertID.
    pub const fn certificate_sha256(&self) -> &[u8; 32] {
        &self.certificate_sha256
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

    /// Return the authenticated certificate serial.
    pub fn serial(&self) -> &[u8] {
        &self.serial
    }

    /// Return the verified issuer key identifier.
    pub fn issuer_key(&self) -> &[u8] {
        &self.issuer_key
    }

    /// Return the authenticated response nonce when present.
    pub fn response_nonce(&self) -> Option<&[u8]> {
        self.response_nonce.as_deref()
    }
}

#[derive(Debug, Clone)]
pub(crate) struct UnverifiedOcspResponse {
    pub(crate) issuer_key: Vec<u8>,
    pub(crate) serial: Vec<u8>,
    pub(crate) status: OcspCertStatus,
    pub(crate) this_update: u64,
    pub(crate) next_update: Option<u64>,
    pub(crate) response_nonce: Option<Vec<u8>>,
    pub(crate) extensions: Option<Vec<OcspExtension>>,
}

impl UnverifiedOcspResponse {
    pub(crate) fn new(
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
