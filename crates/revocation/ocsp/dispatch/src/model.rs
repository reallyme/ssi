// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use identity_revocation_ocsp_core::OcspCertStatus;

/// Opaque OCSP receipt created only after backend signature verification.
///
/// ```compile_fail
/// use identity_revocation_ocsp_dispatch::ParsedOcspResponse;
/// let _forged = ParsedOcspResponse {
///     certificate_sha256: [0; 32],
/// };
/// ```
pub struct ParsedOcspResponse {
    pub(crate) issuer_key: Vec<u8>,
    pub(crate) certificate_sha256: [u8; 32],
    pub(crate) serial: Vec<u8>,
    pub(crate) status: OcspCertStatus,
    pub(crate) this_update: u64,
    pub(crate) next_update: Option<u64>,
    pub(crate) response_nonce: Option<Vec<u8>>,
}

impl core::fmt::Debug for ParsedOcspResponse {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ParsedOcspResponse([VERIFIED])")
    }
}

impl ParsedOcspResponse {
    #[cfg(feature = "native")]
    pub(crate) fn from_native(
        response: identity_revocation_ocsp_openssl::VerifiedOcspResponse,
    ) -> Self {
        Self {
            issuer_key: response.issuer_key().to_vec(),
            certificate_sha256: *response.certificate_sha256(),
            serial: response.serial().to_vec(),
            status: response.status(),
            this_update: response.this_update(),
            next_update: response.next_update(),
            response_nonce: response.response_nonce().map(<[u8]>::to_vec),
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

    /// Return the issuer key identifier derived from verified key material.
    pub fn issuer_key(&self) -> &[u8] {
        &self.issuer_key
    }

    /// Return the authenticated response nonce when present.
    pub fn response_nonce(&self) -> Option<&[u8]> {
        self.response_nonce.as_deref()
    }
}
