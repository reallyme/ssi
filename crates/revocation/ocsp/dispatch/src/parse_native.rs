// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use identity_revocation_ocsp_core::{OcspError, ParsedOcspResponse};
use identity_revocation_ocsp_openssl::parse_ocsp_response_der as parse_openssl;
use openssl::x509::X509;

pub fn parse_ocsp_response_der(
    ocsp_response_der: &[u8],
    cert_der: &[u8],
    issuer_der: &[u8],
    extra_certs_der: &[Vec<u8>],
    now_unix: u64,
) -> Result<ParsedOcspResponse, OcspError> {
    let cert = X509::from_der(cert_der).map_err(|_| OcspError::InvalidResponse)?;
    let issuer = X509::from_der(issuer_der).map_err(|_| OcspError::InvalidResponse)?;

    let mut extra_certs = Vec::with_capacity(extra_certs_der.len());
    for der in extra_certs_der {
        extra_certs.push(X509::from_der(der).map_err(|_| OcspError::InvalidResponse)?);
    }

    parse_openssl(ocsp_response_der, &cert, &issuer, &extra_certs, now_unix)
}
