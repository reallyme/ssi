// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Binding of host-produced OCSP results to the certificates they describe.

use envelopes_x509::parse_cert_der;

use crate::{OcspError, ParsedOcspResponse};

/// Cross-check a response produced by a host platform verifier against the
/// certificate and issuer DER that were submitted for verification.
///
/// Host verifiers (browser, Apple, Android) return a JSON projection that is
/// otherwise taken at face value. This check ensures the projection describes
/// the submitted certificate (serial), the submitted issuer (issuer key
/// identifier), and a well-formed validity window, so a confused or
/// compromised host cannot substitute a response for a different certificate.
///
/// The issuer key identifier is bound to the issuer's subjectKeyIdentifier
/// when present, otherwise to the certificate's authorityKeyIdentifier; a
/// certificate/issuer pair offering neither is rejected.
pub fn bind_response_to_certificates(
    response: ParsedOcspResponse,
    cert_der: &[u8],
    issuer_der: &[u8],
) -> Result<ParsedOcspResponse, OcspError> {
    let cert = parse_cert_der(cert_der).map_err(|_| OcspError::InvalidResponse)?;
    let issuer = parse_cert_der(issuer_der).map_err(|_| OcspError::InvalidResponse)?;

    if canonical_serial(&response.serial) != canonical_serial(&cert.serial) {
        return Err(OcspError::InvalidResponse);
    }

    if let (Some(aki), Some(ski)) = (
        cert.authority_key_identifier.as_deref(),
        issuer.subject_key_identifier.as_deref(),
    ) {
        if aki != ski {
            return Err(OcspError::InvalidResponse);
        }
    }
    let expected_issuer_key = issuer
        .subject_key_identifier
        .as_deref()
        .or(cert.authority_key_identifier.as_deref())
        .ok_or(OcspError::InvalidResponse)?;
    if response.issuer_key.as_slice() != expected_issuer_key {
        return Err(OcspError::InvalidResponse);
    }

    if response.this_update == 0 {
        return Err(OcspError::InvalidResponse);
    }
    if response
        .next_update
        .is_some_and(|next| next < response.this_update)
    {
        return Err(OcspError::InvalidResponse);
    }

    Ok(response)
}

fn canonical_serial(serial: &[u8]) -> &[u8] {
    let start = serial
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(serial.len());
    serial.get(start..).unwrap_or_default()
}
