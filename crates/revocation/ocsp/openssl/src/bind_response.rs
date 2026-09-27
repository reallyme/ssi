// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Binding of host-produced OCSP results to the certificates they describe.

use envelopes_x509::parse_cert_der;

use subtle::ConstantTimeEq;

use identity_revocation_ocsp_core::OcspError;

use crate::model::{UnverifiedOcspResponse, VerifiedOcspResponse};

/// Largest OCSP nonce accepted from a responder or host projection.
const MAX_OCSP_NONCE_BYTES: usize = 32;
const OCSP_NONCE_OID: &str = "1.3.6.1.5.5.7.48.1.2";

/// Cross-check a response produced by a host platform verifier against the
/// certificate and issuer DER that were submitted for verification.
///
/// Host verifiers (browser, Apple, Android) return a JSON projection that is
/// otherwise taken at face value. This check ensures the projection describes
/// the submitted certificate (serial), the submitted issuer (issuer key
/// identifier), and a well-formed validity window, so a confused or
/// compromised host cannot substitute a response for a different certificate.
///
/// The issuer key hash is bound to RFC 6960 `CertID.issuerKeyHash`, which uses
/// RFC 5280 method (1) over the issuer subjectPublicKey bits. The certificate
/// issuer name is matched exactly, and a present authorityKeyIdentifier must
/// independently identify that issuer key.
/// Bind a host-produced response and require its authenticated nonce to equal
/// the nonce sent in the corresponding OCSP request.
pub(crate) fn bind_response_to_certificates_with_nonce(
    response: UnverifiedOcspResponse,
    cert_der: &[u8],
    issuer_der: &[u8],
    expected_nonce: Option<&[u8]>,
) -> Result<VerifiedOcspResponse, OcspError> {
    if response.extensions.as_ref().is_some_and(|extensions| {
        extensions
            .iter()
            .any(|extension| extension.critical && extension.oid != OCSP_NONCE_OID)
    }) {
        return Err(OcspError::InvalidResponse);
    }
    let cert = parse_cert_der(cert_der).map_err(|_| OcspError::InvalidResponse)?;
    let issuer = parse_cert_der(issuer_der).map_err(|_| OcspError::InvalidResponse)?;

    // DER INTEGER encodings are canonical. Removing leading zeroes here would
    // alias a valid positive serial with a negative or non-canonical encoding.
    if response.serial != cert.serial {
        return Err(OcspError::InvalidResponse);
    }

    if cert.issuer_der != issuer.subject_der {
        return Err(OcspError::InvalidResponse);
    }
    if let Some(aki) = cert.authority_key_identifier.as_deref() {
        if !issuer.matches_key_identifier(aki) {
            return Err(OcspError::InvalidResponse);
        }
    }
    let computed_issuer_key = issuer
        .rfc5280_method_one_key_identifier()
        .ok_or(OcspError::InvalidResponse)?;
    if response.issuer_key.as_slice() != computed_issuer_key {
        return Err(OcspError::InvalidResponse);
    }

    validate_response_nonce(response.response_nonce.as_deref(), expected_nonce)?;

    if response.this_update == 0 {
        return Err(OcspError::InvalidResponse);
    }
    if response
        .next_update
        .is_some_and(|next| next < response.this_update)
    {
        return Err(OcspError::InvalidResponse);
    }

    let certificate_sha256 = reallyme_crypto::sha2::digest(cert_der);
    Ok(VerifiedOcspResponse::new(
        response.issuer_key,
        *certificate_sha256.as_bytes(),
        response.serial,
        response.status,
        response.this_update,
        response.next_update,
        response.response_nonce,
    ))
}

/// Validate bounded OCSP nonce presence and equality.
pub(crate) fn validate_response_nonce(
    response_nonce: Option<&[u8]>,
    expected_nonce: Option<&[u8]>,
) -> Result<(), OcspError> {
    if response_nonce.is_some_and(|nonce| nonce.is_empty() || nonce.len() > MAX_OCSP_NONCE_BYTES)
        || expected_nonce
            .is_some_and(|nonce| nonce.is_empty() || nonce.len() > MAX_OCSP_NONCE_BYTES)
    {
        return Err(OcspError::InvalidResponse);
    }
    match (response_nonce, expected_nonce) {
        (Some(response), Some(expected))
            if response.len() == expected.len() && bool::from(response.ct_eq(expected)) =>
        {
            Ok(())
        }
        (_, None) => Ok(()),
        _ => Err(OcspError::InvalidResponse),
    }
}

#[cfg(test)]
#[path = "bind_response_unit_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "bind_response_tests.rs"]
mod integration_tests;
