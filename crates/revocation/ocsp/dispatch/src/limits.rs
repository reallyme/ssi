// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use identity_revocation_ocsp_core::OcspError;

pub(crate) const MAX_OCSP_RESPONSE_DER_BYTES: usize = 1_048_576;
pub(crate) const MAX_OCSP_CERTIFICATE_DER_BYTES: usize = 65_536;
pub(crate) const MAX_OCSP_EXTRA_CERTIFICATES: usize = 10;
pub(crate) const MAX_OCSP_EXTRA_CERTIFICATE_DER_BYTES: usize = 655_360;
#[cfg(any(
    all(feature = "wasm", target_arch = "wasm32"),
    all(
        feature = "apple-platform",
        any(target_os = "ios", target_os = "macos")
    ),
    all(feature = "android-platform", target_os = "android")
))]
pub(crate) const MAX_OCSP_HOST_RESPONSE_JSON_BYTES: usize = 1_048_576;

pub(crate) fn validate_ocsp_inputs(
    ocsp_response_der: &[u8],
    cert_der: &[u8],
    issuer_der: &[u8],
    extra_certs_der: &[Vec<u8>],
) -> Result<(), OcspError> {
    if ocsp_response_der.is_empty() || ocsp_response_der.len() > MAX_OCSP_RESPONSE_DER_BYTES {
        return Err(OcspError::InvalidResponse);
    }
    if !valid_certificate(cert_der) || !valid_certificate(issuer_der) {
        return Err(OcspError::InvalidResponse);
    }
    if extra_certs_der.len() > MAX_OCSP_EXTRA_CERTIFICATES {
        return Err(OcspError::InvalidResponse);
    }

    let mut aggregate_bytes = 0_usize;
    for certificate in extra_certs_der {
        if !valid_certificate(certificate) {
            return Err(OcspError::InvalidResponse);
        }
        aggregate_bytes = aggregate_bytes
            .checked_add(certificate.len())
            .ok_or(OcspError::InvalidResponse)?;
        if aggregate_bytes > MAX_OCSP_EXTRA_CERTIFICATE_DER_BYTES {
            return Err(OcspError::InvalidResponse);
        }
    }
    Ok(())
}

fn valid_certificate(certificate_der: &[u8]) -> bool {
    !certificate_der.is_empty() && certificate_der.len() <= MAX_OCSP_CERTIFICATE_DER_BYTES
}
