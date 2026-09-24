// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use identity_revocation_ocsp_core::OcspError;

use super::limits::{
    validate_ocsp_inputs, MAX_OCSP_CERTIFICATE_DER_BYTES, MAX_OCSP_EXTRA_CERTIFICATES,
    MAX_OCSP_RESPONSE_DER_BYTES,
};

#[test]
fn boundary_rejects_empty_and_oversized_primary_inputs() {
    let certificate = [1_u8];
    assert_eq!(
        validate_ocsp_inputs(&[], &certificate, &certificate, &[]),
        Err(OcspError::InvalidResponse)
    );
    assert_eq!(
        validate_ocsp_inputs(
            &vec![0_u8; MAX_OCSP_RESPONSE_DER_BYTES + 1],
            &certificate,
            &certificate,
            &[],
        ),
        Err(OcspError::InvalidResponse)
    );
    assert_eq!(
        validate_ocsp_inputs(
            &[1_u8],
            &vec![0_u8; MAX_OCSP_CERTIFICATE_DER_BYTES + 1],
            &certificate,
            &[],
        ),
        Err(OcspError::InvalidResponse)
    );
}

#[test]
fn boundary_rejects_excessive_or_invalid_extra_certificates() {
    let certificate = [1_u8];
    let excessive = vec![vec![1_u8]; MAX_OCSP_EXTRA_CERTIFICATES + 1];
    assert_eq!(
        validate_ocsp_inputs(&certificate, &certificate, &certificate, &excessive),
        Err(OcspError::InvalidResponse)
    );
    assert_eq!(
        validate_ocsp_inputs(&certificate, &certificate, &certificate, &[Vec::new()],),
        Err(OcspError::InvalidResponse)
    );
}
