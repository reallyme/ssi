// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use identity_revocation_ocsp_core::{OcspError, ParsedOcspResponse};
use identity_revocation_ocsp_openssl::parse_ocsp_response_der_with_nonce as parse_openssl;

pub fn parse_ocsp_response_der(
    ocsp_response_der: &[u8],
    cert_der: &[u8],
    issuer_der: &[u8],
    extra_certs_der: &[Vec<u8>],
    now_unix: u64,
    expected_nonce: Option<&[u8]>,
) -> Result<ParsedOcspResponse, OcspError> {
    parse_openssl(
        ocsp_response_der,
        cert_der,
        issuer_der,
        extra_certs_der,
        now_unix,
        expected_nonce,
    )
}
