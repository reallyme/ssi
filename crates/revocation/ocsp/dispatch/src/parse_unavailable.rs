// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use identity_revocation_ocsp_core::OcspError;

use crate::ParsedOcspResponse;

pub fn parse_ocsp_response_der(
    _ocsp_response_der: &[u8],
    _cert_der: &[u8],
    _issuer_der: &[u8],
    _extra_certs_der: &[Vec<u8>],
    _now_unix: u64,
    _expected_nonce: Option<&[u8]>,
) -> Result<ParsedOcspResponse, OcspError> {
    Err(OcspError::Unsupported)
}
