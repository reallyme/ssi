// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use identity_revocation_ocsp_core::OcspError;

use crate::ParsedOcspResponse;

/// Browser hosts cannot mint verified OCSP evidence from JSON assertions.
///
/// A future Wasm backend must verify DER and responder authorization inside
/// the trusted module before returning an opaque response capability.
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
