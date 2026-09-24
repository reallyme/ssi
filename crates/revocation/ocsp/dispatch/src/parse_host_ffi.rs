// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(unsafe_code)]

use identity_revocation_ocsp_core::{OcspError, ParsedOcspResponse};

use super::limits::MAX_OCSP_HOST_RESPONSE_JSON_BYTES;

extern "C" {
    fn ocsp_parse_response_der_json(
        ocsp_der: *const u8,
        ocsp_der_len: usize,
        cert_der: *const u8,
        cert_der_len: usize,
        issuer_der: *const u8,
        issuer_der_len: usize,
        extra_certs_json: *const u8,
        extra_certs_json_len: usize,
        now_unix: u64,
        out_buf: *mut u8,
        out_buf_len: usize,
        out_len: *mut usize,
    ) -> i32;
}

pub(crate) fn parse_host_ocsp_response_der(
    ocsp_response_der: &[u8],
    cert_der: &[u8],
    issuer_der: &[u8],
    extra_certs_der: &[Vec<u8>],
    now_unix: u64,
) -> Result<ParsedOcspResponse, OcspError> {
    let extra_json = encode_extra_certs_json(extra_certs_der)?;
    let required = query_required_len(
        ocsp_response_der,
        cert_der,
        issuer_der,
        &extra_json,
        now_unix,
    )?;
    if required > MAX_OCSP_HOST_RESPONSE_JSON_BYTES {
        return Err(OcspError::InvalidResponse);
    }

    let mut out = vec![0u8; required];
    let mut written: usize = 0;

    // SAFETY: All pointers are derived from borrowed slices or owned buffers
    // that remain alive for the duration of the call. The host writes at most
    // `out.len()` bytes and reports the actual initialized prefix in `written`.
    let rc = unsafe {
        ocsp_parse_response_der_json(
            ocsp_response_der.as_ptr(),
            ocsp_response_der.len(),
            cert_der.as_ptr(),
            cert_der.len(),
            issuer_der.as_ptr(),
            issuer_der.len(),
            extra_json.as_ptr(),
            extra_json.len(),
            now_unix,
            out.as_mut_ptr(),
            out.len(),
            &mut written as *mut usize,
        )
    };

    if rc != 0 || written == 0 || written > out.len() {
        return Err(OcspError::InvalidResponse);
    }

    let json = core::str::from_utf8(&out[..written]).map_err(|_| OcspError::InvalidResponse)?;
    serde_json::from_str(json).map_err(|_| OcspError::InvalidResponse)
}

fn encode_extra_certs_json(extra_certs_der: &[Vec<u8>]) -> Result<String, OcspError> {
    let extra_certs_b64: Vec<String> = extra_certs_der
        .iter()
        .map(|der| codec_base64url::bytes_to_base64url(der))
        .collect();
    serde_json::to_string(&extra_certs_b64).map_err(|_| OcspError::InvalidResponse)
}

fn query_required_len(
    ocsp_response_der: &[u8],
    cert_der: &[u8],
    issuer_der: &[u8],
    extra_json: &str,
    now_unix: u64,
) -> Result<usize, OcspError> {
    let mut required: usize = 0;

    // SAFETY: This length-query call passes valid borrowed input pointers and a
    // null output buffer with zero capacity, which is the documented host ABI
    // query mode. The only retained output is the scalar `required`.
    let rc = unsafe {
        ocsp_parse_response_der_json(
            ocsp_response_der.as_ptr(),
            ocsp_response_der.len(),
            cert_der.as_ptr(),
            cert_der.len(),
            issuer_der.as_ptr(),
            issuer_der.len(),
            extra_json.as_ptr(),
            extra_json.len(),
            now_unix,
            core::ptr::null_mut(),
            0,
            &mut required as *mut usize,
        )
    };

    if (rc == -3 || rc == 0) && required != 0 {
        Ok(required)
    } else {
        Err(OcspError::InvalidResponse)
    }
}
