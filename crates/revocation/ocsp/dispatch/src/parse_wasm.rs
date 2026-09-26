// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use identity_revocation_ocsp_core::{bind_response_to_certificates, OcspError, ParsedOcspResponse};
use js_sys::{Array, JsString, Uint8Array};
use wasm_bindgen::prelude::{wasm_bindgen, JsValue};

use super::limits::MAX_OCSP_HOST_RESPONSE_JSON_BYTES;

#[wasm_bindgen]
extern "C" {
    /// Host binding returning JSON compatible with `ParsedOcspResponse`.
    #[wasm_bindgen(catch, js_name = parseOcspResponseDerJson)]
    fn js_parse_ocsp_response_der_json(
        ocsp_der: Uint8Array,
        cert_der: Uint8Array,
        issuer_der: Uint8Array,
        extra_certs_der: Array,
        now_unix: u64,
    ) -> Result<JsValue, JsValue>;
}

pub fn parse_ocsp_response_der(
    ocsp_response_der: &[u8],
    cert_der: &[u8],
    issuer_der: &[u8],
    extra_certs_der: &[Vec<u8>],
    now_unix: u64,
) -> Result<ParsedOcspResponse, OcspError> {
    let extra = Array::new();
    for der in extra_certs_der {
        extra.push(&Uint8Array::from(der.as_slice()));
    }

    let host_value = js_parse_ocsp_response_der_json(
        Uint8Array::from(ocsp_response_der),
        Uint8Array::from(cert_der),
        Uint8Array::from(issuer_der),
        extra,
        now_unix,
    )
    .map_err(|_| OcspError::InvalidResponse)?;
    if !host_value.is_string() {
        return Err(OcspError::InvalidResponse);
    }
    let host_string = JsString::from(host_value);
    let code_units =
        usize::try_from(host_string.length()).map_err(|_| OcspError::InvalidResponse)?;
    if code_units > MAX_OCSP_HOST_RESPONSE_JSON_BYTES {
        return Err(OcspError::InvalidResponse);
    }
    let json = String::from(host_string);
    if json.len() > MAX_OCSP_HOST_RESPONSE_JSON_BYTES {
        return Err(OcspError::InvalidResponse);
    }

    let response: ParsedOcspResponse =
        serde_json::from_str(&json).map_err(|_| OcspError::InvalidResponse)?;
    bind_response_to_certificates(response, cert_der, issuer_der)
}
