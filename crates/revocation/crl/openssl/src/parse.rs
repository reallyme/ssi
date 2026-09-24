// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::parsed_crl::ParsedOpenSslCrl;
use crate::CrlError;

use openssl::x509::{X509Crl, X509};

/// Parse CRL from DER bytes WITH issuer certificate (required).
pub fn parse_crl_der_with_env_issuer(
    der: &[u8],
    issuer_cert: X509,
) -> Result<ParsedOpenSslCrl, CrlError> {
    let crl = X509Crl::from_der(der).map_err(|_| CrlError::InvalidCrl)?;
    parse_crl(crl, issuer_cert)
}

/// Parse CRL from PEM bytes WITH issuer certificate (required).
pub fn parse_crl_pem_with_env_issuer(
    pem: &[u8],
    issuer_cert: X509,
) -> Result<ParsedOpenSslCrl, CrlError> {
    let crl = X509Crl::from_pem(pem).map_err(|_| CrlError::InvalidCrl)?;
    parse_crl(crl, issuer_cert)
}

/// Internal shared CRL parser.
///
/// Performs:
/// - CRL signature verification
/// - issuer key extraction
/// - revoked serial extraction
/// - best-effort time extraction
fn parse_crl(crl: X509Crl, issuer_cert: X509) -> Result<ParsedOpenSslCrl, CrlError> {
    // ------------------------------------------------------------
    // 1) Verify CRL signature
    // ------------------------------------------------------------
    let issuer_pubkey = issuer_cert.public_key().map_err(|_| CrlError::InvalidCrl)?;

    crl.verify(&issuer_pubkey)
        .map_err(|_| CrlError::InvalidCrl)?;

    // ------------------------------------------------------------
    // 2) Issuer key identifier (SKI preferred)
    // ------------------------------------------------------------
    let issuer_key = issuer_cert
        .subject_key_id()
        .ok_or(CrlError::InvalidCrl)?
        .as_slice()
        .to_vec();

    // ------------------------------------------------------------
    // 3) Extract revoked serials
    // ------------------------------------------------------------
    let mut revoked_serials = Vec::new();

    if let Some(revoked) = crl.get_revoked() {
        for r in revoked {
            let serial = r
                .serial_number()
                .to_bn()
                .map_err(|_| CrlError::InvalidCrl)?
                .to_vec();
            revoked_serials.push(normalize_serial(serial));
        }
    }

    // ------------------------------------------------------------
    // 4) Time handling (best-effort)
    // ------------------------------------------------------------
    let this_update_unix = None;
    let next_update_unix = None;

    Ok(ParsedOpenSslCrl {
        issuer_key,
        crl,
        revoked_serials,
        this_update_unix,
        next_update_unix,
        issuer_cert,
    })
}

/// Normalize serial bytes (strip leading zero padding).
fn normalize_serial(mut s: Vec<u8>) -> Vec<u8> {
    while s.len() > 1 && s[0] == 0 {
        s.remove(0);
    }
    s
}
